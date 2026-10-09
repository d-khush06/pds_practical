/**
 * GENERIC LOG ANALYZER
 * ====================
 * Computes dynamic metrics, anomalies, and security indicators
 * from parsed log events produced by logParser.js.
 *
 * NO hard-coded values. NO static defaults.
 * Every metric includes provenance metadata.
 */

// ── Helper: top-N from frequency map ─────────────────────────────────────────
function topN(map, n = 10) {
  return Object.entries(map)
    .sort((a, b) => b[1] - a[1])
    .slice(0, n)
    .map(([key, count]) => ({ key, count }))
}

// ── Helper: frequency map from field values ───────────────────────────────────
function freqMap(events, accessor) {
  const map = {}
  for (const ev of events) {
    const val = accessor(ev)
    if (val !== null && val !== undefined && String(val).trim()) {
      const k = String(val).trim()
      map[k] = (map[k] || 0) + 1
    }
  }
  return map
}

// ── Metric builder with provenance ───────────────────────────────────────────
function metric(name, value, sourceField, confidence = 1.0, extra = {}) {
  if (value === null || value === undefined) {
    return { name, value: null, status: 'not_available', reason: `No ${sourceField} field detected.`, ...extra }
  }
  return { name, value, source_field: sourceField, confidence, status: 'calculated', ...extra }
}

// ── Duration formatting ───────────────────────────────────────────────────────
function formatDuration(seconds) {
  if (seconds === null) return null
  if (seconds < 60) return `${seconds}s`
  if (seconds < 3600) return `${Math.floor(seconds/60)}m ${seconds%60}s`
  if (seconds < 86400) return `${Math.floor(seconds/3600)}h ${Math.floor((seconds%3600)/60)}m`
  return `${Math.floor(seconds/86400)}d ${Math.floor((seconds%86400)/3600)}h`
}

// ── Byte formatting ───────────────────────────────────────────────────────────
function formatBytes(n) {
  if (n < 1024) return `${n} B`
  if (n < 1024*1024) return `${(n/1024).toFixed(1)} KB`
  if (n < 1024*1024*1024) return `${(n/1024/1024).toFixed(2)} MB`
  return `${(n/1024/1024/1024).toFixed(2)} GB`
}

// ── GENERIC STATS (always calculated) ────────────────────────────────────────
function computeGenericStats(parseResult) {
  const { parsing, timeline, events, parsed_events } = parseResult
  const metrics = []

  metrics.push(metric('Total Log Lines', parsing.total_non_empty_lines, 'raw_lines'))
  metrics.push(metric('Parsed Events', parsed_events.length, 'parsed_lines'))
  metrics.push(metric('Parse Success Rate', `${parsing.parse_success_rate}%`, 'parsing'))
  metrics.push(metric('Format Confidence', `${(parseResult.format.confidence * 100).toFixed(0)}%`, 'format_detection'))

  if (timeline.first) {
    metrics.push(metric('First Event', timeline.first.toLocaleString(), 'timestamp'))
    metrics.push(metric('Last Event', timeline.last.toLocaleString(), 'timestamp'))
    if (timeline.duration_seconds !== null) {
      metrics.push(metric('Log Duration', formatDuration(timeline.duration_seconds), 'timestamp'))
      if (timeline.duration_seconds > 0) {
        const epsVal = (parsed_events.length / timeline.duration_seconds).toFixed(3)
        metrics.push(metric('Events per Second', epsVal, 'timestamp+events'))
      }
    }
  }

  return metrics
}

// ── HTTP / ACCESS LOG METRICS ─────────────────────────────────────────────────
function computeHttpMetrics(events) {
  const httpEvents = events.filter(e => e.fields.http_method || e.fields.status_code || e.fields.client_ip)
  if (httpEvents.length === 0) return { available: false, metrics: [], charts: [] }

  const metrics = []
  const charts = []

  metrics.push(metric('Total HTTP Requests', httpEvents.length, 'http_method/status_code'))

  // IPs
  const ipField = httpEvents[0].fields.client_ip !== undefined ? 'client_ip' : null
  if (ipField) {
    const ipMap = freqMap(httpEvents, e => e.fields.client_ip)
    const uniqueIps = Object.keys(ipMap).length
    metrics.push(metric('Unique Client IPs', uniqueIps, 'client_ip'))
    const topIps = topN(ipMap, 10)
    metrics.push(metric('Top IPs by Request Count', topIps, 'client_ip', 1.0, { type: 'table', columns: ['IP Address', 'Request Count'] }))
    charts.push({ id: 'top_ips', title: 'Top Client IPs', type: 'bar', labels: topIps.slice(0,10).map(r=>r.key), data: topIps.slice(0,10).map(r=>r.count), source: 'client_ip' })
  }

  // Methods
  const methodMap = freqMap(httpEvents, e => e.fields.http_method)
  if (Object.keys(methodMap).length > 0) {
    metrics.push(metric('HTTP Methods', Object.entries(methodMap).map(([k,v])=>({key:k,count:v})), 'http_method', 1.0, { type: 'table' }))
    charts.push({ id: 'http_methods', title: 'HTTP Method Distribution', type: 'doughnut', labels: Object.keys(methodMap), data: Object.values(methodMap), source: 'http_method' })
  }

  // Status codes
  const statusMap = freqMap(httpEvents, e => e.fields.status_code || (e.fields.status_code_num ? String(e.fields.status_code_num) : null))
  if (Object.keys(statusMap).length > 0) {
    const status2xx = Object.entries(statusMap).filter(([k])=>k.startsWith('2')).reduce((s,[,v])=>s+v,0)
    const status3xx = Object.entries(statusMap).filter(([k])=>k.startsWith('3')).reduce((s,[,v])=>s+v,0)
    const status4xx = Object.entries(statusMap).filter(([k])=>k.startsWith('4')).reduce((s,[,v])=>s+v,0)
    const status5xx = Object.entries(statusMap).filter(([k])=>k.startsWith('5')).reduce((s,[,v])=>s+v,0)
    metrics.push(metric('2xx (Success)', status2xx, 'status_code'))
    metrics.push(metric('4xx (Client Errors)', status4xx, 'status_code'))
    metrics.push(metric('5xx (Server Errors)', status5xx, 'status_code'))
    charts.push({ id: 'status_codes', title: 'HTTP Status Code Distribution', type: 'bar', labels: Object.keys(statusMap).sort(), data: Object.keys(statusMap).sort().map(k=>statusMap[k]), source: 'status_code' })
  }

  // Endpoints
  const endpointMap = freqMap(httpEvents, e => e.fields.http_path)
  if (Object.keys(endpointMap).length > 0) {
    const topEp = topN(endpointMap, 10)
    metrics.push(metric('Top Endpoints', topEp, 'http_path', 1.0, { type: 'table', columns: ['Endpoint', 'Hits'] }))
    charts.push({ id: 'top_endpoints', title: 'Top Endpoints', type: 'bar', labels: topEp.map(r=>r.key.slice(0,40)), data: topEp.map(r=>r.count), source: 'http_path' })
  }

  // Data transfer
  const bytesEvents = httpEvents.filter(e => typeof e.fields.response_bytes_num === 'number')
  if (bytesEvents.length > 0) {
    const totalBytes = bytesEvents.reduce((s, e) => s + e.fields.response_bytes_num, 0)
    metrics.push(metric('Total Data Transfer', formatBytes(totalBytes), 'response_bytes', 1.0, { raw_bytes: totalBytes }))
    metrics.push(metric('Avg Response Size', formatBytes(totalBytes / bytesEvents.length), 'response_bytes'))
  }

  // User agents
  const uaMap = freqMap(httpEvents, e => e.fields.user_agent)
  if (Object.keys(uaMap).length > 0) {
    const topUas = topN(uaMap, 10)
    metrics.push(metric('Top User Agents', topUas, 'user_agent', 1.0, { type: 'table' }))
  }

  return { available: true, metrics, charts }
}

// ── APPLICATION LOG METRICS ───────────────────────────────────────────────────
function computeAppMetrics(events) {
  const appEvents = events.filter(e => e.severity)
  if (appEvents.length === 0) return { available: false, metrics: [], charts: [] }

  const metrics = []
  const charts = []

  const levelMap = freqMap(appEvents, e => e.severity)
  metrics.push(metric('Total Log Events', appEvents.length, 'severity'))
  metrics.push(metric('Log Level Distribution', Object.entries(levelMap).map(([k,v])=>({key:k,count:v})), 'severity', 1.0, { type: 'table' }))

  const errorCount = (levelMap['ERROR'] || 0) + (levelMap['CRITICAL'] || 0) + (levelMap['FATAL'] || 0)
  const warnCount = levelMap['WARNING'] || 0
  const debugCount = levelMap['DEBUG'] || 0
  const infoCount = levelMap['INFO'] || 0

  metrics.push(metric('Error Events', errorCount, 'severity'))
  if (warnCount > 0) metrics.push(metric('Warning Events', warnCount, 'severity'))
  if (debugCount > 0) metrics.push(metric('Debug Events', debugCount, 'severity'))
  if (infoCount > 0) metrics.push(metric('Info Events', infoCount, 'severity'))

  charts.push({
    id: 'log_levels', title: 'Log Level Distribution', type: 'doughnut',
    labels: Object.keys(levelMap), data: Object.values(levelMap),
    colors: Object.keys(levelMap).map(l => ({
      CRITICAL:'#ef4444', FATAL:'#dc2626', ERROR:'#f87171', WARNING:'#f59e0b',
      NOTICE:'#60a5fa', INFO:'#34d399', DEBUG:'#8b5cf6', TRACE:'#a78bfa', EMERGENCY:'#b91c1c', ALERT:'#d97706'
    }[l] || '#8b9ec0')),
    source: 'severity'
  })

  // Top sources/components
  const srcMap = freqMap(appEvents, e => e.source)
  if (Object.keys(srcMap).length > 0) {
    const topSrc = topN(srcMap, 10)
    metrics.push(metric('Top Components/Sources', topSrc, 'source', 1.0, { type: 'table' }))
    charts.push({ id: 'top_sources', title: 'Events by Component', type: 'bar', labels: topSrc.slice(0,10).map(r=>r.key.slice(0,30)), data: topSrc.slice(0,10).map(r=>r.count), source: 'source' })
  }

  // Thread analysis (Java/JVM)
  const threadMap = freqMap(appEvents, e => e.fields.thread)
  if (Object.keys(threadMap).length > 0) {
    metrics.push(metric('Unique Threads', Object.keys(threadMap).length, 'thread'))
    const topThreads = topN(threadMap, 5)
    metrics.push(metric('Top Threads by Events', topThreads, 'thread', 1.0, { type: 'table' }))
  }

  // Exception detection
  const exceptions = appEvents.filter(e => /\b(exception|stacktrace|caused by|at [a-z][\w.]+\.[A-Z])\b/i.test(e.message || e.raw_line))
  if (exceptions.length > 0) {
    metrics.push(metric('Exception Occurrences', exceptions.length, 'message', 1.0))
  }

  return { available: true, metrics, charts }
}

// ── AUTHENTICATION METRICS ────────────────────────────────────────────────────
function computeAuthMetrics(events) {
  const authEvents = events.filter(e => /\b(auth|login|logout|session|password|accept|fail|invalid user|ssh|sudo|su\b)\b/i.test(e.message || e.raw_line))
  if (authEvents.length === 0) return { available: false, metrics: [], charts: [] }

  const metrics = []
  const charts = []

  const successEvents = authEvents.filter(e => /\b(accept|success|opened|started|granted|valid)\b/i.test(e.message || e.raw_line))
  const failEvents = authEvents.filter(e => /\b(fail|invalid|refused|denied|error|incorrect|wrong|bad)\b/i.test(e.message || e.raw_line))
  const logoutEvents = authEvents.filter(e => /\b(logout|disconnect|closed|ended)\b/i.test(e.message || e.raw_line))

  metrics.push(metric('Total Auth Events', authEvents.length, 'auth_keywords'))
  metrics.push(metric('Successful Auth', successEvents.length, 'auth_accept_keywords'))
  metrics.push(metric('Failed Auth', failEvents.length, 'auth_fail_keywords'))
  if (logoutEvents.length > 0) metrics.push(metric('Logout/Disconnect Events', logoutEvents.length, 'auth_logout_keywords'))

  const failRate = authEvents.length > 0 ? ((failEvents.length / authEvents.length) * 100).toFixed(1) : 0
  metrics.push(metric('Auth Failure Rate', `${failRate}%`, 'auth_events', 1.0))

  // Users
  const userPatterns = [
    /\bfor\s+(?:user\s+)?(\S+)\b/i,
    /\buser\s+(\S+)\b/i,
    /\bUSER=(\S+)\b/,
  ]
  const userMap = {}
  for (const ev of authEvents) {
    const line = ev.message || ev.raw_line
    for (const pat of userPatterns) {
      const m = line.match(pat)
      if (m && m[1] && m[1].length < 64) {
        userMap[m[1]] = (userMap[m[1]] || 0) + 1
        break
      }
    }
  }
  if (Object.keys(userMap).length > 0) {
    metrics.push(metric('Unique Users', Object.keys(userMap).length, 'auth_user'))
    metrics.push(metric('Top Targeted Users', topN(userMap, 10), 'auth_user', 1.0, { type: 'table' }))
  }

  // Source IPs for auth events
  const authIpMap = {}
  for (const ev of authEvents) {
    const ips = ev.fields.client_ip ? [ev.fields.client_ip] : (ev.fields.ips || [])
    for (const ip of ips) { authIpMap[ip] = (authIpMap[ip] || 0) + 1 }
  }
  if (Object.keys(authIpMap).length > 0) {
    metrics.push(metric('Unique Auth Source IPs', Object.keys(authIpMap).length, 'client_ip/ips'))
    metrics.push(metric('Top Auth Source IPs', topN(authIpMap, 10), 'client_ip/ips', 1.0, { type: 'table' }))
  }

  charts.push({
    id: 'auth_breakdown', title: 'Authentication Breakdown', type: 'doughnut',
    labels: ['Successful', 'Failed', 'Logout/Other'],
    data: [successEvents.length, failEvents.length, authEvents.length - successEvents.length - failEvents.length],
    source: 'auth_keywords'
  })

  return { available: true, metrics, charts }
}

// ── DATABASE METRICS ──────────────────────────────────────────────────────────
function computeDatabaseMetrics(events) {
  const dbEvents = events.filter(e => /\b(query|select|insert|update|delete|create|drop|alter|transaction|commit|rollback|sql|mysql|postgres)\b/i.test(e.message || e.raw_line))
  if (dbEvents.length === 0) return { available: false, metrics: [], charts: [] }

  const metrics = []
  metrics.push(metric('Total DB Events', dbEvents.length, 'db_keywords'))

  const opMap = {}
  for (const ev of dbEvents) {
    const line = (ev.message || ev.raw_line).toUpperCase()
    for (const op of ['SELECT','INSERT','UPDATE','DELETE','CREATE','DROP','ALTER','COMMIT','ROLLBACK']) {
      if (line.includes(op)) { opMap[op] = (opMap[op]||0)+1; break }
    }
  }
  if (Object.keys(opMap).length > 0) {
    metrics.push(metric('DB Operation Types', Object.entries(opMap).map(([k,v])=>({key:k,count:v})), 'db_operation', 1.0, { type: 'table' }))
  }

  const errorEvents = dbEvents.filter(e => e.severity === 'ERROR' || e.severity === 'CRITICAL' || /\b(error|fail|exception)\b/i.test(e.message||''))
  if (errorEvents.length > 0) metrics.push(metric('DB Errors', errorEvents.length, 'db_error_keywords'))

  // Query times (from slow query logs etc)
  const timings = []
  for (const ev of dbEvents) {
    const m = (ev.message || ev.raw_line).match(/(?:Query_time|duration|took|elapsed)[:\s]+([0-9.]+)/i)
    if (m) { const t = parseFloat(m[1]); if (!isNaN(t)) timings.push(t) }
  }
  if (timings.length > 0) {
    const avg = timings.reduce((s,t)=>s+t,0)/timings.length
    const max = Math.max(...timings)
    metrics.push(metric('Avg Query Time', `${avg.toFixed(3)}s`, 'query_time'))
    metrics.push(metric('Max Query Time', `${max.toFixed(3)}s`, 'query_time'))
  }

  return { available: true, metrics, charts: [] }
}

// ── ANOMALY DETECTION ─────────────────────────────────────────────────────────
function detectAnomalies(events, timeline) {
  const anomalies = []

  // Need timestamps for time-based anomalies
  const timedEvents = events.filter(e => e.timestamp)

  if (timedEvents.length < 10) {
    return [{ type: 'info', title: 'Insufficient Data for Time-Based Anomaly Detection', description: `Only ${timedEvents.length} events have timestamps. Time-based anomaly detection requires at least 10 timestamped events.`, confidence: 1.0 }]
  }

  // Build per-minute histogram
  const minuteBuckets = {}
  for (const ev of timedEvents) {
    const bucket = Math.floor(ev.timestamp.getTime() / 60000)
    minuteBuckets[bucket] = (minuteBuckets[bucket] || 0) + 1
  }
  const bucketCounts = Object.values(minuteBuckets)
  if (bucketCounts.length > 1) {
    const avg = bucketCounts.reduce((s,c)=>s+c,0)/bucketCounts.length
    const std = Math.sqrt(bucketCounts.reduce((s,c)=>s+Math.pow(c-avg,2),0)/bucketCounts.length)
    const threshold = avg + 3 * std

    const spikeBuckets = Object.entries(minuteBuckets).filter(([,c]) => c > threshold)
    if (spikeBuckets.length > 0) {
      anomalies.push({
        type: 'anomaly', title: 'Event Rate Spikes Detected',
        description: `${spikeBuckets.length} time window(s) show event counts more than 3 standard deviations above average (avg: ${avg.toFixed(1)}/min, threshold: ${threshold.toFixed(1)}/min).`,
        severity: 'WARNING', confidence: 0.85,
        evidence: `Max spike: ${Math.max(...spikeBuckets.map(([,c])=>c))} events/min`,
        derived_from: { field: 'timestamp', method: 'z-score_time_bucketing', threshold: `mean+3σ=${threshold.toFixed(1)}` }
      })
    }
  }

  // Error rate spike
  const errorEvents = events.filter(e => e.severity_rank >= 5)
  if (errorEvents.length > 0 && events.length > 0) {
    const errRate = errorEvents.length / events.length
    if (errRate > 0.20) {
      anomalies.push({
        type: 'anomaly', title: 'High Error Rate',
        description: `${(errRate*100).toFixed(1)}% of all events are ERROR or higher severity (${errorEvents.length} of ${events.length}).`,
        severity: errRate > 0.5 ? 'CRITICAL' : 'WARNING', confidence: 0.95,
        evidence: `Error count: ${errorEvents.length}`,
        derived_from: { field: 'severity', method: 'percentage_threshold', threshold: '20%' }
      })
    }
  }

  // Repeated identical messages (potential loop/crash)
  const msgMap = {}
  for (const ev of events) {
    if (ev.message) {
      const norm = ev.message.replace(/\d+/g, 'N').trim().slice(0, 100)
      msgMap[norm] = (msgMap[norm] || 0) + 1
    }
  }
  const repeatedMsgs = Object.entries(msgMap).filter(([,c]) => c > Math.max(5, events.length * 0.05)).sort((a,b) => b[1]-a[1])
  if (repeatedMsgs.length > 0) {
    anomalies.push({
      type: 'anomaly', title: 'Highly Repeated Log Messages',
      description: `${repeatedMsgs.length} message pattern(s) repeat excessively, which may indicate a crash loop, misconfiguration, or polling issue.`,
      severity: 'WARNING', confidence: 0.80,
      evidence: `Most repeated: "${repeatedMsgs[0][0].slice(0,80)}" (${repeatedMsgs[0][1]} times)`,
      derived_from: { field: 'message', method: 'normalized_message_frequency', threshold: '>5% of total' }
    })
  }

  return anomalies
}

// ── SECURITY ANALYSIS (conditional on available data) ────────────────────────
function analyzeSecurityIndicators(events, parseResult) {
  const indicators = []
  const { meta } = parseResult

  // Only run HTTP security analysis if we have HTTP data
  if (meta.has_http) {
    const httpEvents = events.filter(e => e.fields.http_method || e.fields.status_code)

    // Scanner / tool detection from user agents
    const scannerUaRe = /\b(nikto|dirbuster|gobuster|dirb|sqlmap|nmap|masscan|zgrab|wpscan|hydra|medusa|metasploit|burpsuite|acunetix|nessus|openvas|zap|w3af|arachni|skipfish)\b/i
    const scannerEvents = httpEvents.filter(e => scannerUaRe.test(e.fields.user_agent || ''))
    if (scannerEvents.length > 0) {
      const scannerIps = [...new Set(scannerEvents.map(e => e.fields.client_ip).filter(Boolean))]
      indicators.push({
        type: 'security_threat', severity: 'HIGH',
        title: 'Vulnerability Scanner Detected',
        description: `${scannerEvents.length} request(s) from known vulnerability scanning tools detected.`,
        evidence: `Matching user agents: ${[...new Set(scannerEvents.map(e => e.fields.user_agent).filter(Boolean))].slice(0,3).join(', ')}`,
        affected_ips: scannerIps,
        event_count: scannerEvents.length,
        derived_from: { field: 'user_agent', method: 'known_scanner_ua_pattern_match' }
      })
    }

    // SQLi detection in paths/queries
    const sqliRe = /('|--|union\s+select|select\s+.*from|sleep\(|benchmark\(|1\s*=\s*1|or\s+true|drop\s+table|information_schema)/i
    const sqliEvents = httpEvents.filter(e => sqliRe.test((e.fields.http_path || '') + (e.fields.http_query || '') + (e.fields.request || '')))
    if (sqliEvents.length > 0) {
      const sqliIps = [...new Set(sqliEvents.map(e => e.fields.client_ip).filter(Boolean))]
      indicators.push({
        type: 'security_threat', severity: 'CRITICAL',
        title: 'SQL Injection Attempt Detected',
        description: `${sqliEvents.length} request(s) contain SQL injection payload signatures.`,
        evidence: `Sample: ${(sqliEvents[0].fields.request || sqliEvents[0].raw_line).slice(0,100)}`,
        affected_ips: sqliIps,
        event_count: sqliEvents.length,
        derived_from: { field: 'request/http_path', method: 'sqli_pattern_regex' }
      })
    }

    // XSS detection
    const xssRe = /<script|alert\(|javascript:|onerror=|onload=|%3cscript|<img\s+src.*onerror/i
    const xssEvents = httpEvents.filter(e => xssRe.test((e.fields.request || '') + (e.fields.http_query || '')))
    if (xssEvents.length > 0) {
      indicators.push({
        type: 'security_threat', severity: 'HIGH',
        title: 'XSS Attack Attempt Detected',
        description: `${xssEvents.length} request(s) contain XSS payload signatures.`,
        evidence: `Sample: ${(xssEvents[0].fields.request || xssEvents[0].raw_line).slice(0,100)}`,
        event_count: xssEvents.length,
        derived_from: { field: 'request', method: 'xss_pattern_regex' }
      })
    }

    // LFI/Path traversal
    const lfiRe = /\.\.\/|\.\.\\|\/etc\/passwd|\/etc\/shadow|win\.ini|system32|%2e%2e/i
    const lfiEvents = httpEvents.filter(e => lfiRe.test((e.fields.request || '') + (e.fields.http_query || '')))
    if (lfiEvents.length > 0) {
      indicators.push({
        type: 'security_threat', severity: 'HIGH',
        title: 'Path Traversal / LFI Attempt Detected',
        description: `${lfiEvents.length} request(s) contain path traversal payload signatures.`,
        evidence: `Sample: ${(lfiEvents[0].fields.request || lfiEvents[0].raw_line).slice(0,100)}`,
        event_count: lfiEvents.length,
        derived_from: { field: 'request', method: 'path_traversal_regex' }
      })
    }

    // 404 spike (recon detection)
    const status404 = httpEvents.filter(e => String(e.fields.status_code) === '404')
    if (status404.length > 10 && (status404.length / httpEvents.length) > 0.15) {
      const ipMap = {}
      for (const ev of status404) {
        const ip = ev.fields.client_ip
        if (ip) ipMap[ip] = (ipMap[ip]||0)+1
      }
      const aggressiveIps = Object.entries(ipMap).filter(([,c]) => c > 20).map(([ip,c])=>({ip,count:c}))
      indicators.push({
        type: 'anomaly', severity: 'MEDIUM',
        title: 'High 404 Error Rate — Possible Directory Enumeration',
        description: `${status404.length} 404 responses (${((status404.length/httpEvents.length)*100).toFixed(1)}% of requests). This pattern may indicate directory/endpoint scanning.`,
        evidence: aggressiveIps.length > 0 ? `IPs with >20 404s: ${aggressiveIps.map(i=>`${i.ip}(${i.count})`).join(', ')}` : `Total 404s: ${status404.length}`,
        event_count: status404.length,
        derived_from: { field: 'status_code', method: 'statistical_404_ratio', threshold: '>15% of requests' }
      })
    }

    // IP brute-force detection (many requests from single IP)
    const ipMap = freqMap(httpEvents, e => e.fields.client_ip)
    const totalReqs = httpEvents.length
    const bruteIps = Object.entries(ipMap).filter(([,c]) => c > Math.max(100, totalReqs * 0.05))
    if (bruteIps.length > 0) {
      indicators.push({
        type: 'anomaly', severity: 'MEDIUM',
        title: 'High Request Volume from Single IP',
        description: `${bruteIps.length} IP(s) sent more than 5% of all requests, which may indicate automated scanning or DoS attempts.`,
        evidence: bruteIps.slice(0,5).map(([ip,c])=>`${ip}: ${c} reqs`).join(', '),
        event_count: bruteIps.reduce((s,[,c])=>s+c,0),
        derived_from: { field: 'client_ip', method: 'request_volume_threshold', threshold: '>5% of total or >100 reqs' }
      })
    }
  } else {
    indicators.push({
      type: 'info',
      title: 'HTTP Security Analysis',
      description: 'Insufficient data: No HTTP request fields (method, status code, client IP) were detected in this log file. HTTP-specific threat analysis is not applicable.',
      applicable: false
    })
  }

  // Auth-specific security
  if (meta.has_auth) {
    const authFailRe = /\b(fail|invalid|refused|denied|incorrect|wrong|bad password|authentication failure)\b/i
    const failEvents = events.filter(e => authFailRe.test(e.message || e.raw_line))
    if (failEvents.length > 10) {
      const ipMap = {}
      for (const ev of failEvents) {
        const ips = ev.fields.client_ip ? [ev.fields.client_ip] : (ev.fields.ips || [])
        for (const ip of ips) ipMap[ip] = (ipMap[ip]||0)+1
      }
      const bruteIps = Object.entries(ipMap).filter(([,c]) => c >= 5)
      if (bruteIps.length > 0) {
        indicators.push({
          type: 'security_threat', severity: 'HIGH',
          title: 'Authentication Brute Force Detected',
          description: `${failEvents.length} authentication failures. ${bruteIps.length} source IP(s) have ≥5 failures — indicative of brute-force activity.`,
          evidence: bruteIps.slice(0,5).map(([ip,c])=>`${ip}: ${c} failures`).join(', '),
          event_count: failEvents.length,
          derived_from: { field: 'auth_fail_keywords+client_ip', method: 'failure_count_per_ip', threshold: '≥5 failures per IP' }
        })
      }
    }
  } else {
    indicators.push({
      type: 'info',
      title: 'Authentication Security Analysis',
      description: 'No authentication events were detected in this log file. Auth threat analysis is not applicable.',
      applicable: false
    })
  }

  return indicators
}

// ── TIMELINE CHART (events over time) ────────────────────────────────────────
function buildTimelineChart(events) {
  const timedEvents = events.filter(e => e.timestamp)
  if (timedEvents.length < 3) return null

  // Determine bucket size based on duration
  const firstTs = Math.min(...timedEvents.map(e => e.timestamp.getTime()))
  const lastTs = Math.max(...timedEvents.map(e => e.timestamp.getTime()))
  const durationMs = lastTs - firstTs
  const targetBuckets = 30
  const bucketMs = Math.max(1000, Math.floor(durationMs / targetBuckets))

  const buckets = {}
  for (const ev of timedEvents) {
    const b = Math.floor((ev.timestamp.getTime() - firstTs) / bucketMs)
    if (!buckets[b]) buckets[b] = { total: 0, error: 0, warning: 0 }
    buckets[b].total++
    if (ev.severity_rank >= 5) buckets[b].error++
    else if (ev.severity_rank === 4) buckets[b].warning++
  }

  const maxBucket = Math.max(...Object.keys(buckets).map(Number))
  const labels = []
  const totalData = []
  const errorData = []

  for (let i = 0; i <= maxBucket; i++) {
    const tsMs = firstTs + i * bucketMs
    const d = new Date(tsMs)
    labels.push(d.toLocaleTimeString())
    totalData.push(buckets[i]?.total || 0)
    errorData.push(buckets[i]?.error || 0)
  }

  const bucketLabel = bucketMs < 60000 ? `${Math.round(bucketMs/1000)}s` : bucketMs < 3600000 ? `${Math.round(bucketMs/60000)}m` : `${Math.round(bucketMs/3600000)}h`
  return {
    id: 'timeline', title: `Events Over Time (per ${bucketLabel})`, type: 'line',
    labels, data: totalData, errorData, source: 'timestamp',
    dual: true
  }
}

// ── TOP-LEVEL ANALYZER ────────────────────────────────────────────────────────
export function analyzeLog(parseResult) {
  const { events, parsed_events, format, meta } = parseResult

  if (!parsed_events || parsed_events.length === 0) {
    return {
      summary: { format: format.name, applicable_analyses: [], confidence: format.confidence },
      generic_stats: computeGenericStats(parseResult),
      http: { available: false, metrics: [], charts: [] },
      application: { available: false, metrics: [], charts: [] },
      authentication: { available: false, metrics: [], charts: [] },
      database: { available: false, metrics: [], charts: [] },
      anomalies: [],
      security: [],
      timeline_chart: null,
      ai_context: buildAiContext(parseResult, [], [])
    }
  }

  const genericStats = computeGenericStats(parseResult)
  const http = computeHttpMetrics(events)
  const application = computeAppMetrics(events)
  const authentication = computeAuthMetrics(events)
  const database = computeDatabaseMetrics(events)
  const anomalies = detectAnomalies(events, parseResult.timeline)
  const security = analyzeSecurityIndicators(events, parseResult)
  const timelineChart = buildTimelineChart(events)

  // Top message patterns (repeated messages analysis)
  const msgMap = {}
  for (const ev of events) {
    if (ev.message) {
      const norm = ev.message.replace(/\d+/g, 'N').trim().slice(0, 120)
      msgMap[norm] = (msgMap[norm] || 0) + 1
    }
  }
  const topMessages = topN(msgMap, 10)

  const applicable = []
  if (http.available) applicable.push('HTTP Access Analysis')
  if (application.available) applicable.push('Application Log Analysis')
  if (authentication.available) applicable.push('Authentication Analysis')
  if (database.available) applicable.push('Database Analysis')

  return {
    summary: {
      format: format.name, category: format.category, applicable_analyses: applicable,
      confidence: format.confidence, total_events: events.length, parsed_events: parsed_events.length
    },
    generic_stats: genericStats,
    http,
    application,
    authentication,
    database,
    anomalies,
    security,
    timeline_chart: timelineChart,
    top_messages: topMessages,
    ai_context: buildAiContext(parseResult, anomalies, security, { http, application, authentication, database, topMessages })
  }
}

// ── Build structured context for AI chatbot ───────────────────────────────────
function buildAiContext(parseResult, anomalies, security, sections = {}) {
  const { http, application, authentication, database, topMessages } = sections
  const { events = [], parsed_events = [], format = { name: 'Unknown', category: 'unknown', confidence: 0 }, parsing = {}, timeline = {}, detected_fields = [] } = parseResult

  // Errors and warnings extraction from real parsed events
  let totalErrors = 0
  let totalWarnings = 0
  const errorSamples = []
  const levelDist = {}

  for (const ev of events) {
    const sev = (ev.severity || '').toUpperCase()
    if (sev) {
      levelDist[sev] = (levelDist[sev] || 0) + 1
      if (['ERROR', 'CRITICAL', 'FATAL', 'EMERGENCY', 'ALERT'].includes(sev)) {
        totalErrors++
        if (errorSamples.length < 5) {
          errorSamples.push({
            message: (ev.message || ev.raw_line || '').slice(0, 160),
            severity: sev,
            timestamp: ev.timestamp && !isNaN(ev.timestamp.getTime()) ? ev.timestamp.toISOString() : null
          })
        }
      } else if (sev === 'WARNING' || sev === 'WARN') {
        totalWarnings++
      }
    } else if (ev.fields) {
      const sc = String(ev.fields.status_code || ev.fields.status_code_num || '')
      if (sc.startsWith('5')) {
        totalErrors++
        if (errorSamples.length < 5) {
          errorSamples.push({
            message: `${ev.fields.http_method || 'HTTP'} ${ev.fields.http_path || '/'} → ${sc}`,
            severity: '5xx Server Error',
            timestamp: ev.timestamp && !isNaN(ev.timestamp.getTime()) ? ev.timestamp.toISOString() : null
          })
        }
      } else if (sc.startsWith('4')) {
        totalWarnings++
      }
    }
  }

  // Extract HTTP details if available
  let httpData = null
  if (http && http.available) {
    const getMetric = (name) => http.metrics.find(m => m.name === name)?.value
    httpData = {
      total_requests: getMetric('Total HTTP Requests') || 0,
      unique_ips: getMetric('Unique Client IPs') || 0,
      top_ips: getMetric('Top IPs by Request Count') || [],
      top_endpoints: getMetric('Top Endpoints') || [],
      methods: getMetric('HTTP Methods') || [],
      status_2xx: getMetric('2xx (Success)') || 0,
      status_4xx: getMetric('4xx (Client Errors)') || 0,
      status_5xx: getMetric('5xx (Server Errors)') || 0,
      data_transfer: getMetric('Total Data Transfer') || null,
      top_user_agents: getMetric('Top User Agents') || []
    }
  }

  // Extract Auth details if available
  let authData = null
  if (authentication && authentication.available) {
    const getMetric = (name) => authentication.metrics.find(m => m.name === name)?.value
    authData = {
      total: getMetric('Total Auth Events') || 0,
      success: getMetric('Successful Auth') || 0,
      failed: getMetric('Failed Auth') || 0,
      failure_rate: getMetric('Auth Failure Rate') || '0%',
      top_users: getMetric('Top Targeted Users') || [],
      top_ips: getMetric('Top Auth Source IPs') || []
    }
  }

  // Extract Database details if available
  let dbData = null
  if (database && database.available) {
    const getMetric = (name) => database.metrics.find(m => m.name === name)?.value
    dbData = {
      total_events: getMetric('Total DB Events') || 0,
      operations: getMetric('DB Operation Types') || [],
      errors: getMetric('DB Errors') || 0,
      avg_query_time: getMetric('Avg Query Time') || null
    }
  }

  const realThreats = (security || []).filter(s => s.type === 'security_threat')
  const realAnomalies = (anomalies || []).filter(a => a.type === 'anomaly')

  return {
    format: format.name,
    category: format.category,
    confidence: format.confidence,
    total_events: events.length,
    parsed_events: parsed_events.length,
    parse_success_rate: parsing.parse_success_rate || 0,
    detected_fields,
    timeline: {
      first: (timeline.first && !isNaN(timeline.first.getTime())) ? timeline.first.toISOString() : null,
      last: (timeline.last && !isNaN(timeline.last.getTime())) ? timeline.last.toISOString() : null,
      duration_seconds: timeline.duration_seconds || null
    },
    threat_count: realThreats.length,
    threats: realThreats.map(t => ({
      title: t.title,
      severity: t.severity,
      description: t.description,
      evidence: t.evidence || null,
      affected_ips: t.affected_ips || [],
      event_count: t.event_count || 0
    })),
    high_severity_threats: realThreats.filter(s => s.severity === 'CRITICAL' || s.severity === 'HIGH').map(s => s.title),
    anomaly_count: realAnomalies.length,
    anomalies: realAnomalies.map(a => ({
      title: a.title,
      severity: a.severity,
      description: a.description,
      evidence: a.evidence || null,
      confidence: a.confidence !== undefined ? a.confidence : null
    })),
    anomaly_summaries: realAnomalies.map(a => a.title),
    total_errors: totalErrors,
    total_warnings: totalWarnings,
    error_samples: errorSamples,
    level_distribution: levelDist,
    http: httpData,
    auth: authData,
    database: dbData,
    top_messages: topMessages || []
  }
}
