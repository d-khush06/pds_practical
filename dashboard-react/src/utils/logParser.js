/**
 * GENERIC ADAPTIVE LOG PARSER
 * Supports any text-based log format. No hard-coded format assumptions.
 */

const TS_PATTERNS = [
  { re: /\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?/, name: 'iso8601' },
  { re: /\d{2}\/\w{3}\/\d{4}:\d{2}:\d{2}:\d{2}\s[+-]\d{4}/, name: 'apache_clf' },
  { re: /\b(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}/, name: 'syslog_ts' },
  { re: /\d{2}[\/\-]\d{2}[\/\-]\d{4}\s+\d{2}:\d{2}:\d{2}/, name: 'euro_datetime' },
  { re: /\b1[4-9]\d{8}\b/, name: 'unix_epoch' },
  { re: /\b1[4-9]\d{11}\b/, name: 'unix_epoch_ms' },
  { re: /\b\d{4}-\d{2}-\d{2}\b/, name: 'date_only' },
  { re: /\b\d{2}:\d{2}:\d{2}(?:\.\d+)?\b/, name: 'time_only' },
]

const SEVERITY_PATTERNS = [
  { re: /\b(EMERGENCY|EMERG)\b/i, level: 'EMERGENCY', rank: 8 },
  { re: /\b(ALERT)\b/i, level: 'ALERT', rank: 7 },
  { re: /\b(CRITICAL|CRIT|FATAL|SEVERE)\b/i, level: 'CRITICAL', rank: 6 },
  { re: /\b(ERROR|ERR|EXCEPTION|FAIL(?:ED)?)\b/i, level: 'ERROR', rank: 5 },
  { re: /\b(WARN(?:ING)?)\b/i, level: 'WARNING', rank: 4 },
  { re: /\b(NOTICE|NOTIFY)\b/i, level: 'NOTICE', rank: 3 },
  { re: /\b(INFO(?:RMATION)?)\b/i, level: 'INFO', rank: 2 },
  { re: /\b(DEBUG|TRACE|VERBOSE|FINE|FINER|FINEST)\b/i, level: 'DEBUG', rank: 1 },
]

const IPV4_RE = /\b((?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?))\b/g

const FORMAT_REGEXES = {
  apache_combined: {
    re: /^(\S+)\s+(\S+)\s+(\S+)\s+\[([^\]]+)\]\s+"([^"]*?)"\s+(\d{3})\s+(\S+)(?:\s+"([^"]*?)"\s+"([^"]*?)")?/,
    fields: ['client_ip','ident','auth_user','timestamp','request','status_code','response_bytes','referer','user_agent'],
    name: 'Apache/Nginx Combined', category: 'http_access'
  },
  apache_common: {
    re: /^(\S+)\s+(\S+)\s+(\S+)\s+\[([^\]]+)\]\s+"([^"]*?)"\s+(\d{3})\s+(\S+)$/,
    fields: ['client_ip','ident','auth_user','timestamp','request','status_code','response_bytes'],
    name: 'Apache/Nginx Common', category: 'http_access'
  },
  iis_w3c: {
    re: /^(\d{4}-\d{2}-\d{2})\s(\d{2}:\d{2}:\d{2})\s(\S+)\s(GET|POST|PUT|DELETE|HEAD|OPTIONS)\s(\S+)\s(\S+)\s(\d+)\s(\S+)\s(\d{3})/,
    fields: ['date','time','server_ip','method','uri_stem','uri_query','port','client_ip','status_code'],
    name: 'IIS W3C', category: 'http_access'
  },
  syslog_3164: {
    re: /^<(\d+)>(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+([^\[:]+)(?:\[(\d+)\])?:\s+(.*)/,
    fields: ['priority','timestamp','hostname','process','pid','message'],
    name: 'Syslog RFC3164', category: 'syslog'
  },
  syslog_plain: {
    re: /^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+([^\[:]+)(?:\[(\d+)\])?:\s+(.*)/,
    fields: ['timestamp','hostname','process','pid','message'],
    name: 'Syslog Plain', category: 'syslog'
  },
  java_log4j: {
    re: /^(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?(?:[+-]\d{4})?)\s+(\w+)\s+\[([^\]]+)\]\s+([^\s-]+)\s+-\s+(.*)/,
    fields: ['timestamp','level','thread','class','message'],
    name: 'Java/Log4j/Logback', category: 'application'
  },
  python_log: {
    re: /^(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}(?:[.,]\d+)?)\s+(\w+)\s+([^\s:]+)(?:\s+\d+\s+\w+)?:\s+(.*)/,
    fields: ['timestamp','level','logger','message'],
    name: 'Python logging', category: 'application'
  },
  nodejs_log: {
    re: /^\[?(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}[^\]]*)\]?\s+[-:]?\s*(\w+):\s+(.*)/,
    fields: ['timestamp','level','message'],
    name: 'Node.js/Winston', category: 'application'
  },
  auth_log: {
    re: /^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+(sshd|sudo|su|pam|login|passwd|auth)(?:\[(\d+)\])?:\s+(.*)/i,
    fields: ['timestamp','hostname','process','pid','message'],
    name: 'Auth Log', category: 'authentication'
  },
  postgres_log: {
    re: /^(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}(?:\.\d+)?\s+\w+)\s+\[(\d+)\]\s+(\w+):\s+(.*)/,
    fields: ['timestamp','pid','level','message'],
    name: 'PostgreSQL', category: 'database'
  },
  docker_log: {
    re: /^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+Z)\s+(stdout|stderr)\s+([PF])\s+(.*)/,
    fields: ['timestamp','stream','partial','message'],
    name: 'Docker/Kubernetes', category: 'container'
  },
  windows_event: {
    re: /^(\d{1,2}\/\d{1,2}\/\d{4}\s+\d{1,2}:\d{2}:\d{2}\s+(?:AM|PM))\s+(Information|Warning|Error|Critical|Verbose)\s+(\S+)\s+(\d+)\s+(.*)/i,
    fields: ['timestamp','level','source','event_id','message'],
    name: 'Windows Event Log', category: 'windows'
  },
  bracket_ts_level: {
    re: /^\[([^\]]{8,40})\]\s+\[?(\w+)\]?\s+(.*)/,
    fields: ['timestamp','level','message'],
    name: 'Bracket Timestamp+Level', category: 'application'
  },
}

function parseKeyValue(line) {
  const kvRe = /(\w[\w.-]*)=(?:"([^"]*?)"|'([^']*?)'|(\S+))/g
  const fields = {}
  let match
  while ((match = kvRe.exec(line)) !== null) {
    fields[match[1]] = match[2] ?? match[3] ?? match[4]
  }
  return Object.keys(fields).length >= 2 ? fields : null
}

function detectCsvDelimiter(samples) {
  const candidates = [',', '\t', '|', ';']
  const scores = candidates.map(d => {
    const counts = samples.map(l => (l.split(d).length - 1))
    const avg = counts.reduce((a, b) => a + b, 0) / counts.length
    const variance = counts.reduce((s, c) => s + Math.pow(c - avg, 2), 0) / counts.length
    return { d, avg, variance }
  })
  const best = scores.filter(s => s.avg >= 2).sort((a, b) => a.variance - b.variance || b.avg - a.avg)[0]
  return best && best.variance < 2 ? best.d : null
}

function parseTimestamp(str, patternName) {
  if (!str) return null
  str = str.trim()
  try {
    if (patternName === 'apache_clf') {
      const converted = str.replace(/(\d{2})\/(\w{3})\/(\d{4}):(\d{2}:\d{2}:\d{2})\s([+-]\d{4})/, '$3-$2-$1T$4$5')
      const months = {Jan:'01',Feb:'02',Mar:'03',Apr:'04',May:'05',Jun:'06',Jul:'07',Aug:'08',Sep:'09',Oct:'10',Nov:'11',Dec:'12'}
      const final = converted.replace(/-(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)-/, (_, m) => `-${months[m]}-`)
      return new Date(final)
    }
    if (patternName === 'syslog_ts') {
      return new Date(str + ' ' + new Date().getFullYear())
    }
    if (patternName === 'unix_epoch') return new Date(parseInt(str) * 1000)
    if (patternName === 'unix_epoch_ms') return new Date(parseInt(str))
    return new Date(str.replace(',', '.'))
  } catch { return null }
}

function detectFormat(lines) {
  const sample = lines.filter(l => l.trim()).slice(0, 200)
  if (sample.length === 0) return { type: 'empty', name: 'Empty File', category: 'generic', confidence: 1.0 }

  // JSON check
  const jsonCount = sample.filter(l => { try { const t=l.trim(); return (t.startsWith('{') && t.endsWith('}')) } catch{return false} }).length
  if (jsonCount > sample.length * 0.5) {
    return { type: 'json', name: 'JSON Structured Log', category: 'structured', confidence: jsonCount / sample.length }
  }

  // Known formats
  const scores = {}
  for (const [id, def] of Object.entries(FORMAT_REGEXES)) {
    const cnt = sample.filter(l => def.re.test(l)).length
    if (cnt > 0) scores[id] = cnt / sample.length
  }
  const best = Object.entries(scores).sort((a,b) => b[1]-a[1]).find(([,s]) => s >= 0.25)
  if (best) return { type: best[0], ...FORMAT_REGEXES[best[0]], confidence: best[1] }

  // Key=value
  const kvCount = sample.filter(l => parseKeyValue(l) !== null).length
  if (kvCount > sample.length * 0.4) {
    return { type: 'keyvalue', name: 'Key=Value / LogFmt', category: 'structured', confidence: kvCount / sample.length }
  }

  // CSV
  const nonEmpty = sample.filter(l => l.trim())
  if (nonEmpty.length > 0) {
    const delim = detectCsvDelimiter(nonEmpty.slice(0, 20))
    if (delim) {
      const hdr = nonEmpty[0].split(delim).map(p => p.trim().replace(/^["']|["']$/g, ''))
      const colCount = hdr.length
      const consistent = nonEmpty.slice(1, 10).filter(l=>l.trim()).every(l => l.split(delim).length === colCount)
      if (colCount >= 3 && consistent) {
        return { type: 'csv', name: `CSV (delimiter: ${delim==='\t'?'TAB':delim})`, category: 'structured', confidence: 0.75, delimiter: delim, colCount, headers: hdr }
      }
    }
  }

  return { type: 'unknown', name: 'Unknown/Custom Format', category: 'generic', confidence: 0.5 }
}

function detectSeverity(str) {
  if (!str) return null
  for (const p of SEVERITY_PATTERNS) {
    if (p.re.test(str)) return { level: p.level, rank: p.rank }
  }
  return null
}

function extractHttpFields(event) {
  const req = event.fields.request || ''
  const methodMatch = req.match(/^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS|CONNECT|TRACE)\s+(\S+)/)
  if (methodMatch) {
    event.fields.http_method = methodMatch[1]
    const pathFull = methodMatch[2]
    event.fields.http_path = pathFull.split('?')[0]
    event.fields.http_query = pathFull.includes('?') ? pathFull.split('?')[1] : null
  }
  if (event.fields.response_bytes && event.fields.response_bytes !== '-') {
    const n = parseInt(event.fields.response_bytes)
    if (!isNaN(n)) event.fields.response_bytes_num = n
  }
  const status = parseInt(event.fields.status_code)
  if (!isNaN(status)) {
    event.fields.status_code_num = status
    if (status >= 500) { event.severity = 'ERROR'; event.severity_rank = 5 }
    else if (status >= 400) { event.severity = 'WARNING'; event.severity_rank = 4 }
    else { event.severity = 'INFO'; event.severity_rank = 2 }
  }
}

function parseLine(line, formatDef, lineNum) {
  if (!line.trim()) return null
  const event = { line_number: lineNum, raw_line: line, timestamp: null, timestamp_raw: null, severity: null, severity_rank: 0, source: null, message: null, fields: {}, parsed: false }

  if (formatDef.type === 'json') {
    try {
      const obj = JSON.parse(line.trim())
      if (typeof obj !== 'object' || obj === null) return null
      const tsKey = ['timestamp','time','ts','datetime','@timestamp','date','t'].find(k => k in obj)
      const lvlKey = ['level','severity','loglevel','log_level','lvl','priority'].find(k => k in obj)
      const msgKey = ['message','msg','text','body','log','content'].find(k => k in obj)
      const srcKey = ['service','source','component','app','logger','module','process','name'].find(k => k in obj)
      event.timestamp_raw = tsKey ? String(obj[tsKey]) : null
      event.timestamp = tsKey ? parseTimestamp(event.timestamp_raw, 'iso8601') : null
      if (lvlKey) { const d = detectSeverity(String(obj[lvlKey])); event.severity = d?.level || String(obj[lvlKey]).toUpperCase(); event.severity_rank = d?.rank || 0 }
      event.message = msgKey ? String(obj[msgKey]) : JSON.stringify(obj)
      event.source = srcKey ? String(obj[srcKey]) : null
      for (const [k,v] of Object.entries(obj)) { if (k!==tsKey && k!==lvlKey && k!==msgKey && k!==srcKey) event.fields[k] = v }
      event.parsed = true
      return event
    } catch { event.parsed = false; return event }
  }

  if (formatDef.type === 'keyvalue') {
    const kv = parseKeyValue(line)
    if (kv) {
      const tsKey = ['timestamp','time','ts','datetime','date'].find(k => k in kv)
      const lvlKey = ['level','severity','lvl','log_level'].find(k => k in kv)
      const msgKey = ['message','msg','text','log'].find(k => k in kv)
      const srcKey = ['service','source','host','app','logger'].find(k => k in kv)
      event.timestamp_raw = tsKey ? kv[tsKey] : null
      event.timestamp = tsKey ? parseTimestamp(event.timestamp_raw, 'iso8601') : null
      if (lvlKey) { const d = detectSeverity(kv[lvlKey]); event.severity = d?.level || kv[lvlKey].toUpperCase(); event.severity_rank = d?.rank || 0 }
      event.message = msgKey ? kv[msgKey] : line
      event.source = srcKey ? kv[srcKey] : null
      event.fields = kv
      event.parsed = true
      return event
    }
    event.parsed = false; return event
  }

  if (formatDef.type === 'csv') {
    const parts = line.split(formatDef.delimiter).map(p => p.trim().replace(/^["']|["']$/g, ''))
    if (parts.length < formatDef.colCount - 1) { event.parsed = false; return event }
    formatDef.headers.forEach((h, i) => { event.fields[h] = parts[i] })
    const tsH = formatDef.headers.find(h => /time|date|timestamp/i.test(h))
    const lvlH = formatDef.headers.find(h => /level|severity|type/i.test(h))
    const msgH = formatDef.headers.find(h => /message|msg|text|description/i.test(h))
    if (tsH) { event.timestamp_raw = event.fields[tsH]; event.timestamp = parseTimestamp(event.timestamp_raw, 'iso8601') }
    if (lvlH) { const d = detectSeverity(event.fields[lvlH]); event.severity = d?.level || event.fields[lvlH]?.toUpperCase(); event.severity_rank = d?.rank || 0 }
    event.message = msgH ? event.fields[msgH] : parts.join(' | ')
    event.parsed = true
    return event
  }

  if (formatDef.re) {
    const match = line.match(formatDef.re)
    if (match) {
      formatDef.fields.forEach((field, i) => { if (match[i+1] !== undefined) event.fields[field] = match[i+1] })
      const tsField = formatDef.fields.find(f => /timestamp|time|date/.test(f))
      if (tsField && event.fields[tsField]) {
        event.timestamp_raw = event.fields[tsField]
        const tsP = (formatDef.name||'').includes('Apache')||(formatDef.name||'').includes('Nginx') ? 'apache_clf' : (formatDef.name||'').includes('Syslog')||(formatDef.name||'').includes('Auth') ? 'syslog_ts' : 'iso8601'
        event.timestamp = parseTimestamp(event.timestamp_raw, tsP)
      }
      const lvlField = formatDef.fields.find(f => /level|severity|priority/.test(f))
      if (lvlField && event.fields[lvlField]) { const d = detectSeverity(event.fields[lvlField]); event.severity = d?.level || event.fields[lvlField].toUpperCase(); event.severity_rank = d?.rank || 0 }
      const msgField = formatDef.fields.find(f => /message|msg/.test(f))
      if (msgField && event.fields[msgField]) event.message = event.fields[msgField]
      const srcField = formatDef.fields.find(f => /class|process|service|source|app|logger|hostname/.test(f))
      if (srcField && event.fields[srcField]) event.source = event.fields[srcField]
      if (formatDef.category === 'http_access') extractHttpFields(event)
      event.parsed = true
      return event
    }
  }

  // Fallback: dynamic inference
  for (const pattern of TS_PATTERNS) {
    const m = line.match(pattern.re)
    if (m) { event.timestamp_raw = m[0]; event.timestamp = parseTimestamp(m[0], pattern.name); break }
  }
  const sev = detectSeverity(line)
  if (sev) { event.severity = sev.level; event.severity_rank = sev.rank }
  const ipMatches = []
  let mip
  const ipRe = new RegExp(IPV4_RE.source, 'g')
  while ((mip = ipRe.exec(line)) !== null) ipMatches.push(mip[1])
  if (ipMatches.length > 0) event.fields.ips = ipMatches
  const httpM = line.match(/\b(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS|CONNECT|TRACE)\b/)
  if (httpM) event.fields.http_method = httpM[1]
  const httpS = line.match(/\b([1-5]\d{2})\b/)
  if (httpS) event.fields.status_code = httpS[1]
  event.message = line.trim()
  event.parsed = !!(event.timestamp || event.severity || ipMatches.length > 0 || event.fields.http_method)
  return event
}

export function parseLogFile(content, filename = '') {
  if (!content || !content.trim()) {
    return {
      filename, format: { type: 'empty', name: 'Empty File', category: 'generic', confidence: 1.0 },
      parsing: { total_raw_lines: 0, total_non_empty_lines: 0, parsed_lines: 0, unparsed_lines: 0, parse_success_rate: 0 },
      timeline: { first: null, last: null, duration_seconds: null },
      detected_fields: [], events: [], parsed_events: [], meta: {}
    }
  }

  const allLines = content.split('\n')

  // Handle JSON array
  if (content.trim().startsWith('[')) {
    try {
      const arr = JSON.parse(content.trim())
      if (Array.isArray(arr) && arr.length > 0) {
        const formatted = arr.map(item => JSON.stringify(item))
        const formatDef = { type: 'json', name: 'JSON Array Log', category: 'structured', confidence: 1.0 }
        const events = formatted.map((l, i) => parseLine(l, formatDef, i + 1)).filter(Boolean)
        return buildResult(events, formatDef, allLines.length, arr.length, filename)
      }
    } catch {}
  }

  const dataLines = allLines.filter(l => l.trim() && !/^\s*#/.test(l))
  const totalLines = dataLines.length
  const formatDef = detectFormat(dataLines)

  const events = []
  let lineNum = 0
  for (const line of allLines) {
    lineNum++
    if (!line.trim() || /^\s*#/.test(line)) continue
    const event = parseLine(line, formatDef, lineNum)
    if (event) events.push(event)
  }

  // Second pass enrichment
  for (const ev of events) {
    if (!ev.fields.client_ip && !ev.fields.ips) {
      const ipMatches = []
      let m
      const ipRe = new RegExp(IPV4_RE.source, 'g')
      while ((m = ipRe.exec(ev.raw_line)) !== null) ipMatches.push(m[1])
      if (ipMatches.length > 0) ev.fields.ips = ipMatches
    }
    if (!ev.severity) {
      const sev = detectSeverity(ev.raw_line)
      if (sev) { ev.severity = sev.level; ev.severity_rank = sev.rank }
    }
  }

  return buildResult(events, formatDef, allLines.length, totalLines, filename)
}

function buildResult(events, formatDef, rawLineCount, totalLines, filename) {
  const parsed = events.filter(e => e.parsed)
  const parseRate = totalLines > 0 ? (parsed.length / totalLines) * 100 : 0
  const detectedFields = new Set()
  for (const ev of events) {
    if (ev.timestamp) detectedFields.add('timestamp')
    if (ev.severity) detectedFields.add('severity')
    if (ev.source) detectedFields.add('source')
    if (ev.message) detectedFields.add('message')
    for (const k of Object.keys(ev.fields)) detectedFields.add(k)
  }
  const timestamps = events.map(e => e.timestamp).filter(t => t && !isNaN(t.getTime()))
  const firstTimestamp = timestamps.length > 0 ? new Date(Math.min(...timestamps.map(t => t.getTime()))) : null
  const lastTimestamp = timestamps.length > 0 ? new Date(Math.max(...timestamps.map(t => t.getTime()))) : null
  const validFirst = firstTimestamp && !isNaN(firstTimestamp.getTime()) ? firstTimestamp : null
  const validLast = lastTimestamp && !isNaN(lastTimestamp.getTime()) ? lastTimestamp : null
  return {
    filename,
    format: { type: formatDef.type, name: formatDef.name || 'Unknown', category: formatDef.category || 'generic', confidence: formatDef.confidence || 0.5 },
    parsing: { total_raw_lines: rawLineCount, total_non_empty_lines: totalLines, parsed_lines: parsed.length, unparsed_lines: events.length - parsed.length, parse_success_rate: parseFloat(parseRate.toFixed(2)) },
    timeline: { first: validFirst, last: validLast, duration_seconds: validFirst && validLast ? Math.round((validLast - validFirst) / 1000) : null },
    detected_fields: Array.from(detectedFields),
    events,
    parsed_events: parsed,
    meta: {
      has_timestamps: timestamps.length > 0,
      has_severity: events.some(e => e.severity),
      has_http: Array.from(detectedFields).some(f => /http_method|status_code|client_ip/.test(f)),
      has_ips: Array.from(detectedFields).some(f => /^ips$|^client_ip$|^ip$/.test(f)),
      has_auth: formatDef.category === 'authentication' || events.some(e => /\b(auth|login|ssh|sudo|password|accept|fail|invalid user|session)\b/i.test(e.message || '')),
      has_database: formatDef.category === 'database' || events.some(e => /\b(query|select|insert|update|delete|transaction|sql)\b/i.test(e.message || '')),
    }
  }
}
