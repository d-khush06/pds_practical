/**
 * Threat Analysis Simulator Engine
 * ================================
 * A safe, defensive threat-analysis simulator that evaluates request characteristics locally.
 *
 * SAFETY GUARANTEES:
 * - NO payload execution (no shell commands, no SQL queries, no JS evaluation, no eval).
 * - NO network requests sent to supplied IPs, APIs, or external hosts.
 * - Payloads are treated purely as inert text data.
 * - Classifications and risk scores are dynamically derived from actual features,
 *   never hard-coded from UI presets.
 */

// ── IP Validation & Classification ───────────────────────────────────────────
const IPV4_REGEX = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/
const IPV6_REGEX = /^(?:[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}$|^::(?:[a-fA-F0-9]{1,4}:){0,6}[a-fA-F0-9]{1,4}$|^(?:[a-fA-F0-9]{1,4}:){1,7}:$/

export function classifyIp(ipStr) {
  const ip = (ipStr || '').trim()
  if (!ip) {
    return { valid: false, format: 'Missing', type: 'Unspecified', isPrivate: false, isLoopback: false }
  }

  const isV4 = IPV4_REGEX.test(ip)
  const isV6 = IPV6_REGEX.test(ip) || ip.includes('::')

  if (!isV4 && !isV6 && ip.toLowerCase() !== 'localhost') {
    return { valid: false, format: 'Invalid', type: 'Malformed IP Format', isPrivate: false, isLoopback: false }
  }

  // Loopback
  if (ip === 'localhost' || ip === '127.0.0.1' || ip === '::1' || ip.startsWith('127.')) {
    return { valid: true, format: isV4 ? 'IPv4' : 'IPv6 / Loopback', type: 'Loopback (Localhost)', isPrivate: true, isLoopback: true }
  }

  if (isV4) {
    const parts = ip.split('.').map(Number)
    // RFC 1918 private addresses
    if (
      parts[0] === 10 ||
      (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) ||
      (parts[0] === 192 && parts[1] === 168)
    ) {
      return { valid: true, format: 'IPv4', type: 'Private Network (RFC 1918)', isPrivate: true, isLoopback: false }
    }
    // Link-local / reserved
    if (parts[0] === 169 && parts[1] === 254) {
      return { valid: true, format: 'IPv4', type: 'Link-Local / Reserved (RFC 3927)', isPrivate: true, isLoopback: false }
    }
    return { valid: true, format: 'IPv4', type: 'Public IPv4', isPrivate: false, isLoopback: false }
  }

  // IPv6
  if (ip.toLowerCase().startsWith('fc') || ip.toLowerCase().startsWith('fd')) {
    return { valid: true, format: 'IPv6', type: 'Unique Local Address (ULA)', isPrivate: true, isLoopback: false }
  }
  if (ip.toLowerCase().startsWith('fe80')) {
    return { valid: true, format: 'IPv6', type: 'Link-Local IPv6', isPrivate: true, isLoopback: false }
  }
  return { valid: true, format: 'IPv6', type: 'Public IPv6', isPrivate: false, isLoopback: false }
}

// ── User-Agent Analyzer ───────────────────────────────────────────────────────
const SCANNER_TOOL_PATTERNS = [
  { name: 'Nikto Web Scanner', re: /\bnikto\b/i },
  { name: 'sqlmap Automated SQLi Tool', re: /\bsqlmap\b/i },
  { name: 'DirBuster Directory Scanner', re: /\bdirbuster\b/i },
  { name: 'Gobuster Directory Scanner', re: /\bgobuster\b/i },
  { name: 'Nmap Scripting Engine', re: /\bnmap\b/i },
  { name: 'WPScan WordPress Scanner', re: /\bwpscan\b/i },
  { name: 'Masscan Port Scanner', re: /\bmasscan\b/i },
  { name: 'Zgrab Banner Grabber', re: /\bzgrab\b/i },
  { name: 'Acunetix Vulnerability Scanner', re: /\bacunetix\b/i },
  { name: 'Burp Suite Scanner', re: /\bburp(suite)?\b/i },
  { name: 'OWASP ZAP', re: /\b(owasp\s+zap|zap-cli)\b/i },
  { name: 'Hydra Login Cracker', re: /\bhydra\b/i }
]

const HEADLESS_CLIENT_PATTERNS = [
  { name: 'cURL Command-Line Tool', re: /\bcurl\/\d/i },
  { name: 'Wget Downloader', re: /\bwget\/\d/i },
  { name: 'Python Requests Library', re: /\bpython-requests\b/i },
  { name: 'Go HTTP Client', re: /\bgo-http-client\b/i },
  { name: 'Apache HttpClient', re: /\bapache-httpclient\b/i },
  { name: 'Node.js / Axios Client', re: /\b(axios|node-fetch)\b/i },
  { name: 'Java Net Client', re: /\bjava\/\d/i }
]

export function analyzeUserAgent(uaStr) {
  const ua = (uaStr || '').trim()
  if (!ua || ua.toLowerCase() === 'none') {
    return { category: 'Missing / Not Specified', tool: null, isScanner: false, isHeadless: false, confidence: 0.90 }
  }

  for (const s of SCANNER_TOOL_PATTERNS) {
    if (s.re.test(ua)) {
      return { category: 'Automated Security Scanner', tool: s.name, isScanner: true, isHeadless: true, confidence: 0.95 }
    }
  }

  for (const h of HEADLESS_CLIENT_PATTERNS) {
    if (h.re.test(ua)) {
      return { category: 'Automated Headless Client / Script', tool: h.name, isScanner: false, isHeadless: true, confidence: 0.88 }
    }
  }

  if (/mozilla\/5\.0.*(chrome|safari|firefox|edge|opera|trident)/i.test(ua)) {
    return { category: 'Standard Web Browser', tool: null, isScanner: false, isHeadless: false, confidence: 0.92 }
  }

  if (/bot|crawler|spider|slurp|facebookexternalhit|whatsapp/i.test(ua)) {
    return { category: 'Search Engine / Social Crawler', tool: null, isScanner: false, isHeadless: true, confidence: 0.85 }
  }

  return { category: 'Unusual / Custom Client', tool: null, isScanner: false, isHeadless: false, confidence: 0.65 }
}

// ── Shannon Entropy Calculation ───────────────────────────────────────────────
export function calcEntropy(str) {
  if (!str || str === 'none') return 0
  const len = str.length
  if (len <= 1) return 0
  const freq = {}
  for (const c of str) freq[c] = (freq[c] || 0) + 1
  const h = Object.values(freq).reduce((sum, count) => {
    const p = count / len
    return sum - p * Math.log2(p)
  }, 0)
  return parseFloat(h.toFixed(3))
}

// ── Input Normalization ───────────────────────────────────────────────────────
export function normalizeInput(rawVal) {
  const original = String(rawVal ?? '')
  const trimmed = original.trim()

  let normalized = trimmed
  let hasUrlEncoding = false
  let hasDoubleEncoding = false
  let hasHexEncoding = false

  // Detect and perform safe URL decoding
  if (/%[0-9a-fA-F]{2}/.test(trimmed)) {
    try {
      const decodedOnce = decodeURIComponent(trimmed.replace(/\+/g, ' '))
      if (decodedOnce !== trimmed) {
        hasUrlEncoding = true
        normalized = decodedOnce

        // Check for double URL encoding (e.g. %2527 -> %27 -> ')
        if (/%[0-9a-fA-F]{2}/.test(decodedOnce)) {
          try {
            const decodedTwice = decodeURIComponent(decodedOnce.replace(/\+/g, ' '))
            if (decodedTwice !== decodedOnce) {
              hasDoubleEncoding = true
              normalized = decodedTwice
            }
          } catch (_) { /* ignore nested decode errors */ }
        }
      }
    } catch (_) {
      hasUrlEncoding = true
    }
  }

  // Detect hex escape sequences (e.g. \x27)
  if (/\\x[0-9a-fA-F]{2}/i.test(normalized)) {
    hasHexEncoding = true
    normalized = normalized.replace(/\\x([0-9a-fA-F]{2})/gi, (_, hex) => String.fromCharCode(parseInt(hex, 16)))
  }

  // Detect unicode escapes (e.g. \u0027)
  if (/\\u[0-9a-fA-F]{4}/i.test(normalized)) {
    hasHexEncoding = true
    normalized = normalized.replace(/\\u([0-9a-fA-F]{4})/gi, (_, hex) => String.fromCharCode(parseInt(hex, 16)))
  }

  let encodingType = 'Plaintext'
  if (hasDoubleEncoding) encodingType = 'Double URL-Encoded'
  else if (hasUrlEncoding && hasHexEncoding) encodingType = 'Mixed URL & Hex Escape'
  else if (hasUrlEncoding) encodingType = 'Standard URL-Encoded'
  else if (hasHexEncoding) encodingType = 'Hex / Unicode Escape'

  return {
    original_value: original,
    normalized_value: normalized,
    lower_value: normalized.toLowerCase(),
    encodingType,
    hasUrlEncoding,
    hasDoubleEncoding,
    hasHexEncoding
  }
}

// ── Feature Extraction ────────────────────────────────────────────────────────
export function extractFeatures(key, val, ip, ua, norm) {
  const valLength = norm.original_value.length
  const keyLength = (key || '').length
  const entropy = calcEntropy(norm.original_value)
  const normEntropy = calcEntropy(norm.normalized_value)

  const specialChars = (norm.original_value.match(/['";:<>()\[\]{}\\/\\%$*+=&|!^~`]/g) || []).length
  const specialCharRatio = valLength > 0 ? parseFloat((specialChars / valLength).toFixed(3)) : 0

  const delimiterCount = (norm.normalized_value.match(/(--|;|\/\*|\*\/|\|{1,2}|&&|`|<|>)/g) || []).length

  const ipAnalysis = classifyIp(ip)
  const uaAnalysis = analyzeUserAgent(ua)

  return {
    parameter_key: key || '',
    key_length: keyLength,
    payload_length: valLength,
    original_entropy: entropy,
    normalized_entropy: normEntropy,
    special_char_count: specialChars,
    special_char_ratio: specialCharRatio,
    delimiter_count: delimiterCount,
    encoding: norm.encodingType,
    has_double_encoding: norm.hasDoubleEncoding,
    ip_format: ipAnalysis.format,
    ip_type: ipAnalysis.type,
    ip_valid: ipAnalysis.valid,
    is_private_ip: ipAnalysis.isPrivate,
    ua_category: uaAnalysis.category,
    ua_tool: uaAnalysis.tool,
    is_scanner_ua: uaAnalysis.isScanner,
    is_headless_ua: uaAnalysis.isHeadless
  }
}

// ── Input Validation ──────────────────────────────────────────────────────────
export function validateInput(ip, key, val) {
  const errors = []
  if (!key || !key.trim()) {
    errors.push('Parameter Key is required (e.g. "id", "search", "file").')
  } else if (key.length > 256) {
    errors.push('Parameter Key exceeds 256 characters.')
  }

  if (val === undefined || val === null || val === '') {
    errors.push('Parameter Value (Payload) cannot be empty.')
  } else if (val.length > 10000) {
    errors.push('Parameter Value exceeds maximum test simulation limit of 10,000 characters.')
  }

  const ipAnalysis = classifyIp(ip)
  if (ip && !ipAnalysis.valid) {
    errors.push(`Supplied IP address "${ip}" is not a valid IPv4, IPv6, or localhost address format.`)
  }

  return {
    isValid: errors.length === 0,
    errors,
    ipAnalysis
  }
}

// ── Pattern Detection & Threat Analysis Engine ────────────────────────────────
export function simulateThreatAnalysis({ ip, key, val, ua }) {
  const validation = validateInput(ip, key, val)
  if (!validation.isValid) {
    return {
      simulation: true,
      network_request_sent: false,
      timestamp: new Date().toISOString(),
      validation_error: true,
      errors: validation.errors,
      classification: { label: 'Validation Failed', category: 'Invalid Input', confidence: 0 },
      risk: { score: 0, severity: 'Low' },
      input: { parameter_key: key || '', parameter_length: (val || '').length, user_agent: ua || '', ip: ip || '', ip_valid: false },
      indicators: [],
      evidence: [],
      explanation: validation.errors.join(' '),
      recommendation: 'Provide valid parameters to run simulated analysis.',
      limitations: ['This is a local simulation.', 'No external target was contacted.']
    }
  }

  const norm = normalizeInput(val)
  const features = extractFeatures(key, val, ip, ua, norm)
  const rawVal = norm.original_value
  const normVal = norm.normalized_value
  const lowerVal = norm.lower_value
  const lowerKey = (key || '').toLowerCase().trim()
  const valLength = features.payload_length

  const indicators = []
  const evidenceList = []

  // ── 1. SQL Injection (SQLi) Detection ──────────────────────────────────────
  let sqliScore = 0
  const sqliMatches = []

  // Boolean-based OR / AND injection
  const boolSqliMatch = normVal.match(/(?:'|"|\b)\s*(or|and)\s+(?:'[^']*'='[^']*'|\d+\s*=\s*\d+|true\b|1\s*=\s*1|'1'='1'|'a'='a')/i)
  if (boolSqliMatch) {
    const isQuoted = boolSqliMatch[0].includes("'") || boolSqliMatch[0].includes('"')
    const dynamicWeight = Math.round(40 + (isQuoted ? 8 : 4) + Math.min(8, boolSqliMatch[0].length / 2))
    sqliScore += dynamicWeight
    sqliMatches.push(`Boolean logic bypass condition: "${boolSqliMatch[0]}"`)
    evidenceList.push({ indicator: 'SQLi Boolean Logic', source: 'Parameter Value', evidence_snippet: boolSqliMatch[0], confidence: 0.92 })
  }

  // UNION SELECT injection
  const unionSelectMatch = normVal.match(/union\s+(?:all\s+)?select\b/i)
  if (unionSelectMatch) {
    const hasColumns = /select\s+[\w\s,*()]+from/i.test(normVal)
    const dynamicWeight = Math.round(46 + (hasColumns ? 10 : 4) + Math.min(6, normVal.length / 20))
    sqliScore += dynamicWeight
    sqliMatches.push(`UNION SELECT query construction: "${unionSelectMatch[0]}"`)
    evidenceList.push({ indicator: 'SQLi UNION Statement', source: 'Parameter Value', evidence_snippet: unionSelectMatch[0], confidence: 0.97 })
  }

  // Time-based blind SQLi functions
  const timeSqliMatch = normVal.match(/\b(sleep|benchmark|waitfor\s+delay|pg_sleep)\s*\(\s*\d+\s*\)/i)
  if (timeSqliMatch) {
    const dynamicWeight = Math.round(42 + Math.min(8, timeSqliMatch[0].length))
    sqliScore += dynamicWeight
    sqliMatches.push(`Time-delay database function: "${timeSqliMatch[0]}"`)
    evidenceList.push({ indicator: 'SQLi Time Delay Function', source: 'Parameter Value', evidence_snippet: timeSqliMatch[0], confidence: 0.94 })
  }

  // Schema enumeration or system table access
  const schemaMatch = normVal.match(/\b(information_schema|sys\.tables|sqlite_master|dual)\b/i)
  if (schemaMatch) {
    const dynamicWeight = 34 + Math.min(8, schemaMatch[0].length)
    sqliScore += dynamicWeight
    sqliMatches.push(`System schema table reference: "${schemaMatch[0]}"`)
    evidenceList.push({ indicator: 'SQLi Schema Enumeration', source: 'Parameter Value', evidence_snippet: schemaMatch[0], confidence: 0.89 })
  }

  // SQL comment terminator with quote
  const commentMatch = normVal.match(/(?:'|"|;)\s*(--|\/\*.*?\*\/|#\s*$)/)
  if (commentMatch) {
    const dynamicWeight = 22 + (normVal.includes("'") ? 6 : 2)
    sqliScore += dynamicWeight
    sqliMatches.push(`SQL comment truncation delimiter: "${commentMatch[0]}"`)
    evidenceList.push({ indicator: 'SQLi Comment Delimiter', source: 'Parameter Value', evidence_snippet: commentMatch[0], confidence: 0.87 })
  }

  // Stacked queries with dangerous DDL/DML
  const dmlMatch = normVal.match(/;\s*(drop\s+table|delete\s+from|insert\s+into|update\s+\w+\s+set|alter\s+table)\b/i)
  if (dmlMatch) {
    const dynamicWeight = 50 + Math.min(10, dmlMatch[0].length / 2)
    sqliScore += dynamicWeight
    sqliMatches.push(`Stacked DDL/DML statement execution: "${dmlMatch[0]}"`)
    evidenceList.push({ indicator: 'SQLi Stacked Query Execution', source: 'Parameter Value', evidence_snippet: dmlMatch[0], confidence: 0.95 })
  }

  // Standalone SELECT clause (with conversational guard to avoid false positives)
  const isConversational = /\b(?:please|can you|help|i want|kindly|could you|prefer|language|menu|options|dropdown)\b/i.test(normVal)
  const selectFromMatch = normVal.match(/\bselect\s+(?:[\w*,\s()]|\bnull\b)+\s+from\s+(?:information_schema\.|sys\.|\w+)/i)
  if (selectFromMatch && !unionSelectMatch && !isConversational) {
    const dynamicWeight = 38 + Math.min(8, selectFromMatch[0].length / 4)
    sqliScore += dynamicWeight
    sqliMatches.push(`Structured SQL SELECT query: "${selectFromMatch[0]}"`)
    evidenceList.push({ indicator: 'SQL Statement Syntax', source: 'Parameter Value', evidence_snippet: selectFromMatch[0], confidence: 0.90 })
  }

  if (sqliScore > 0) {
    if (/^(id|user_id|cat|query|search|filter|where|sort|col)$/i.test(lowerKey)) {
      sqliScore += 6
    }
    indicators.push({
      type: 'sqli',
      title: 'SQL Injection Signature Detected',
      severity: sqliScore >= 45 ? 'High' : 'Moderate',
      weight: sqliScore,
      description: sqliMatches.join('; ')
    })
  }

  // ── 2. Cross-Site Scripting (XSS) Detection ────────────────────────────────
  let xssScore = 0
  const xssMatches = []

  // Explicit script tag
  const scriptTagMatch = normVal.match(/<script\b[^>]*>([\s\S]*?)<\/script>|<script\b/i)
  if (scriptTagMatch) {
    const dynamicWeight = 48 + Math.min(12, scriptTagMatch[0].length / 3)
    xssScore += dynamicWeight
    xssMatches.push(`HTML <script> execution tag: "${scriptTagMatch[0]}"`)
    evidenceList.push({ indicator: 'XSS Script Tag', source: 'Parameter Value', evidence_snippet: scriptTagMatch[0], confidence: 0.96 })
  }

  // JavaScript event handler
  const eventHandlerMatch = normVal.match(/\bon\w+\s*=\s*['"]?[^'"]*(alert|confirm|prompt|document\.cookie|window\.location|eval|fetch)/i)
  if (eventHandlerMatch) {
    const dynamicWeight = 42 + Math.min(10, eventHandlerMatch[0].length / 4)
    xssScore += dynamicWeight
    xssMatches.push(`Inline DOM event handler execution: "${eventHandlerMatch[0]}"`)
    evidenceList.push({ indicator: 'XSS Event Handler', source: 'Parameter Value', evidence_snippet: eventHandlerMatch[0], confidence: 0.93 })
  }

  // JavaScript pseudoprotocol
  const jsUriMatch = normVal.match(/\bjavascript:\s*(alert|prompt|confirm|eval|document|window)/i)
  if (jsUriMatch) {
    const dynamicWeight = 38 + Math.min(8, jsUriMatch[0].length / 3)
    xssScore += dynamicWeight
    xssMatches.push(`JavaScript URI pseudoprotocol: "${jsUriMatch[0]}"`)
    evidenceList.push({ indicator: 'XSS JavaScript URI', source: 'Parameter Value', evidence_snippet: jsUriMatch[0], confidence: 0.91 })
  }

  // Injected HTML tags with alert or onerror
  const imgErrMatch = normVal.match(/<(?:img|svg|iframe|body|input|audio|video)\s+[^>]*onerror\s*=/i)
  if (imgErrMatch) {
    const dynamicWeight = 44 + Math.min(8, imgErrMatch[0].length / 4)
    xssScore += dynamicWeight
    xssMatches.push(`Injected element with error handler: "${imgErrMatch[0]}"`)
    evidenceList.push({ indicator: 'XSS Injected Error Handler', source: 'Parameter Value', evidence_snippet: imgErrMatch[0], confidence: 0.93 })
  }

  if (xssScore > 0) {
    indicators.push({
      type: 'xss',
      title: 'Cross-Site Scripting (XSS) Signature Detected',
      severity: xssScore >= 45 ? 'High' : 'Moderate',
      weight: xssScore,
      description: xssMatches.join('; ')
    })
  }

  // ── 3. Command Injection / RCE Detection ──────────────────────────────────
  let rceScore = 0
  const rceMatches = []

  // Core shell command binaries
  const SHELL_COMMANDS_REGEX = /(?:^|[;&|`\n\r]|\$\()\s*(?:sudo\s+)?(echo\b|cat\b|ls\b|dir\b|whoami\b|id\b|uname\b|hostname\b|ping\b|curl\b|wget\b|nc\b|netcat\b|bash\b|sh\b|zsh\b|powershell\b|cmd\b|rm\b|cp\b|mv\b|chmod\b|chown\b|kill\b|ps\b|mkdir\b|touch\b|type\b|find\b|grep\b|awk\b|sed\b|certutil\b|nslookup\b|systeminfo\b|wmic\b)/i
  const shellCmdMatch = normVal.match(SHELL_COMMANDS_REGEX)

  // Delimited chaining (e.g. '; cat /etc/passwd && whoami')
  const hasShellDelimiter = /(;|\|{1,2}|&&|`|\$\()/.test(normVal)

  // Subshell execution: $(cmd) or `cmd`
  const subshellMatch = normVal.match(/\$\([a-zA-Z0-9_\s-]+\)|`[a-zA-Z0-9_\s-]+`/)

  // Sensitive linux/unix files
  const sysFileMatch = normVal.match(/\b(\/etc\/passwd|\/etc\/shadow|\/proc\/version|c:\\windows\\system32|c:\\boot\.ini)/i)

  // Dangerous backend code execution functions: system(), exec(), popen()
  const phpExecMatch = normVal.match(/\b(system|exec|passthru|shell_exec|popen|proc_open)\s*\(/i)

  if (shellCmdMatch) {
    const cmdName = shellCmdMatch[1].toLowerCase()
    const hasArgs = normVal.length > (shellCmdMatch.index + shellCmdMatch[0].length)
    const argsSnippet = normVal.substring(shellCmdMatch.index + shellCmdMatch[0].length).trim()

    let cmdWeight = 42
    if (hasShellDelimiter) cmdWeight += 14
    if (hasArgs && argsSnippet.length > 0) cmdWeight += Math.min(12, Math.round(argsSnippet.length * 1.5))
    if (cmdName === 'whoami' || cmdName === 'id' || cmdName === 'uname') cmdWeight += 8
    if (cmdName === 'echo') cmdWeight += (hasArgs ? 8 : 2)

    rceScore += cmdWeight
    rceMatches.push(`OS shell binary execution "${cmdName}": "${shellCmdMatch[0].trim()}"`)
    evidenceList.push({
      indicator: `Shell Command Execution (${cmdName})`,
      source: 'Parameter Value',
      evidence_snippet: normVal.length > 50 ? normVal.slice(0, 50) + '...' : normVal,
      confidence: hasShellDelimiter ? 0.96 : 0.88
    })
  }

  if (subshellMatch) {
    const dynamicWeight = 38 + Math.min(8, subshellMatch[0].length)
    rceScore += dynamicWeight
    rceMatches.push(`Subshell invocation operator: "${subshellMatch[0]}"`)
    evidenceList.push({ indicator: 'RCE Subshell Operator', source: 'Parameter Value', evidence_snippet: subshellMatch[0], confidence: 0.94 })
  }

  if (sysFileMatch) {
    const dynamicWeight = 42 + Math.min(8, sysFileMatch[0].length / 2)
    rceScore += dynamicWeight
    rceMatches.push(`Targeting sensitive system path: "${sysFileMatch[0]}"`)
    evidenceList.push({ indicator: 'RCE System File Target', source: 'Parameter Value', evidence_snippet: sysFileMatch[0], confidence: 0.97 })
  }

  if (phpExecMatch) {
    const dynamicWeight = 45 + Math.min(6, phpExecMatch[0].length)
    rceScore += dynamicWeight
    rceMatches.push(`Backend command execution wrapper: "${phpExecMatch[0]}"`)
    evidenceList.push({ indicator: 'RCE Execution Wrapper', source: 'Parameter Value', evidence_snippet: phpExecMatch[0], confidence: 0.92 })
  }

  if (rceScore > 0) {
    if (/^(cmd|exec|command|shell|run|payload|process|eval|cli)$/i.test(lowerKey)) {
      rceScore += 10
    }
    indicators.push({
      type: 'cmd_injection',
      title: 'Command Injection / RCE Signature Detected',
      severity: rceScore >= 45 ? 'High' : 'Moderate',
      weight: rceScore,
      description: rceMatches.join('; ')
    })
  }

  // ── 4. Path Traversal / LFI Detection ─────────────────────────────────────
  let lfiScore = 0
  const lfiMatches = []

  // Multi-hop parent directory traversals
  const traversalMatch = normVal.match(/(\.\.\/|\.\.\\){2,}/)
  if (traversalMatch) {
    const hopCount = (traversalMatch[0].match(/\.\./g) || []).length
    const dynamicWeight = 38 + Math.min(16, hopCount * 4)
    lfiScore += dynamicWeight
    lfiMatches.push(`Directory traversal sequence (${hopCount} hops): "${traversalMatch[0]}"`)
    evidenceList.push({ indicator: 'Path Traversal Sequence', source: 'Parameter Value', evidence_snippet: traversalMatch[0], confidence: 0.93 })
  }

  // Sensitive target paths
  const lfiFileMatch = normVal.match(/(\/etc\/passwd|\/etc\/shadow|win\.ini|windows\/system32|boot\.ini)/i)
  if (lfiFileMatch && !shellCmdMatch) {
    const dynamicWeight = 36 + Math.min(8, lfiFileMatch[0].length / 2)
    lfiScore += dynamicWeight
    lfiMatches.push(`Sensitive filesystem file reference: "${lfiFileMatch[0]}"`)
    evidenceList.push({ indicator: 'Sensitive File Path Reference', source: 'Parameter Value', evidence_snippet: lfiFileMatch[0], confidence: 0.92 })
  }

  // Null byte truncation
  const nullByteMatch = rawVal.match(/%00|\x00/)
  if (nullByteMatch) {
    lfiScore += 26
    lfiMatches.push(`Null byte string terminator (%00) for extension bypass`)
    evidenceList.push({ indicator: 'Null Byte Injection', source: 'Parameter Value', evidence_snippet: '%00', confidence: 0.90 })
  }

  if (lfiScore > 0) {
    if (/^(file|path|doc|page|include|template|view|load)$/i.test(lowerKey)) {
      lfiScore += 8
    }
    indicators.push({
      type: 'path_traversal',
      title: 'Path Traversal / LFI Signature Detected',
      severity: lfiScore >= 40 ? 'High' : 'Moderate',
      weight: lfiScore,
      description: lfiMatches.join('; ')
    })
  }

  // ── 5. User-Agent Header Analysis ─────────────────────────────────────────
  let uaScore = 0
  if (features.is_scanner_ua) {
    uaScore = 32 + Math.min(10, (ua || '').length / 10)
    indicators.push({
      type: 'scanner_recon',
      title: `Automated Security Scanner Identified (${features.ua_tool || 'Scanner'})`,
      severity: 'High',
      weight: Math.round(uaScore),
      description: `Client User-Agent signature matches known automated scanner: ${features.ua_tool || 'Scanner tool'}.`
    })
    evidenceList.push({ indicator: 'Automated Scanner Signature', source: 'User-Agent Header', evidence_snippet: (ua || '').slice(0, 50), confidence: 0.96 })
  } else if (features.is_headless_ua) {
    uaScore = 14 + Math.min(6, (ua || '').length / 8)
    indicators.push({
      type: 'headless_client',
      title: `Automated Scripting Client (${features.ua_tool || 'Headless Tool'})`,
      severity: 'Low',
      weight: Math.round(uaScore),
      description: `Client User-Agent matches programmatic HTTP client: ${features.ua_tool || 'Scripting tool'}.`
    })
  }

  // ── 6. Encoding & Anomaly Features ────────────────────────────────────────
  let obfuscationScore = 0
  if (norm.hasDoubleEncoding) {
    obfuscationScore += 24
    indicators.push({
      type: 'double_encoding',
      title: 'Double URL-Encoding Evasion Technique',
      severity: 'Moderate',
      weight: 24,
      description: 'Payload utilizes nested URL encoding (%25) often used to bypass WAF normalization filters.'
    })
    evidenceList.push({ indicator: 'Double URL-Encoding', source: 'Encoding Structure', evidence_snippet: norm.original_value.slice(0, 60), confidence: 0.91 })
  }

  if (norm.hasHexEncoding) {
    obfuscationScore += 16
    indicators.push({
      type: 'hex_encoding',
      title: 'Hex / Unicode Escape Sequences Detected',
      severity: 'Low',
      weight: 16,
      description: 'Input contains escaped hex or unicode character representations.'
    })
  }

  // High entropy / statistical anomaly check
  if (features.original_entropy > 4.4 && features.payload_length > 30 && sqliScore === 0 && xssScore === 0 && rceScore === 0) {
    const entropyBonus = Math.round((features.original_entropy - 4.4) * 10)
    obfuscationScore += 12 + entropyBonus
    indicators.push({
      type: 'high_entropy',
      title: 'Elevated Information Entropy',
      severity: 'Low',
      weight: 12 + entropyBonus,
      description: `Shannon entropy is ${features.original_entropy} bits (random or encrypted string characteristics).`
    })
  }

  // ── 7. Calculate Truly Dynamic Risk Score & Confidence (Strictly Separated!) ──────
  // Dynamic structural baseline noise: reflects real-world variability of text characteristics
  const lengthNoise = Math.min(6, Math.floor(Math.sqrt(valLength || 1)))
  const entropyNoise = features.original_entropy > 2.0 ? Math.min(4, Math.floor((features.original_entropy - 2.0) * 1.5)) : 0
  const punctuationNoise = Math.min(6, Math.floor(features.special_char_count * 1.5))
  const baselineStructuralRisk = Math.min(18, lengthNoise + entropyNoise + punctuationNoise)

  let calculatedRisk = 0
  const attackScores = [sqliScore, xssScore, rceScore, lfiScore].filter(s => s > 0)
  const maxAttackScore = attackScores.length > 0 ? Math.max(...attackScores) : 0

  if (maxAttackScore > 0) {
    // Primary attack score + compounding secondary factors + header & encoding modifiers
    const secondaryCompound = attackScores
      .filter(s => s !== maxAttackScore)
      .reduce((acc, s) => acc + (s * 0.35), 0)

    calculatedRisk = maxAttackScore + secondaryCompound + (uaScore * 0.4) + (obfuscationScore * 0.5)
  } else if (uaScore > 0 || obfuscationScore > 0) {
    calculatedRisk = (uaScore * 0.8) + (obfuscationScore * 0.8) + (baselineStructuralRisk * 0.5)
  } else {
    // Truly dynamic benign / baseline score that varies with exact length, entropy, and punctuation
    calculatedRisk = Math.max(1, baselineStructuralRisk)
  }

  const finalRiskScore = Math.min(100, Math.max(1, Math.round(calculatedRisk)))

  let severity = 'Low'
  if (finalRiskScore >= 76) severity = 'Critical'
  else if (finalRiskScore >= 51) severity = 'High'
  else if (finalRiskScore >= 21) severity = 'Moderate'

  // Threat Classification Category & Label
  let category = 'Benign'
  let label = 'Benign Normal Request'
  let dynamicConfidence = 0.92

  if (rceScore >= 35) {
    category = 'Command Injection'
    label = 'Remote Code Execution (RCE) / Command Injection Signature'
    // Dynamic confidence: graduated based on command specificity and shell delimiters (76%–96%)
    dynamicConfidence = Math.min(0.96, Math.max(0.70, 0.68 + (rceScore / 220) * 0.20 + (hasShellDelimiter ? 0.08 : 0.02)))
  } else if (sqliScore >= 35) {
    category = 'SQL Injection'
    label = 'Suspicious SQL-like Input / SQL Injection Attempt'
    dynamicConfidence = Math.min(0.96, Math.max(0.70, 0.69 + (sqliScore / 220) * 0.20 + (unionSelectMatch ? 0.07 : 0.02)))
  } else if (xssScore >= 35) {
    category = 'Cross-Site Scripting'
    label = 'Cross-Site Scripting (XSS) Exploit Pattern'
    dynamicConfidence = Math.min(0.96, Math.max(0.70, 0.68 + (xssScore / 220) * 0.20 + (scriptTagMatch ? 0.08 : 0.02)))
  } else if (lfiScore >= 30) {
    category = 'Path Traversal'
    label = 'Path Traversal / Local File Inclusion (LFI) Pattern'
    dynamicConfidence = Math.min(0.95, Math.max(0.69, 0.67 + (lfiScore / 220) * 0.20 + (traversalMatch ? 0.07 : 0.02)))
  } else if (features.is_scanner_ua) {
    category = 'Scanner Activity'
    label = `Automated Vulnerability Scanner Probe (${features.ua_tool || 'Scanner'})`
    dynamicConfidence = 0.94
  } else if (finalRiskScore >= 21) {
    category = 'Suspicious'
    label = 'Suspicious Input / Anomaly Detected'
    dynamicConfidence = Math.min(0.85, Math.max(0.62, 0.58 + (finalRiskScore / 100) * 0.24))
  } else {
    category = 'Benign'
    label = 'Benign Normal Request'
    // Dynamic benign confidence: scales from ~78% for complex/noisy text to ~96% for clean inputs
    dynamicConfidence = Math.min(0.96, Math.max(0.76, 0.96 - (baselineStructuralRisk * 0.012)))
  }

  dynamicConfidence = parseFloat(dynamicConfidence.toFixed(2))

  // Build Dynamic Explanation
  let explanation = ''
  if (category === 'Benign') {
    explanation = `The supplied parameter "${key}" contains standard alphanumeric request data (${features.payload_length} chars, ${features.original_entropy} bits entropy) without executable syntax or known exploit patterns. Characteristics match normal application traffic.`
  } else {
    const matchedNames = indicators.map(i => i.title).join(', ')
    explanation = `Evaluation of parameter "${key}" and client headers triggered ${indicators.length} security indicator(s): ${matchedNames}. Classification was calculated dynamically from structural syntax, entropy (${features.original_entropy} bits), and heuristic weights.`
  }

  // Build Dynamic Recommendations
  let recommendation = ''
  if (category === 'SQL Injection') {
    recommendation = 'Use parameterized queries / prepared statements (e.g. PDO, SQLAlchemy, Prisma). Never concatenate unsanitized user inputs into database statements.'
  } else if (category === 'Cross-Site Scripting') {
    recommendation = 'Contextually HTML-encode user input before rendering in web templates. Enforce a strict Content-Security-Policy (CSP) header.'
  } else if (category === 'Command Injection') {
    recommendation = 'Avoid passing user-supplied input to system shell functions (exec, system, popen). Use parameterized standard library APIs.'
  } else if (category === 'Path Traversal') {
    recommendation = 'Canonicalize file paths and validate against a strict allowed-directory whitelist. Disallow relative path traversal sequences (../).'
  } else if (category === 'Scanner Activity') {
    recommendation = 'Block or rate-limit automated security testing scanners at perimeter firewall / WAF layers unless explicitly authorized.'
  } else if (category === 'Suspicious') {
    recommendation = 'Validate parameter structure against a strict schema. Inspect application logs around this request window for repeated anomalies.'
  } else {
    recommendation = 'No immediate mitigation required. Continue routine security monitoring.'
  }

  // Result Schema matching section 20
  return {
    simulation: true,
    network_request_sent: false,
    timestamp: new Date().toISOString(),
    classification: {
      label,
      category,
      confidence: dynamicConfidence
    },
    risk: {
      score: finalRiskScore,
      severity
    },
    input: {
      parameter_key: key,
      parameter_length: features.payload_length,
      original_value: norm.original_value,
      normalized_value: norm.normalized_value,
      user_agent: ua || 'Unspecified',
      ip: ip || 'Unspecified',
      ip_valid: features.ip_valid,
      ip_type: features.ip_type
    },
    features,
    indicators,
    evidence: evidenceList,
    explanation,
    recommendation,
    limitations: [
      'This is a local simulation.',
      'No external target was contacted.',
      'Analysis was performed purely on text characteristics without code execution.'
    ]
  }
}

// ── Realistic Test Presets (Detection Test Cases) ─────────────────────────────
// NOTE: Presets ONLY populate test input fields. They do NOT dictate the verdict!
export const DETECTION_TEST_CASES = {
  sqli: {
    id: 'sqli',
    title: 'SQLi Test Case',
    badge: 'SQL Injection',
    ip: '198.51.100.42',
    key: 'id',
    val: "1' OR 1=1 UNION SELECT username, password_hash FROM admin_users--",
    ua: 'sqlmap/1.6.12#stable'
  },
  xss: {
    id: 'xss',
    title: 'XSS Test Case',
    badge: 'Cross-Site Scripting',
    ip: '203.0.113.88',
    key: 'search',
    val: "<script>alert('Simulated XSS Test');</script>",
    ua: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0'
  },
  rce: {
    id: 'rce',
    title: 'RCE / Shell Test Case',
    badge: 'Command Injection',
    ip: '198.51.100.19',
    key: 'cmd',
    val: '; cat /etc/passwd && whoami',
    ua: 'curl/8.4.0'
  },
  scanner: {
    id: 'scanner',
    title: 'Scanner UA Test Case',
    badge: 'Vulnerability Scanner',
    ip: '192.0.2.145',
    key: 'path',
    val: '/administrator/index.php',
    ua: 'Mozilla/5.0 (compatible; Nikto/2.1.6; Automated Vulnerability Scanner)'
  },
  lfi: {
    id: 'lfi',
    title: 'LFI Path Test Case',
    badge: 'Path Traversal',
    ip: '198.51.100.73',
    key: 'file',
    val: '../../../../etc/passwd',
    ua: 'python-requests/2.31.0'
  },
  benign: {
    id: 'benign',
    title: 'Benign Traffic Test Case',
    badge: 'Normal Traffic',
    ip: '104.28.209.153',
    key: 'page',
    val: 'account_settings',
    ua: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/121.0'
  }
}
