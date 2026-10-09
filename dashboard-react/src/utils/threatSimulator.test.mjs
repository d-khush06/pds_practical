/**
 * Threat Simulator Unit Tests
 * ============================
 * Verifies all 14 required evaluation cases from Section 24:
 * 1. Normal benign request
 * 2. Suspicious request
 * 3. SQL-like input
 * 4. Script-like input
 * 5. Path traversal-like input
 * 6. Scanner-like User-Agent
 * 7. Invalid IP
 * 8. Private IP
 * 9. IPv6
 * 10. Empty payload
 * 11. Very long payload
 * 12. Encoded input
 * 13. Mixed indicators
 * 14. Unknown pattern
 *
 * Also verifies that classification is dynamic and evidence-based,
 * NOT dependent on any preset selection.
 */

import { simulateThreatAnalysis, classifyIp, normalizeInput } from './threatSimulator.js'

function assert(cond, msg) {
  if (!cond) {
    console.error(`❌ FAILED: ${msg}`)
    process.exit(1)
  }
}

console.log('🧪 Starting Threat Analysis Simulator Test Suite...\n')

// 1. Normal benign request
{
  const res = simulateThreatAnalysis({
    ip: '104.28.209.153',
    key: 'theme',
    val: 'dark_mode',
    ua: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0'
  })
  assert(res.classification.category === 'Benign', '1. Benign request must classify as Benign')
  assert(res.risk.score <= 20, '1. Benign risk score must be Low (<= 20)')
  assert(res.simulation === true && res.network_request_sent === false, '1. Safe simulation flags must be true/false')
  console.log('✅ Test 1 Passed: Normal benign request evaluated as Benign (Risk:', res.risk.score, ')')
}

// 2. Suspicious request (anomalous special chars without full exploit)
{
  const res = simulateThreatAnalysis({
    ip: '198.51.100.12',
    key: 'filter',
    val: 'price!@#$%^&*()_+~`',
    ua: 'Mozilla/5.0'
  })
  assert(res.risk.score > 0, '2. Suspicious request must have elevated risk')
  console.log('✅ Test 2 Passed: Suspicious request detected with elevated risk (Score:', res.risk.score, ')')
}

// 3. SQL-like input
{
  const res = simulateThreatAnalysis({
    ip: '198.51.100.42',
    key: 'id',
    val: "1' OR 1=1 UNION SELECT username, password FROM users--",
    ua: 'Mozilla/5.0'
  })
  assert(res.classification.category === 'SQL Injection', '3. Must classify as SQL Injection')
  assert(res.risk.score >= 51, '3. SQLi risk must be High/Critical')
  assert(res.evidence.length > 0, '3. Evidence list must contain SQL patterns')
  console.log('✅ Test 3 Passed: SQL-like input classified as SQL Injection (Score:', res.risk.score, ', Conf:', res.classification.confidence, ')')
}

// 4. Script-like input (XSS)
{
  const res = simulateThreatAnalysis({
    ip: '203.0.113.88',
    key: 'search',
    val: "<script>alert('XSS-Test')</script>",
    ua: 'Mozilla/5.0'
  })
  assert(res.classification.category === 'Cross-Site Scripting', '4. Must classify as Cross-Site Scripting')
  assert(res.risk.score >= 51, '4. XSS risk must be High/Critical')
  assert(res.evidence.some(e => e.evidence_snippet.includes('<script')), '4. Evidence must include script tag')
  console.log('✅ Test 4 Passed: Script-like input classified as Cross-Site Scripting (Score:', res.risk.score, ')')
}

// 5. Path traversal-like input
{
  const res = simulateThreatAnalysis({
    ip: '198.51.100.73',
    key: 'file',
    val: '../../../../etc/passwd',
    ua: 'curl/7.88.1'
  })
  assert(res.classification.category === 'Path Traversal', '5. Must classify as Path Traversal')
  assert(res.risk.score >= 51, '5. LFI risk must be High/Critical')
  console.log('✅ Test 5 Passed: Path traversal-like input classified as Path Traversal (Score:', res.risk.score, ')')
}

// 6. Scanner-like User-Agent
{
  const res = simulateThreatAnalysis({
    ip: '192.0.2.145',
    key: 'page',
    val: 'home',
    ua: 'Mozilla/5.0 (compatible; Nikto/2.1.6; Automated Security Scanner)'
  })
  assert(res.features.is_scanner_ua === true, '6. Scanner UA must be detected')
  assert(res.classification.category === 'Scanner Activity', '6. Must identify Scanner Activity')
  console.log('✅ Test 6 Passed: Scanner-like User-Agent detected (Tool:', res.features.ua_tool, ')')
}

// 7. Invalid IP
{
  const res = simulateThreatAnalysis({
    ip: '999.999.999.999',
    key: 'id',
    val: '123',
    ua: 'Mozilla/5.0'
  })
  assert(res.validation_error === true, '7. Invalid IP must be caught during validation')
  assert(res.errors.some(e => e.includes('valid IPv4')), '7. Error message must mention IP format')
  console.log('✅ Test 7 Passed: Invalid IP caught with validation error')
}

// 8. Private IP
{
  const res = simulateThreatAnalysis({
    ip: '192.168.1.105',
    key: 'query',
    val: 'status',
    ua: 'Mozilla/5.0'
  })
  assert(res.input.ip_valid === true, '8. Private IP is valid format')
  assert(res.input.ip_type.includes('Private'), '8. Must categorize as Private Network IP')
  console.log('✅ Test 8 Passed: Private IP recognized correctly (Type:', res.input.ip_type, ')')
}

// 9. IPv6
{
  const res = simulateThreatAnalysis({
    ip: '2001:0db8:85a3:0000:0000:8a2e:0370:7334',
    key: 'action',
    val: 'view',
    ua: 'Mozilla/5.0'
  })
  assert(res.input.ip_valid === true, '9. IPv6 must be marked valid')
  assert(res.features.ip_format === 'IPv6', '9. Format must be IPv6')
  console.log('✅ Test 9 Passed: IPv6 format validated and classified')
}

// 10. Empty payload
{
  const res = simulateThreatAnalysis({
    ip: '198.51.100.1',
    key: 'id',
    val: '',
    ua: 'Mozilla/5.0'
  })
  assert(res.validation_error === true, '10. Empty payload must fail validation')
  console.log('✅ Test 10 Passed: Empty payload rejected with validation error')
}

// 11. Very long payload
{
  const longVal = 'A'.repeat(5000)
  const res = simulateThreatAnalysis({
    ip: '198.51.100.1',
    key: 'data',
    val: longVal,
    ua: 'Mozilla/5.0'
  })
  assert(res.input.parameter_length === 5000, '11. Length correctly tracked')
  console.log('✅ Test 11 Passed: Long payload analyzed safely without crash')
}

// 12. Encoded input (URL encoded SQLi)
{
  const res = simulateThreatAnalysis({
    ip: '198.51.100.1',
    key: 'id',
    val: '1%27%20OR%201%3D1%20--%20',
    ua: 'Mozilla/5.0'
  })
  assert(res.features.encoding.includes('URL-Encoded'), '12. URL encoding detected')
  assert(res.classification.category === 'SQL Injection', '12. Normalized SQLi correctly detected')
  console.log('✅ Test 12 Passed: Encoded input normalized and detected (Encoding:', res.features.encoding, ')')
}

// 13. Mixed indicators (Command Injection + Scanner UA)
{
  const res = simulateThreatAnalysis({
    ip: '203.0.113.5',
    key: 'cmd',
    val: '; cat /etc/passwd && whoami',
    ua: 'sqlmap/1.6.12#stable'
  })
  assert(res.risk.score >= 76, '13. Mixed critical indicators must achieve Critical risk')
  assert(res.risk.severity === 'Critical', '13. Severity must be Critical')
  console.log('✅ Test 13 Passed: Mixed indicators evaluated as Critical (Score:', res.risk.score, ')')
}

// 14. Unknown pattern / benign words false positive check
{
  // A query containing "select your language from the list" should NOT be classified as SQL injection!
  const res = simulateThreatAnalysis({
    ip: '198.51.100.1',
    key: 'instruction',
    val: 'Please select your preferred language from the options',
    ua: 'Mozilla/5.0'
  })
  assert(res.classification.category === 'Benign', '14. English text containing "select" and "from" without syntax must remain Benign')
  assert(res.risk.score <= 20, '14. False positive guard: risk must be Low')
  console.log('✅ Test 14 Passed: False positive guard verified — conversational English remains Benign (Score:', res.risk.score, ')')
}

// 15. Verify preset independence:
{
  // If user modifies SQLi preset to innocent input, the engine must classify as Benign!
  const res = simulateThreatAnalysis({
    ip: '45.33.32.156', // SQLi preset IP
    key: 'id',
    val: '42', // innocent integer
    ua: 'Mozilla/5.0'
  })
  assert(res.classification.category === 'Benign', '15. Preset IP with benign value must classify as Benign')
  console.log('✅ Test 15 Passed: Preset independence verified — classification is 100% dynamic based on actual input')
}

console.log('\n🎉 ALL 15 THREAT SIMULATOR TESTS PASSED SUCCESSFULLY!\n')
