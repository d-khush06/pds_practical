import { useState, useRef, useCallback, useEffect } from 'react'
import {
  Shield, Play, CheckCircle2, AlertTriangle, UploadCloud, Bot,
  MessageSquare, TerminalSquare, Cpu, Send, Sparkles, ArrowUp,
  FileText, Activity, Info, Clock, Zap, Lock, Database, Globe,
  ChevronDown, ChevronRight, X, TrendingUp, AlertCircle, Eye,
  RefreshCw, Check, HelpCircle, BarChart2, Link2, Search,
  Lightbulb, Paperclip, ListChecks, FileCode, Target
} from 'lucide-react'
import { calcEntropy } from '../../utils/helpers'
import { parseLogFile } from '../../utils/logParser'
import { analyzeLog } from '../../utils/logAnalyzer'
import {
  simulateThreatAnalysis,
  DETECTION_TEST_CASES,
  classifyIp,
  analyzeUserAgent
} from '../../utils/threatSimulator'

// ── Helpers ───────────────────────────────────────────────────────────────────
const SEVERITY_COLORS = {
  CRITICAL: '#dc2626', FATAL: '#dc2626', EMERGENCY: '#b91c1c', ALERT: '#d97706',
  ERROR: '#ef4444', WARNING: '#f59e0b', NOTICE: '#60a5fa',
  INFO: '#34d399', DEBUG: '#8b5cf6', TRACE: '#a78bfa'
}

function renderIcon(iconName, size = 18, color) {
  if (!iconName) return null
  if (typeof iconName !== 'string') return iconName

  const iconProps = { size, style: color ? { color } : undefined }

  switch (iconName) {
    case 'bot':
    case '🤖':
      return <Bot {...iconProps} style={{ color: color || 'var(--accent-indigo, #818cf8)' }} />
    case 'shield':
    case 'security':
    case '🛡️':
    case '🛡':
      return <Shield {...iconProps} style={{ color: color || '#38bdf8' }} />
    case 'alert':
    case 'warn':
    case 'warning':
    case '⚠️':
    case '⚠':
      return <AlertTriangle {...iconProps} style={{ color: color || '#f59e0b' }} />
    case 'globe':
    case 'network':
    case '🌐':
      return <Globe {...iconProps} style={{ color: color || '#60a5fa' }} />
    case 'link':
    case 'endpoint':
    case '🔗':
      return <Link2 {...iconProps} style={{ color: color || '#a78bfa' }} />
    case 'chart':
    case 'status':
    case '📊':
      return <BarChart2 {...iconProps} style={{ color: color || '#34d399' }} />
    case 'lock':
    case 'auth':
    case '🔐':
    case '🔒':
      return <Lock {...iconProps} style={{ color: color || '#f43f5e' }} />
    case 'database':
    case 'db':
    case '🗄️':
    case '🗄':
      return <Database {...iconProps} style={{ color: color || '#fb923c' }} />
    case 'trend':
    case 'stats':
    case '📈':
      return <TrendingUp {...iconProps} style={{ color: color || '#2dd4bf' }} />
    case 'clock':
    case 'time':
    case 'timeline':
    case '🕐':
      return <Clock {...iconProps} style={{ color: color || '#818cf8' }} />
    case 'lightbulb':
    case 'tips':
    case 'remedy':
    case '💡':
      return <Lightbulb {...iconProps} style={{ color: color || '#facc15' }} />
    case 'search':
    case 'format':
    case 'schema':
    case '🔍':
      return <Search {...iconProps} style={{ color: color || '#38bdf8' }} />
    case 'check':
    case 'clean':
    case 'success':
    case '✅':
      return <CheckCircle2 {...iconProps} style={{ color: color || '#34d399' }} />
    case 'danger':
    case 'emergency':
    case '🚨':
      return <AlertCircle {...iconProps} style={{ color: color || '#ef4444' }} />
    case 'sparkles':
    case '⚡':
      return <Zap {...iconProps} style={{ color: color || '#f59e0b' }} />
    case 'clipboard':
    case 'checklist':
    case '📋':
      return <ListChecks {...iconProps} style={{ color: color || '#60a5fa' }} />
    case 'message':
    case 'chat':
    case '💬':
      return <MessageSquare {...iconProps} style={{ color: color || '#c084fc' }} />
    case 'paperclip':
    case 'file':
    case '📎':
      return <Paperclip {...iconProps} style={{ color: color || '#94a3b8' }} />
    case 'info':
    case 'ℹ️':
      return <Info {...iconProps} style={{ color: color || '#60a5fa' }} />
    default:
      return null
  }
}

function Badge({ text, color, bg }) {
  return (
    <span style={{
      display: 'inline-block', padding: '2px 8px', borderRadius: 12,
      fontSize: 11, fontWeight: 600, letterSpacing: '0.4px', textTransform: 'uppercase',
      color: color || '#34d399', background: bg || 'rgba(52,211,153,0.12)',
      border: `1px solid ${color || '#34d399'}30`
    }}>{text}</span>
  )
}

function MetricCard({ label, value, sub, icon: Icon, color = '#60a5fa', unavailable = false }) {
  return (
    <div style={{
      background: 'var(--bg-input)', padding: '8px 12px', borderRadius: 8,
      border: `1px solid ${unavailable ? 'var(--border-subtle)' : 'var(--border-medium)'}`,
      display: 'flex', flexDirection: 'column', gap: 3
    }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 5, fontSize: 10, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.4px', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
        {Icon && <Icon size={11} style={{ color: unavailable ? 'var(--text-muted)' : color, flexShrink: 0 }} />}
        <span style={{ overflow: 'hidden', textOverflow: 'ellipsis' }}>{label}</span>
      </div>
      <div style={{ fontSize: unavailable ? 12 : 16, fontWeight: unavailable ? 400 : 700, color: unavailable ? 'var(--text-muted)' : 'var(--text-primary)', fontStyle: unavailable ? 'italic' : 'normal', lineHeight: 1.2 }}>
        {value}
      </div>
      {sub && <div style={{ fontSize: 10, color: 'var(--text-muted)' }}>{sub}</div>}
    </div>
  )
}

function SectionBlock({ title, icon: Icon, color = '#60a5fa', children, defaultOpen = true }) {
  const [open, setOpen] = useState(defaultOpen)
  return (
    <div style={{ marginBottom: 12, border: '1px solid var(--border-subtle)', borderRadius: 10, overflow: 'hidden' }}>
      <div
        onClick={() => setOpen(o => !o)}
        style={{
          display: 'flex', alignItems: 'center', gap: 8, padding: '9px 14px',
          background: 'var(--bg-card)', cursor: 'pointer', userSelect: 'none',
          borderBottom: open ? '1px solid var(--border-subtle)' : 'none'
        }}
      >
        {Icon && <Icon size={14} style={{ color }} />}
        <span style={{ fontWeight: 600, fontSize: 13, color: 'var(--text-primary)', flex: 1 }}>{title}</span>
        {open ? <ChevronDown size={13} style={{ color: 'var(--text-muted)' }} /> : <ChevronRight size={13} style={{ color: 'var(--text-muted)' }} />}
      </div>
      {open && <div style={{ padding: '12px 14px', background: 'var(--bg-card-h)' }}>{children}</div>}
    </div>
  )
}

function TableMetric({ items, columns = ['Key', 'Count'], maxRows = 8 }) {
  if (!items || items.length === 0) return <div style={{ color: 'var(--text-muted)', fontSize: 13 }}>No data</div>
  return (
    <div style={{ overflowX: 'auto' }}>
      <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 13 }}>
        <thead>
          <tr>
            {columns.map(c => <th key={c} style={{ textAlign: 'left', padding: '5px 10px', color: 'var(--text-muted)', fontWeight: 500, borderBottom: '1px solid var(--border-subtle)', fontSize: 11, textTransform: 'uppercase', letterSpacing: '0.4px' }}>{c}</th>)}
          </tr>
        </thead>
        <tbody>
          {items.slice(0, maxRows).map((row, i) => (
            <tr key={i} style={{ borderBottom: '1px solid var(--border-subtle)' }}>
              <td style={{ padding: '6px 10px', color: 'var(--text-primary)', fontFamily: 'monospace', maxWidth: 280, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                {row.key}
              </td>
              <td style={{ padding: '6px 10px', color: 'var(--text-secondary)', textAlign: 'right' }}>
                {typeof row.count === 'number' ? row.count.toLocaleString() : row.count}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

function IndicatorCard({ indicator }) {
  const isInfo = indicator.type === 'info' || indicator.applicable === false
  const isThreat = indicator.type === 'security_threat'
  const color = isInfo ? '#60a5fa' : isThreat ? '#ef4444' : '#f59e0b'
  const bg = isInfo ? 'rgba(96,165,250,0.08)' : isThreat ? 'rgba(239,68,68,0.10)' : 'rgba(245,158,11,0.10)'
  const Icon = isInfo ? Info : isThreat ? AlertTriangle : AlertCircle

  return (
    <div style={{ border: `1px solid ${color}30`, background: bg, borderRadius: 10, padding: '14px 16px', marginBottom: 10 }}>
      <div style={{ display: 'flex', gap: 10, alignItems: 'flex-start' }}>
        <Icon size={15} style={{ color, marginTop: 2, flexShrink: 0 }} />
        <div style={{ flex: 1 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 4, flexWrap: 'wrap' }}>
            <span style={{ fontSize: 14, fontWeight: 600, color }}>{indicator.title}</span>
            {indicator.severity && <Badge text={indicator.severity} color={color} bg={bg} />}
            {indicator.event_count !== undefined && <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>{indicator.event_count.toLocaleString()} events</span>}
          </div>
          <div style={{ fontSize: 13, color: 'var(--text-secondary)', lineHeight: 1.6, marginBottom: indicator.evidence ? 6 : 0 }}>{indicator.description}</div>
          {indicator.evidence && (
            <div style={{ fontSize: 12, color: 'var(--text-muted)', fontFamily: 'monospace', background: 'var(--bg-input)', padding: '6px 10px', borderRadius: 6, marginTop: 6, wordBreak: 'break-all' }}>
              Evidence: {indicator.evidence}
            </div>
          )}
          {indicator.derived_from && (
            <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 6 }}>
              Source: <code style={{ color: 'var(--accent-cyan)' }}>{indicator.derived_from.field}</code> · Method: {indicator.derived_from.method}
            </div>
          )}
        </div>
      </div>
    </div>
  )
}

function AnomalyCard({ anomaly }) {
  const isInfo = anomaly.type === 'info'
  const color = isInfo ? '#60a5fa' : '#f59e0b'
  const bg = isInfo ? 'rgba(96,165,250,0.08)' : 'rgba(245,158,11,0.10)'

  return (
    <div style={{ border: `1px solid ${color}30`, background: bg, borderRadius: 10, padding: '14px 16px', marginBottom: 10 }}>
      <div style={{ display: 'flex', gap: 10, alignItems: 'flex-start' }}>
        <TrendingUp size={15} style={{ color, marginTop: 2, flexShrink: 0 }} />
        <div style={{ flex: 1 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 4 }}>
            <span style={{ fontSize: 14, fontWeight: 600, color }}>{anomaly.title}</span>
            {anomaly.severity && <Badge text={anomaly.severity} color={color} bg={bg} />}
            {anomaly.confidence !== undefined && <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>confidence: {(anomaly.confidence*100).toFixed(0)}%</span>}
          </div>
          <div style={{ fontSize: 13, color: 'var(--text-secondary)', lineHeight: 1.6 }}>{anomaly.description}</div>
          {anomaly.evidence && (
            <div style={{ fontSize: 12, color: 'var(--text-muted)', fontFamily: 'monospace', background: 'var(--bg-input)', padding: '6px 10px', borderRadius: 6, marginTop: 6 }}>
              {anomaly.evidence}
            </div>
          )}
          {anomaly.derived_from && (
            <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 6 }}>
              Method: {anomaly.derived_from.method}
            </div>
          )}
        </div>
      </div>
    </div>
  )
}

// ── Full Dynamic Analysis Report ──────────────────────────────────────────────
function AnalysisReport({ parseResult, analysis }) {
  const { format, parsing, timeline } = parseResult
  const { generic_stats, http, application, authentication, database, anomalies, security, top_messages } = analysis

  // 4 Core Numerical KPIs strictly locked to 1 row
  const kpiMetrics = [
    { name: 'Total Log Lines', value: parsing.total_non_empty_lines?.toLocaleString() ?? '0', status: 'calculated' },
    { name: 'Parsed Events', value: (parseResult.parsed_events?.length || parsing.parsed_lines)?.toLocaleString() ?? '0', status: 'calculated' },
    { name: 'Parse Success Rate', value: `${parsing.parse_success_rate}%`, status: 'calculated' },
    { name: 'Format Confidence', value: `${(format.confidence * 100).toFixed(0)}%`, status: 'calculated' }
  ]

  const realThreats = security.filter(s => s.type === 'security_threat')
  const realAnomalies = anomalies.filter(a => a.type === 'anomaly')
  const infoNotices = [...security.filter(s => s.type === 'info' || s.applicable === false), ...anomalies.filter(a => a.type === 'info')]

  return (
    <div style={{ padding: '0' }}>
      {/* Header */}
      <div style={{ background: 'var(--bg-card)', border: '1px solid var(--border-medium)', borderRadius: 10, padding: '10px 14px', marginBottom: 10 }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 12, flexWrap: 'wrap' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10, flexWrap: 'wrap' }}>
            <div style={{ fontSize: 14, fontWeight: 700, color: 'var(--text-primary)' }}>
              Dynamic Analysis Report
            </div>
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
              <Badge text={format.name} color='#9333ea' bg='rgba(147,51,234,0.12)' />
              <Badge text={format.category} color='#60a5fa' bg='rgba(96,165,250,0.12)' />
              <Badge text={`${(format.confidence*100).toFixed(0)}% format confidence`} color='#34d399' bg='rgba(52,211,153,0.12)' />
            </div>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10, fontSize: 12, color: 'var(--text-muted)' }}>
            <span>{parsing.parsed_lines.toLocaleString()} / {parsing.total_non_empty_lines.toLocaleString()} parsed</span>
            <span style={{ color: parsing.parse_success_rate > 90 ? '#34d399' : parsing.parse_success_rate > 60 ? '#f59e0b' : '#ef4444', fontWeight: 700 }}>
              {parsing.parse_success_rate}% parse rate
            </span>
          </div>
        </div>

        {analysis.summary.applicable_analyses.length > 0 && (
          <div style={{ marginTop: 6, fontSize: 11, color: 'var(--text-muted)', display: 'flex', alignItems: 'center', flexWrap: 'wrap', gap: 4 }}>
            <span>Active analyses:</span>
            {analysis.summary.applicable_analyses.map((a, i) => (
              <Badge key={i} text={a} color='#60a5fa' bg='rgba(96,165,250,0.08)' />
            ))}
          </div>
        )}
      </div>

      {/* KPI Grid - Exactly 4 items, locked into 1 row! */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 8, marginBottom: 12 }}>
        {kpiMetrics.map((m, i) => (
          <MetricCard key={i} label={m.name} value={m.value ?? 'N/A'} unavailable={m.status === 'not_available'} />
        ))}
      </div>

      {/* Timeline */}
      {timeline.first && (
        <SectionBlock title="Timeline" icon={Clock} color="#60a5fa" defaultOpen={true}>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: 10 }}>
            <MetricCard label="First Event" value={timeline.first.toLocaleString()} icon={Clock} color="#60a5fa" />
            <MetricCard label="Last Event" value={timeline.last.toLocaleString()} icon={Clock} color="#60a5fa" />
            {generic_stats.find(m => m.name === 'Log Duration') && (
              <MetricCard label="Duration" value={generic_stats.find(m => m.name === 'Log Duration').value} icon={Clock} color="#60a5fa" />
            )}
            {generic_stats.find(m => m.name === 'Events per Second') && (
              <MetricCard label="Events / sec" value={generic_stats.find(m => m.name === 'Events per Second').value} icon={Activity} color="#a78bfa" />
            )}
          </div>
        </SectionBlock>
      )}

      {/* HTTP Metrics */}
      {http.available && (
        <SectionBlock title="HTTP / Web Access Analysis" icon={Globe} color="#60a5fa">
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(160px, 1fr))', gap: 10, marginBottom: 16 }}>
            {http.metrics.filter(m => typeof m.value !== 'object' && m.status !== 'not_available').map((m, i) => (
              <MetricCard key={i} label={m.name} value={m.value} icon={Globe} color="#60a5fa" />
            ))}
          </div>
          {http.metrics.filter(m => typeof m.value === 'object' && m.value !== null && Array.isArray(m.value)).map((m, i) => (
            <div key={i} style={{ marginBottom: 16 }}>
              <div style={{ fontSize: 13, fontWeight: 600, color: 'var(--text-secondary)', marginBottom: 8 }}>{m.name}</div>
              <TableMetric items={m.value} columns={m.columns || ['Value', 'Count']} />
            </div>
          ))}
        </SectionBlock>
      )}

      {/* Application Metrics */}
      {application.available && (
        <SectionBlock title="Application Log Analysis" icon={Activity} color="#9333ea">
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(160px, 1fr))', gap: 10, marginBottom: 16 }}>
            {application.metrics.filter(m => typeof m.value !== 'object' && m.status !== 'not_available').map((m, i) => (
              <MetricCard key={i} label={m.name} value={m.value}
                icon={Activity} color={m.name.includes('Error') ? '#ef4444' : m.name.includes('Warning') ? '#f59e0b' : '#9333ea'} />
            ))}
          </div>
          {application.metrics.filter(m => typeof m.value === 'object' && m.value !== null && Array.isArray(m.value)).map((m, i) => (
            <div key={i} style={{ marginBottom: 16 }}>
              <div style={{ fontSize: 13, fontWeight: 600, color: 'var(--text-secondary)', marginBottom: 8 }}>{m.name}</div>
              <TableMetric items={m.value} columns={m.columns || ['Value', 'Count']} />
            </div>
          ))}
        </SectionBlock>
      )}

      {/* Auth Metrics */}
      {authentication.available && (
        <SectionBlock title="Authentication Analysis" icon={Lock} color="#f59e0b">
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(160px, 1fr))', gap: 10, marginBottom: 16 }}>
            {authentication.metrics.filter(m => typeof m.value !== 'object' && m.status !== 'not_available').map((m, i) => (
              <MetricCard key={i} label={m.name} value={m.value} icon={Lock}
                color={m.name.includes('Fail') ? '#ef4444' : '#f59e0b'} />
            ))}
          </div>
          {authentication.metrics.filter(m => typeof m.value === 'object' && m.value !== null && Array.isArray(m.value)).map((m, i) => (
            <div key={i} style={{ marginBottom: 16 }}>
              <div style={{ fontSize: 13, fontWeight: 600, color: 'var(--text-secondary)', marginBottom: 8 }}>{m.name}</div>
              <TableMetric items={m.value} columns={m.columns || ['Value', 'Count']} />
            </div>
          ))}
        </SectionBlock>
      )}

      {/* Database Metrics */}
      {database.available && (
        <SectionBlock title="Database Log Analysis" icon={Database} color="#34d399">
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(160px, 1fr))', gap: 10, marginBottom: 16 }}>
            {database.metrics.filter(m => typeof m.value !== 'object' && m.status !== 'not_available').map((m, i) => (
              <MetricCard key={i} label={m.name} value={m.value} icon={Database} color="#34d399" />
            ))}
          </div>
          {database.metrics.filter(m => typeof m.value === 'object' && m.value !== null && Array.isArray(m.value)).map((m, i) => (
            <div key={i} style={{ marginBottom: 16 }}>
              <div style={{ fontSize: 13, fontWeight: 600, color: 'var(--text-secondary)', marginBottom: 8 }}>{m.name}</div>
              <TableMetric items={m.value} columns={m.columns || ['Operation', 'Count']} />
            </div>
          ))}
        </SectionBlock>
      )}

      {/* Security Indicators */}
      {(realThreats.length > 0 || realAnomalies.length > 0) && (
        <SectionBlock title={`Security Indicators (${realThreats.length} threats, ${realAnomalies.length} anomalies)`} icon={Shield} color="#ef4444" defaultOpen={true}>
          {realThreats.map((ind, i) => <IndicatorCard key={i} indicator={ind} />)}
          {realAnomalies.map((a, i) => <AnomalyCard key={i} anomaly={a} />)}
          {realThreats.length === 0 && realAnomalies.length === 0 && (
            <div style={{ display: 'flex', alignItems: 'center', gap: 8, color: '#34d399', fontSize: 13, padding: '8px 0' }}>
              <CheckCircle2 size={15} />
              No threats or statistical anomalies detected in this log file.
            </div>
          )}
        </SectionBlock>
      )}

      {realThreats.length === 0 && realAnomalies.length === 0 && (
        <div style={{ display: 'flex', alignItems: 'center', gap: 10, background: 'rgba(52,211,153,0.08)', border: '1px solid rgba(52,211,153,0.25)', borderRadius: 10, padding: '12px 16px', marginBottom: 20 }}>
          <CheckCircle2 size={16} style={{ color: '#34d399' }} />
          <span style={{ fontSize: 13, color: '#34d399', fontWeight: 600 }}>No threats or statistical anomalies detected in this log file.</span>
        </div>
      )}

      {/* Info notices (non-applicable analyses) */}
      {infoNotices.length > 0 && (
        <SectionBlock title="Analysis Coverage Notes" icon={Info} color="#60a5fa" defaultOpen={false}>
          {infoNotices.map((n, i) => (
            <div key={i} style={{ display: 'flex', alignItems: 'flex-start', gap: 8, fontSize: 13, color: 'var(--text-muted)', marginBottom: 8, padding: '8px 10px', background: 'rgba(96,165,250,0.06)', borderRadius: 8 }}>
              <Info size={13} style={{ color: '#60a5fa', marginTop: 2, flexShrink: 0 }} />
              <div>
                <strong style={{ color: 'var(--text-secondary)' }}>{n.title}:</strong> {n.description}
              </div>
            </div>
          ))}
        </SectionBlock>
      )}

      {/* Top messages */}
      {top_messages && top_messages.length > 0 && (
        <SectionBlock title="Frequent Log Messages" icon={Eye} color="#a78bfa" defaultOpen={false}>
          <TableMetric items={top_messages} columns={['Message Pattern', 'Count']} maxRows={10} />
        </SectionBlock>
      )}

      {/* Detected fields */}
      <SectionBlock title={`Detected Fields (${parseResult.detected_fields.length})`} icon={Cpu} color="#8b5cf6" defaultOpen={false}>
        <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
          {parseResult.detected_fields.map(f => (
            <code key={f} style={{ background: 'var(--bg-input)', padding: '3px 8px', borderRadius: 6, fontSize: 12, color: 'var(--accent-cyan)', border: '1px solid var(--border-subtle)' }}>{f}</code>
          ))}
        </div>
      </SectionBlock>
    </div>
  )
}

// ── AI chat response (deterministic, based on parsed data) ────────────────────
function buildAiResponse(aiCtx, question) {
  if (!aiCtx) {
    return [{ type: 'alert', variant: 'info', text: "No log data analyzed yet. Upload a log file first." }]
  }

  const q = (question || '').toLowerCase()
  const has = (kws) => kws.some(k => q.includes(k))
  const blocks = []

  // ── THREAT / SECURITY QUERY ──────────────────────────────────────────────
  if (has(['threat', 'attack', 'security', 'danger', 'malicious', 'hack', 'safe', 'sqli', 'xss', 'lfi', 'injection', 'recon', 'scanner', 'vulnerability'])) {
    blocks.push({ type: 'heading', text: 'Security Threat & Attack Analysis', icon: 'shield' })
    if (aiCtx.threat_count > 0) {
      blocks.push({
        type: 'alert',
        variant: 'danger',
        text: `${aiCtx.threat_count} security attack signature(s) detected from parsed log entries.`
      })

      // Threat breakdown table
      const threatRows = (aiCtx.threats || []).map(t => [
        `**${t.severity}**`,
        t.title,
        `${(t.event_count || 1).toLocaleString()} hits`,
        t.affected_ips && t.affected_ips.length > 0 ? t.affected_ips.slice(0, 2).join(', ') : 'Pattern match'
      ])
      blocks.push({
        type: 'table',
        title: 'Detected Security Attack Signatures',
        columns: ['Severity', 'Threat Vector', 'Occurrences', 'Source / Context'],
        rows: threatRows
      })

      // Evidence samples
      const sampleThreats = (aiCtx.threats || []).filter(t => t.evidence).slice(0, 3)
      if (sampleThreats.length > 0) {
        sampleThreats.forEach(t => {
          blocks.push({
            type: 'code',
            title: `Evidence: ${t.title}`,
            badge: t.severity,
            content: t.evidence
          })
        })
      }

      // Attack IPs if any
      const allAttackIps = [...new Set((aiCtx.threats || []).flatMap(t => t.affected_ips || []))]
      if (allAttackIps.length > 0) {
        blocks.push({ type: 'text', text: '**Targeted / Attacking IP Addresses:**' })
        blocks.push({ type: 'tags', items: allAttackIps })
      }

      // Actionable advice
      blocks.push({
        type: 'bullets',
        items: [
          '**Block Attacking IPs**: Immediately firewall or rate-limit identified scanning IPs.',
          '**Input Validation**: Ensure parameter binding / prepared statements for database queries.',
          '**WAF Inspection**: Enforce web application firewall rules to drop injection payloads.'
        ]
      })

      blocks.push({
        type: 'suggestions',
        items: [
          'What errors occurred?',
          'Who are the top client IPs?',
          'What endpoints were requested?',
          'Give mitigation recommendations'
        ]
      })
    } else {
      blocks.push({
        type: 'alert',
        variant: 'success',
        text: 'No malicious security threats or known attack patterns (SQLi, XSS, Path Traversal, Scanners) were found in the parsed events.'
      })
      blocks.push({
        type: 'suggestions',
        items: [
          'What errors occurred?',
          'Who are the top client IPs?',
          'Show log format details',
          'Give log summary'
        ]
      })
    }

  // ── ERROR / WARNING / EXCEPTION QUERY ─────────────────────────────────────
  } else if (has(['error', 'warn', 'warning', 'fail', 'failure', 'exception', 'crash', '500', '404', 'issue', 'bug', 'broken', 'problem', 'health'])) {
    blocks.push({ type: 'heading', text: 'Error & System Health Analysis', icon: 'alert' })

    const totalErr = aiCtx.total_errors || 0
    const totalWarn = aiCtx.total_warnings || 0
    const errColor = totalErr > 0 ? '#ef4444' : '#34d399'

    blocks.push({
      type: 'metric_cards',
      cards: [
        { label: 'Total Errors', value: totalErr.toLocaleString(), color: errColor, border: totalErr > 0 ? 'rgba(239,68,68,0.3)' : 'rgba(52,211,153,0.3)' },
        { label: 'Total Warnings', value: totalWarn.toLocaleString(), color: totalWarn > 0 ? '#f59e0b' : 'var(--text-primary)' },
        ...(aiCtx.http ? [
          { label: '4xx Client Errors', value: (aiCtx.http.status_4xx || 0).toLocaleString(), color: '#f59e0b' },
          { label: '5xx Server Errors', value: (aiCtx.http.status_5xx || 0).toLocaleString(), color: '#ef4444' }
        ] : [])
      ]
    })

    if (totalErr > 0 || totalWarn > 0) {
      blocks.push({
        type: 'alert',
        variant: totalErr > 0 ? 'danger' : 'warning',
        text: `Identified ${totalErr} error(s) and ${totalWarn} warning(s) in this log file.`
      })
    } else {
      blocks.push({
        type: 'alert',
        variant: 'success',
        text: 'Clean execution — zero errors or warnings detected in the analyzed log events.'
      })
    }

    // Log level distribution table if available
    const levels = Object.entries(aiCtx.level_distribution || {})
    if (levels.length > 0) {
      const levelRows = levels.map(([lvl, count]) => [
        lvl,
        count.toLocaleString(),
        aiCtx.total_events > 0 ? `${((count / aiCtx.total_events) * 100).toFixed(1)}%` : 'N/A'
      ])
      blocks.push({
        type: 'table',
        title: 'Log Level Distribution',
        columns: ['Severity Level', 'Count', 'Share %'],
        rows: levelRows
      })
    }

    // Error samples if available
    if (aiCtx.error_samples && aiCtx.error_samples.length > 0) {
      blocks.push({ type: 'text', text: '**Sample error messages extracted from log events:**' })
      aiCtx.error_samples.forEach(s => {
        blocks.push({
          type: 'code',
          title: `${s.severity}${s.timestamp ? ` • ${new Date(s.timestamp).toLocaleTimeString()}` : ''}`,
          badge: s.severity,
          content: s.message
        })
      })
    }

    blocks.push({
      type: 'suggestions',
      items: [
        'Show security threats',
        'Who are the top client IPs?',
        'What endpoints had errors?',
        'Give mitigation recommendations'
      ]
    })

  // ── IP ADDRESS / CLIENT ACTIVITY QUERY ─────────────────────────────────────
  } else if (has(['ip', 'client', 'visitor', 'user', 'attacker', 'source', 'who', 'traffic from'])) {
    blocks.push({ type: 'heading', text: 'Client IP Activity & Traffic Analysis', icon: 'globe' })

    if (aiCtx.http && aiCtx.http.top_ips && aiCtx.http.top_ips.length > 0) {
      const topIps = aiCtx.http.top_ips
      const totalReq = aiCtx.http.total_requests || 1

      blocks.push({
        type: 'metric_cards',
        cards: [
          { label: 'Unique Client IPs', value: (aiCtx.http.unique_ips || topIps.length).toLocaleString(), color: '#60a5fa' },
          { label: 'Total HTTP Hits', value: totalReq.toLocaleString(), color: 'var(--text-primary)' },
          { label: 'Top IP Volume Share', value: `${((topIps[0].count / totalReq) * 100).toFixed(1)}%`, color: '#c084fc', sub: topIps[0].key }
        ]
      })

      const ipRows = topIps.slice(0, 10).map((item, idx) => [
        `#${idx + 1}`,
        `\`${item.key}\``,
        item.count.toLocaleString(),
        `${((item.count / totalReq) * 100).toFixed(1)}%`
      ])

      blocks.push({
        type: 'table',
        title: 'Top Client IP Addresses by Traffic Volume',
        columns: ['Rank', 'Client IP', 'Requests', 'Share %'],
        rows: ipRows,
        monoCols: [1]
      })

      // Flag threats if any match IPs
      const attackIps = [...new Set((aiCtx.threats || []).flatMap(t => t.affected_ips || []))]
      if (attackIps.length > 0) {
        blocks.push({
          type: 'alert',
          variant: 'danger',
          text: `**Identified Attacker IPs:** ${attackIps.join(', ')} were observed initiating malicious request payloads.`
        })
      }

      blocks.push({
        type: 'suggestions',
        items: [
          'What endpoints were requested?',
          'What status codes were returned?',
          'Show security threats',
          'What errors occurred?'
        ]
      })
    } else if (aiCtx.auth && aiCtx.auth.top_ips && aiCtx.auth.top_ips.length > 0) {
      blocks.push({
        type: 'table',
        title: 'Authentication Source IPs',
        columns: ['Rank', 'Source IP', 'Auth Attempts'],
        rows: aiCtx.auth.top_ips.slice(0, 10).map((it, idx) => [`#${idx + 1}`, `\`${it.key}\``, it.count.toLocaleString()]),
        monoCols: [1]
      })
      blocks.push({
        type: 'suggestions',
        items: ['What errors occurred?', 'Show security threats', 'Give log summary']
      })
    } else {
      blocks.push({
        type: 'alert',
        variant: 'info',
        text: 'No client IP address fields were detected in this log file format.'
      })
      blocks.push({
        type: 'suggestions',
        items: ['What fields were detected?', 'What errors occurred?', 'Give log summary']
      })
    }

  // ── ENDPOINTS / URLS / PATHS QUERY ────────────────────────────────────────
  } else if (has(['endpoint', 'url', 'path', 'route', 'request', 'page', 'uri', 'get', 'post', 'method'])) {
    blocks.push({ type: 'heading', text: 'HTTP Request & Endpoint Analysis', icon: 'link' })

    if (aiCtx.http && aiCtx.http.top_endpoints && aiCtx.http.top_endpoints.length > 0) {
      const topEp = aiCtx.http.top_endpoints
      const totalReq = aiCtx.http.total_requests || 1

      // HTTP Methods distribution if available
      if (aiCtx.http.methods && aiCtx.http.methods.length > 0) {
        const methodCards = aiCtx.http.methods.map(m => ({
          label: m.key,
          value: m.count.toLocaleString(),
          color: m.key === 'GET' ? '#34d399' : m.key === 'POST' ? '#60a5fa' : m.key === 'DELETE' ? '#ef4444' : '#f59e0b'
        }))
        blocks.push({ type: 'metric_cards', cards: methodCards })
      }

      const epRows = topEp.slice(0, 10).map((it, idx) => [
        `#${idx + 1}`,
        `\`${it.key}\``,
        it.count.toLocaleString(),
        `${((it.count / totalReq) * 100).toFixed(1)}%`
      ])

      blocks.push({
        type: 'table',
        title: 'Top Requested Endpoints / URLs',
        columns: ['Rank', 'Endpoint Path', 'Hits', 'Share %'],
        rows: epRows,
        monoCols: [1]
      })

      if (aiCtx.http.data_transfer) {
        blocks.push({
          type: 'alert',
          variant: 'info',
          text: `Total payload data transferred: **${aiCtx.http.data_transfer}**`
        })
      }

      blocks.push({
        type: 'suggestions',
        items: [
          'What status codes were returned?',
          'Who are the top client IPs?',
          'What errors occurred?',
          'Show security threats'
        ]
      })
    } else {
      blocks.push({
        type: 'alert',
        variant: 'info',
        text: 'No HTTP endpoint or URL paths were detected in this log file format.'
      })
      blocks.push({
        type: 'suggestions',
        items: ['What fields were detected?', 'What errors occurred?', 'Give log summary']
      })
    }

  // ── STATUS CODES QUERY ───────────────────────────────────────────────────
  } else if (has(['status', 'status code', 'code', 'response code', '200', '2xx', '3xx', '4xx', '5xx'])) {
    blocks.push({ type: 'heading', text: 'HTTP Status Code Distribution', icon: 'chart' })

    if (aiCtx.http) {
      blocks.push({
        type: 'metric_cards',
        cards: [
          { label: '2xx Success', value: (aiCtx.http.status_2xx || 0).toLocaleString(), color: '#34d399' },
          { label: '4xx Client Errors', value: (aiCtx.http.status_4xx || 0).toLocaleString(), color: '#f59e0b' },
          { label: '5xx Server Errors', value: (aiCtx.http.status_5xx || 0).toLocaleString(), color: '#ef4444' }
        ]
      })

      const totalReq = aiCtx.http.total_requests || 1
      const statusRows = [
        ['2xx (Successful Responses)', (aiCtx.http.status_2xx || 0).toLocaleString(), `${(((aiCtx.http.status_2xx || 0) / totalReq) * 100).toFixed(1)}%`, 'Normal'],
        ['4xx (Client Errors, e.g. 404, 403)', (aiCtx.http.status_4xx || 0).toLocaleString(), `${(((aiCtx.http.status_4xx || 0) / totalReq) * 100).toFixed(1)}%`, (aiCtx.http.status_4xx || 0) > 50 ? 'High' : 'Normal'],
        ['5xx (Server Internal Errors)', (aiCtx.http.status_5xx || 0).toLocaleString(), `${(((aiCtx.http.status_5xx || 0) / totalReq) * 100).toFixed(1)}%`, (aiCtx.http.status_5xx || 0) > 0 ? 'Action Needed' : 'Clean']
      ]

      blocks.push({
        type: 'table',
        title: 'Response Categories',
        columns: ['Class', 'Count', 'Share %', 'Health'],
        rows: statusRows
      })

      blocks.push({
        type: 'suggestions',
        items: [
          'What endpoints had errors?',
          'Who are the top client IPs?',
          'What errors occurred?',
          'Show security threats'
        ]
      })
    } else {
      blocks.push({
        type: 'alert',
        variant: 'info',
        text: 'No HTTP status codes detected in this log file format.'
      })
      blocks.push({
        type: 'suggestions',
        items: ['What fields were detected?', 'What errors occurred?', 'Give log summary']
      })
    }

  // ── AUTHENTICATION & USERS QUERY ──────────────────────────────────────────
  } else if (has(['auth', 'login', 'logout', 'password', 'session', 'credential', 'user'])) {
    blocks.push({ type: 'heading', text: 'Authentication & Session Activity', icon: 'lock' })

    if (aiCtx.auth) {
      blocks.push({
        type: 'metric_cards',
        cards: [
          { label: 'Total Auth Events', value: aiCtx.auth.total.toLocaleString(), color: '#60a5fa' },
          { label: 'Successful Logins', value: aiCtx.auth.success.toLocaleString(), color: '#34d399' },
          { label: 'Failed Logins', value: aiCtx.auth.failed.toLocaleString(), color: aiCtx.auth.failed > 0 ? '#ef4444' : '#34d399' },
          { label: 'Failure Rate', value: aiCtx.auth.failure_rate, color: parseFloat(aiCtx.auth.failure_rate) > 20 ? '#ef4444' : 'var(--text-primary)' }
        ]
      })

      if (aiCtx.auth.top_users && aiCtx.auth.top_users.length > 0) {
        blocks.push({
          type: 'table',
          title: 'Top Targeted User Accounts',
          columns: ['Rank', 'Username', 'Attempts'],
          rows: aiCtx.auth.top_users.slice(0, 8).map((u, i) => [`#${i + 1}`, `\`${u.key}\``, u.count.toLocaleString()]),
          monoCols: [1]
        })
      }

      blocks.push({
        type: 'suggestions',
        items: ['Show security threats', 'Who are the top client IPs?', 'Give mitigation recommendations']
      })
    } else {
      blocks.push({
        type: 'alert',
        variant: 'info',
        text: 'No authentication or login attempt events detected in this log file.'
      })
      blocks.push({
        type: 'suggestions',
        items: ['What errors occurred?', 'Who are the top client IPs?', 'Give log summary']
      })
    }

  // ── DATABASE QUERY ────────────────────────────────────────────────────────
  } else if (has(['database', 'db', 'query', 'sql', 'mysql', 'postgres', 'slow query'])) {
    blocks.push({ type: 'heading', text: 'Database Operations & Queries', icon: 'database' })

    if (aiCtx.database) {
      blocks.push({
        type: 'metric_cards',
        cards: [
          { label: 'Total DB Events', value: aiCtx.database.total_events.toLocaleString(), color: '#60a5fa' },
          { label: 'DB Errors', value: aiCtx.database.errors.toLocaleString(), color: aiCtx.database.errors > 0 ? '#ef4444' : '#34d399' },
          ...(aiCtx.database.avg_query_time ? [{ label: 'Avg Query Duration', value: aiCtx.database.avg_query_time, color: '#f59e0b' }] : [])
        ]
      })

      if (aiCtx.database.operations && aiCtx.database.operations.length > 0) {
        blocks.push({
          type: 'table',
          title: 'Database Operation Types',
          columns: ['Operation', 'Count'],
          rows: aiCtx.database.operations.map(op => [op.key, op.count.toLocaleString()])
        })
      }

      blocks.push({
        type: 'suggestions',
        items: ['What errors occurred?', 'Show security threats', 'Give log summary']
      })
    } else {
      blocks.push({
        type: 'alert',
        variant: 'info',
        text: 'No database queries or operations detected in this log file.'
      })
      blocks.push({
        type: 'suggestions',
        items: ['What errors occurred?', 'Show security threats', 'Give log summary']
      })
    }

  // ── ANOMALY QUERY ─────────────────────────────────────────────────────────
  } else if (has(['anomaly', 'unusual', 'spike', 'weird', 'strange', 'abnormal', 'deviation'])) {
    blocks.push({ type: 'heading', text: 'Statistical Anomaly Report', icon: 'trend' })

    if (aiCtx.anomaly_count > 0) {
      blocks.push({
        type: 'alert',
        variant: 'warning',
        text: `${aiCtx.anomaly_count} statistical anomaly/anomalies detected via volume and rate analysis.`
      })

      const anomRows = (aiCtx.anomalies || []).map(a => [
        a.title,
        a.confidence !== null ? `${(a.confidence * 100).toFixed(0)}%` : 'Rule-based',
        a.description
      ])
      blocks.push({
        type: 'table',
        title: 'Detected Anomalies',
        columns: ['Anomaly Indicator', 'Confidence', 'Description'],
        rows: anomRows
      })

      // Sample evidence
      const sampleAnom = (aiCtx.anomalies || []).filter(a => a.evidence).slice(0, 2)
      sampleAnom.forEach(a => {
        blocks.push({
          type: 'code',
          title: `Evidence: ${a.title}`,
          badge: a.severity || 'ANOMALY',
          content: a.evidence
        })
      })

      blocks.push({
        type: 'alert',
        variant: 'info',
        text: 'Statistical anomalies indicate deviation from baseline behavior and should be investigated for root cause.'
      })

      blocks.push({
        type: 'suggestions',
        items: ['Show security threats', 'What errors occurred?', 'Give mitigation recommendations']
      })
    } else {
      blocks.push({
        type: 'alert',
        variant: 'success',
        text: 'No statistical anomalies detected. Request rates, error frequency, and volume follow normal baselines.'
      })
      blocks.push({
        type: 'suggestions',
        items: ['Show security threats', 'What errors occurred?', 'Give log summary']
      })
    }

  // ── TIMELINE QUERY ────────────────────────────────────────────────────────
  } else if (has(['time', 'duration', 'period', 'when', 'start', 'end', 'range', 'date', 'hours', 'window'])) {
    blocks.push({ type: 'heading', text: 'Log Timeline & Activity Window', icon: 'clock' })

    if (aiCtx.timeline.first) {
      const d = aiCtx.timeline.duration_seconds
      const dur = !d ? 'Instantaneous' : d < 60 ? `${d}s` : d < 3600 ? `${Math.floor(d/60)}m ${d%60}s` : d < 86400 ? `${Math.floor(d/3600)}h ${Math.floor((d%3600)/60)}m` : `${Math.floor(d/86400)}d ${Math.floor((d%86400)/3600)}h`
      const eps = d && d > 0 ? (aiCtx.parsed_events / d).toFixed(2) : 'N/A'

      blocks.push({
        type: 'metric_cards',
        cards: [
          { label: 'Total Duration', value: dur, color: '#60a5fa' },
          { label: 'Events / Sec', value: eps, color: '#34d399' },
          { label: 'Events Parsed', value: aiCtx.parsed_events.toLocaleString(), color: 'var(--text-primary)' }
        ]
      })

      blocks.push({
        type: 'kv',
        rows: [
          { key: 'First Event', value: new Date(aiCtx.timeline.first).toLocaleString() },
          { key: 'Last Event', value: new Date(aiCtx.timeline.last).toLocaleString() },
          { key: 'Total Duration', value: dur },
          { key: 'Throughput', value: `${eps} events/sec` }
        ]
      })

      blocks.push({
        type: 'suggestions',
        items: ['What errors occurred?', 'Show security threats', 'Who are the top client IPs?']
      })
    } else {
      blocks.push({
        type: 'alert',
        variant: 'info',
        text: 'No timestamps detected in this log file. Timeline analysis is not applicable.'
      })
      blocks.push({
        type: 'suggestions',
        items: ['What fields were detected?', 'What errors occurred?', 'Give log summary']
      })
    }

  // ── RECOMMENDATIONS / MITIGATION QUERY ────────────────────────────────────
  } else if (has(['recommend', 'suggestion', 'fix', 'mitigate', 'action', 'next step', 'advice', 'remediation', 'how to', 'what should i do'])) {
    blocks.push({ type: 'heading', text: 'Actionable Remediation & Mitigation Checklist', icon: 'lightbulb' })

    const recs = []
    if (aiCtx.threat_count > 0) {
      recs.push('**Perimeter IP Blocking**: Block the identified attacking IPs in your edge firewall (iptables / cloud WAF).')
      if ((aiCtx.threats || []).some(t => t.title.toLowerCase().includes('sql'))) {
        recs.push('**Fix SQL Injection Vulnerabilities**: Review database queries touching user input and ensure parameterized statements / ORM usage.')
      }
      if ((aiCtx.threats || []).some(t => t.title.toLowerCase().includes('xss'))) {
        recs.push('**Implement CSP & Sanitization**: Add strict `Content-Security-Policy` headers and sanitize HTML output.')
      }
      if ((aiCtx.threats || []).some(t => t.title.toLowerCase().includes('scanner'))) {
        recs.push('**Automated Bot Protection**: Configure rate limits and user-agent challenges to filter out automated vulnerability scanners.')
      }
    }

    if (aiCtx.total_errors > 0) {
      recs.push(`**Application Debugging**: Review the ${aiCtx.total_errors} recorded errors and address root-cause exceptions.`)
    }

    if (aiCtx.http && aiCtx.http.status_4xx > 20) {
      recs.push('**Directory Traversal / Scan Hardening**: Elevated 404 count detected; consider fail2ban or endpoint rate-limiting.')
    }

    if (aiCtx.auth && parseFloat(aiCtx.auth.failure_rate) > 20) {
      recs.push('**Credential Protection**: Auth failure rate exceeds 20%; enforce multi-factor authentication (MFA) and account lockout limits.')
    }

    recs.push('**Monitoring & Alerting**: Set up active threshold-based alerts for CRITICAL severity events in your SIEM/dashboard.')

    blocks.push({ type: 'bullets', items: recs })

    blocks.push({
      type: 'suggestions',
      items: ['Show security threats', 'What errors occurred?', 'Who are the top client IPs?']
    })

  // ── FORMAT & SCHEMA QUERY ────────────────────────────────────────────────
  } else if (has(['format', 'type', 'kind', 'what', 'structure', 'schema', 'field', 'column', 'fields'])) {
    blocks.push({ type: 'heading', text: 'Detected Log Format & Schema', icon: 'search' })

    blocks.push({
      type: 'metric_cards',
      cards: [
        { label: 'Format', value: aiCtx.format, color: '#c084fc' },
        { label: 'Confidence', value: `${(aiCtx.confidence * 100).toFixed(0)}%`, color: '#34d399' },
        { label: 'Parse Rate', value: `${aiCtx.parse_success_rate}%`, color: aiCtx.parse_success_rate > 90 ? '#34d399' : '#f59e0b' },
        { label: 'Fields Detected', value: `${aiCtx.detected_fields.length}`, color: '#60a5fa' }
      ]
    })

    blocks.push({
      type: 'kv',
      rows: [
        { key: 'Format Name', value: aiCtx.format },
        { key: 'Category', value: aiCtx.category || 'General' },
        { key: 'Total Raw Lines', value: aiCtx.total_events.toLocaleString() },
        { key: 'Parsed Events', value: aiCtx.parsed_events.toLocaleString() },
        { key: 'Parse Success Rate', value: `${aiCtx.parse_success_rate}%`, highlight: aiCtx.parse_success_rate > 90 ? 'success' : 'warning' }
      ]
    })

    blocks.push({ type: 'text', text: '**Extracted Field Names:**' })
    blocks.push({ type: 'tags', items: aiCtx.detected_fields })

    blocks.push({
      type: 'suggestions',
      items: ['What errors occurred?', 'Show security threats', 'Who are the top client IPs?']
    })

  // ── PARSE COVERAGE QUERY ──────────────────────────────────────────────────
  } else if (has(['parse', 'coverage', 'miss', 'skip', 'unparsed', 'success rate'])) {
    blocks.push({ type: 'heading', text: 'Parse Coverage & Ingestion Stats', icon: 'chart' })

    blocks.push({
      type: 'kv',
      rows: [
        { key: 'Total Lines', value: aiCtx.total_events.toLocaleString() },
        { key: 'Successfully Parsed', value: `${aiCtx.parsed_events.toLocaleString()} (${aiCtx.parse_success_rate}%)`, highlight: aiCtx.parse_success_rate > 90 ? 'success' : 'warning' },
        { key: 'Unparsed / Skipped', value: `${(aiCtx.total_events - aiCtx.parsed_events).toLocaleString()}` },
        { key: 'Detected Format', value: aiCtx.format }
      ]
    })

    blocks.push({
      type: 'suggestions',
      items: ['What fields were detected?', 'What errors occurred?', 'Show security threats']
    })

  // ── GENERAL SUMMARY (default) ────────────────────────────────────────────
  } else {
    blocks.push({ type: 'heading', text: 'Log Analysis Executive Summary', icon: 'bot' })

    const d = aiCtx.timeline.duration_seconds
    const dur = !d ? null : d < 60 ? `${d}s` : d < 3600 ? `${Math.floor(d/60)}m ${d%60}s` : d < 86400 ? `${Math.floor(d/3600)}h ${Math.floor((d%3600)/60)}m` : `${Math.floor(d/86400)}d ${Math.floor((d%86400)/3600)}h`

    blocks.push({
      type: 'metric_cards',
      cards: [
        { label: 'Total Events', value: aiCtx.total_events.toLocaleString(), color: '#60a5fa' },
        { label: 'Parse Rate', value: `${aiCtx.parse_success_rate}%`, color: aiCtx.parse_success_rate > 90 ? '#34d399' : '#f59e0b' },
        { label: 'Threats', value: `${aiCtx.threat_count}`, color: aiCtx.threat_count > 0 ? '#ef4444' : '#34d399' },
        { label: 'Anomalies', value: `${aiCtx.anomaly_count}`, color: aiCtx.anomaly_count > 0 ? '#f59e0b' : '#34d399' },
        { label: 'Errors', value: `${aiCtx.total_errors || 0}`, color: (aiCtx.total_errors || 0) > 0 ? '#ef4444' : '#34d399' }
      ]
    })

    if (aiCtx.threat_count > 0) {
      blocks.push({
        type: 'alert',
        variant: 'danger',
        text: `**Action Required**: ${aiCtx.threat_count} security attack signature(s) detected in the log entries.`
      })
    } else if ((aiCtx.total_errors || 0) > 0) {
      blocks.push({
        type: 'alert',
        variant: 'warning',
        text: `**Attention**: ${aiCtx.total_errors} application error events detected during analysis.`
      })
    } else {
      blocks.push({
        type: 'alert',
        variant: 'success',
        text: '**Log Ingestion Clean**: System operating within normal security parameters; no attack signatures detected.'
      })
    }

    blocks.push({
      type: 'kv',
      rows: [
        { key: 'Format', value: aiCtx.format },
        { key: 'Events Parsed', value: `${aiCtx.parsed_events.toLocaleString()} / ${aiCtx.total_events.toLocaleString()} (${aiCtx.parse_success_rate}%)` },
        ...(aiCtx.timeline.first ? [
          { key: 'Period', value: `${new Date(aiCtx.timeline.first).toLocaleString()} → ${new Date(aiCtx.timeline.last).toLocaleString()}` },
          ...(dur ? [{ key: 'Duration', value: dur }] : [])
        ] : [{ key: 'Timestamps', value: 'Not detected' }]),
        { key: 'Security Threats', value: `${aiCtx.threat_count}`, highlight: aiCtx.threat_count > 0 ? 'danger' : 'success' },
        { key: 'Anomalies', value: `${aiCtx.anomaly_count}`, highlight: aiCtx.anomaly_count > 0 ? 'warning' : 'success' },
        { key: 'Fields Detected', value: `${aiCtx.detected_fields.length}` }
      ]
    })

    if (aiCtx.detected_fields.length > 0) {
      blocks.push({ type: 'tags', items: aiCtx.detected_fields.slice(0, 10), overflow: Math.max(0, aiCtx.detected_fields.length - 10) })
    }

    blocks.push({
      type: 'suggestions',
      items: [
        'What errors occurred?',
        'Show security threats',
        'Who are the top client IPs?',
        'What endpoints were requested?',
        'Give mitigation recommendations'
      ]
    })
  }

  return blocks
}

// ── MAIN COMPONENT ─────────────────────────────────────────────────────────────
export default function SandboxView() {
  const [mode, setMode] = useState('chatbot')
  const [form, setForm] = useState({
    ip: DETECTION_TEST_CASES.sqli.ip,
    key: DETECTION_TEST_CASES.sqli.key,
    val: DETECTION_TEST_CASES.sqli.val,
    ua: DETECTION_TEST_CASES.sqli.ua
  })
  const [result, setResult] = useState(null)
  const [isSimulating, setIsSimulating] = useState(false)
  const [simStep, setSimStep] = useState('')
  const [validationErrors, setValidationErrors] = useState([])
  const [presetNotice, setPresetNotice] = useState('')
  const [showEvidence, setShowEvidence] = useState(true)
  const [activePresetKey, setActivePresetKey] = useState('sqli')

  // Chatbot state
  const fileInputRef = useRef(null)
  const chatEndRef = useRef(null)
  const [chatLog, setChatLog] = useState([{
    role: 'ai',
    blocks: [
      { type: 'heading', text: 'Generic Log Analysis AI', icon: 'bot' },
      { type: 'text', text: 'Upload **any log file** to execute automated forensic ingestion, schema inference, and threat detection on its live contents.' },
      { type: 'bullets', items: [
        '**Format Auto-Detection**: Supports Apache, Nginx, Java, Python, JSON arrays, Syslog, CSV, and custom streams.',
        '**Schema & Field Extraction**: Normalizes attributes, IP endpoints, HTTP verbs, status codes, and user-agents.',
        '**Evidence-Based Metrics**: Computes throughput rates, error frequencies, and unique origin profiling.',
        '**Threat & Anomaly Profiling**: Flags OWASP signatures (SQLi, XSS, RCE), Shannon entropy spikes, and scanning bots.',
        '**Deterministic Analysis**: 100% dynamic calculations derived strictly from parsed log entries with zero simulated data.'
      ]},
      { type: 'alert', variant: 'info', text: 'Supported formats: `.log` · `.txt` · `.json` · `.csv` · `.tsv` or any plain-text log file.' },
    ]
  }])
  const [chatInput, setChatInput] = useState('')
  const [isAnalyzing, setIsAnalyzing] = useState(false)
  const [pendingFile, setPendingFile] = useState(null)
  const [lastAnalysis, setLastAnalysis] = useState(null) // { parseResult, analysis, aiCtx }

  useEffect(() => {
    chatEndRef.current?.scrollIntoView({ behavior: 'smooth' })
  }, [chatLog, isAnalyzing])

  const runAnalysis = useCallback((file, extraText) => {
    const reader = new FileReader()
    reader.onload = (event) => {
      const content = event.target.result

      // Run the full pipeline
      const parseResult = parseLogFile(content, file.name)
      const analysis = analyzeLog(parseResult)

      setLastAnalysis({ parseResult, analysis, aiCtx: analysis.ai_context })

      setChatLog(prev => [...prev, {
        role: 'ai',
        type: 'report',
        filename: file.name,
        parseResult,
        analysis
      }])

      // If there was a question alongside the file, answer it
      if (extraText && extraText.trim()) {
        const blocks = buildAiResponse(analysis.ai_context, extraText)
        setChatLog(prev => [...prev, { role: 'ai', blocks }])
      }

      setPendingFile(null)
      setIsAnalyzing(false)
    }
    reader.onerror = () => {
      setChatLog(prev => [...prev, { role: 'ai', blocks: [{ type: 'alert', variant: 'danger', text: 'Could not read the file. Please ensure it is a valid text-based log file.' }] }])
      setPendingFile(null)
      setIsAnalyzing(false)
    }
    reader.readAsText(file, 'utf-8')
  }, [])

  const handleSendMessage = useCallback((e) => {
    e.preventDefault()
    if ((!chatInput.trim() && !pendingFile) || isAnalyzing) return
    const text = chatInput.trim()
    setChatInput('')

    // Build user message display text
    let userMsgText = text
    if (pendingFile) userMsgText = `**Attached Log File:** \`${pendingFile.name}\`${text ? `\n\n${text}` : ''}`
    setChatLog(prev => [...prev, { role: 'user', text: userMsgText }])
    setIsAnalyzing(true)

    if (pendingFile) {
      runAnalysis(pendingFile, text)
    } else {
      // Text-only question — answer from last analysis context
      setTimeout(() => {
        if (lastAnalysis) {
          const blocks = buildAiResponse(lastAnalysis.aiCtx, text)
          setChatLog(prev => [...prev, { role: 'ai', blocks }])
        } else {
          setChatLog(prev => [...prev, {
            role: 'ai',
            blocks: [{ type: 'alert', variant: 'info', text: 'Please upload a log file first — I will not guess or invent values without real data to analyze.' }]
          }])
        }
        setIsAnalyzing(false)
      }, 400)
    }
  }, [chatInput, pendingFile, isAnalyzing, lastAnalysis, runAnalysis])

  const handleFileUpload = (e) => {
    const f = e.target.files[0]
    if (!f) return
    // Accept any text-based file
    setPendingFile(f)
    e.target.value = ''
  }

  const update = (field, value) => {
    setForm(f => ({ ...f, [field]: value }))
    setActivePresetKey(null) // Clear preset selection so UI reflects custom user input
    setValidationErrors([])
    setPresetNotice('')
  }

  const handleLoadPreset = (key) => {
    const testCase = DETECTION_TEST_CASES[key]
    if (!testCase) return
    setActivePresetKey(key)
    const newForm = {
      ip: testCase.ip,
      key: testCase.key,
      val: testCase.val,
      ua: testCase.ua
    }
    setForm(newForm)
    setValidationErrors([])
    setPresetNotice(`Loaded test case "${testCase.title}". Evaluating request parameters...`)
    // Run simulation immediately on loaded test case for instant dynamic analysis
    setTimeout(() => {
      const res = simulateThreatAnalysis(newForm)
      if (!res.validation_error) {
        setResult(res)
        setPresetNotice(`Loaded test case "${testCase.title}". Verdict dynamically derived from parameters.`)
      }
    }, 50)
  }

  const runSimulation = useCallback(() => {
    setPresetNotice('')
    setValidationErrors([])
    setIsSimulating(true)
    setSimStep('Normalizing request input & checking character encoding...')

    setTimeout(() => {
      setSimStep('Extracting entropy, delimiters & network metadata...')
      setTimeout(() => {
        setSimStep('Evaluating signature rules & behavioral indicators...')
        setTimeout(() => {
          setSimStep('Calculating risk score & evidence classification...')
          setTimeout(() => {
            const res = simulateThreatAnalysis(form)
            if (res.validation_error) {
              setValidationErrors(res.errors || [])
              setResult(null)
            } else {
              setValidationErrors([])
              setResult(res)
            }
            setIsSimulating(false)
            setSimStep('')
          }, 120)
        }, 120)
      }, 120)
    }, 120)
  }, [form])

  const askQuestion = useCallback((text) => {
    if (!text || isAnalyzing) return
    setChatLog(prev => [...prev, { role: 'user', text }])
    setIsAnalyzing(true)
    setTimeout(() => {
      if (lastAnalysis) {
        const blocks = buildAiResponse(lastAnalysis.aiCtx, text)
        setChatLog(prev => [...prev, { role: 'ai', blocks }])
      } else {
        setChatLog(prev => [...prev, {
          role: 'ai',
          blocks: [{ type: 'alert', variant: 'info', text: 'Please upload a log file first — I will not guess or invent values without real data to analyze.' }]
        }])
      }
      setIsAnalyzing(false)
    }, 350)
  }, [isAnalyzing, lastAnalysis])

  // ── Rich message block renderer ──────────────────────────────────────────
  const VARIANT_STYLES = {
    info:    { bg: 'rgba(96,165,250,0.08)',  border: 'rgba(96,165,250,0.25)',  Icon: Info,          color: '#60a5fa' },
    success: { bg: 'rgba(52,211,153,0.08)',  border: 'rgba(52,211,153,0.25)',  Icon: CheckCircle2,  color: '#34d399' },
    warning: { bg: 'rgba(245,158,11,0.08)',  border: 'rgba(245,158,11,0.28)', Icon: AlertTriangle, color: '#f59e0b' },
    danger:  { bg: 'rgba(239,68,68,0.08)',   border: 'rgba(239,68,68,0.28)',  Icon: AlertCircle,   color: '#ef4444' },
  }
  const HIGHLIGHT_COLORS = { success: '#34d399', warning: '#f59e0b', danger: '#ef4444' }

  function inlineRich(str) {
    if (typeof str !== 'string') return String(str ?? '')
    return str.split(/(`[^`]+`|\*\*[^*]+\*\*)/g).map((part, i) => {
      if (part.startsWith('`') && part.endsWith('`')) {
        return <code key={i} style={{ background: 'rgba(0,210,255,0.10)', padding: '1px 6px', borderRadius: 4, color: 'var(--accent-cyan)', fontFamily: 'monospace', fontSize: '12.5px', border: '1px solid rgba(0,210,255,0.18)' }}>{part.slice(1,-1)}</code>
      }
      if (part.startsWith('**') && part.endsWith('**')) {
        return <strong key={i} style={{ color: 'var(--text-primary)', fontWeight: 650 }}>{part.slice(2,-2)}</strong>
      }
      return <span key={i}>{part}</span>
    })
  }

  function renderBlocks(blocks, onAskQuestion) {
    // Graceful fallback: plain string
    if (typeof blocks === 'string') {
      return (
        <div style={{ fontSize: 14, lineHeight: 1.75, color: 'var(--text-secondary)' }}>
          {blocks.split('\n').map((line, i) => (
            <p key={i} style={{ margin: '0 0 6px 0' }}>{inlineRich(line)}</p>
          ))}
        </div>
      )
    }

    if (!Array.isArray(blocks)) return null

    return (
      <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
        {blocks.map((block, i) => {
          if (!block) return null

          if (block.type === 'heading') return (
            <div key={i} style={{
              display: 'flex', alignItems: 'center', gap: 10,
              paddingBottom: 10, borderBottom: '1px solid var(--border-subtle)',
              marginBottom: 2
            }}>
              {block.icon && (
                <div style={{
                  width: 32, height: 32, borderRadius: 8,
                  background: 'rgba(99, 102, 241, 0.08)',
                  border: '1px solid rgba(99, 102, 241, 0.22)',
                  display: 'flex', alignItems: 'center', justifyContent: 'center',
                  flexShrink: 0
                }}>
                  {renderIcon(block.icon, 16)}
                </div>
              )}
              <span style={{ fontSize: 16, fontWeight: 700, color: 'var(--text-primary)', letterSpacing: '-0.2px' }}>{block.text}</span>
            </div>
          )

          if (block.type === 'text') return (
            <p key={i} style={{ margin: 0, fontSize: 14, lineHeight: 1.7, color: 'var(--text-secondary)' }}>{inlineRich(block.text)}</p>
          )

          if (block.type === 'alert') {
            const v = VARIANT_STYLES[block.variant] || VARIANT_STYLES.info
            const AlertIconComponent = v.Icon || Info
            return (
              <div key={i} style={{
                display: 'flex', gap: 12, alignItems: 'flex-start',
                background: v.bg, border: `1px solid ${v.border}`,
                borderRadius: 10, padding: '12px 16px',
                boxShadow: '0 2px 8px rgba(0,0,0,0.04)'
              }}>
                <div style={{
                  width: 24, height: 24, borderRadius: 6,
                  background: `${v.color}15`,
                  display: 'flex', alignItems: 'center', justifyContent: 'center',
                  flexShrink: 0, marginTop: 1
                }}>
                  <AlertIconComponent size={14} style={{ color: v.color }} />
                </div>
                <span style={{ fontSize: 13.5, color: v.color, lineHeight: 1.65, fontWeight: 450 }}>{inlineRich(block.text)}</span>
              </div>
            )
          }

          if (block.type === 'metric_cards') return (
            <div key={i} style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(130px, 1fr))', gap: 8 }}>
              {(block.cards || []).map((c, ci) => (
                <div key={ci} style={{ background: 'var(--bg-input)', border: `1px solid ${c.border || 'var(--border-subtle)'}`, borderRadius: 8, padding: '10px 12px', display: 'flex', flexDirection: 'column', gap: 3 }}>
                  <div style={{ fontSize: 10.5, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.4px', fontWeight: 600 }}>{c.label}</div>
                  <div style={{ fontSize: 17, fontWeight: 700, color: c.color || 'var(--text-primary)' }}>{c.value}</div>
                  {c.sub && <div style={{ fontSize: 10.5, color: 'var(--text-muted)' }}>{c.sub}</div>}
                </div>
              ))}
            </div>
          )

          if (block.type === 'table') return (
            <div key={i} style={{ borderRadius: 10, overflow: 'hidden', border: '1px solid var(--border-subtle)', background: 'var(--bg-input)' }}>
              {block.title && (
                <div style={{ padding: '8px 12px', fontSize: 11.5, fontWeight: 600, color: 'var(--text-muted)', borderBottom: '1px solid var(--border-subtle)', textTransform: 'uppercase', letterSpacing: '0.4px', background: 'rgba(255,255,255,0.02)' }}>
                  {block.title}
                </div>
              )}
              <div style={{ overflowX: 'auto' }}>
                <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 13 }}>
                  <thead>
                    <tr style={{ background: 'rgba(255,255,255,0.03)' }}>
                      {(block.columns || []).map((c, ci) => (
                        <th key={ci} style={{ textAlign: ci === block.columns.length - 1 ? 'right' : 'left', padding: '7px 12px', color: 'var(--text-muted)', fontWeight: 600, fontSize: 11, textTransform: 'uppercase', letterSpacing: '0.4px', borderBottom: '1px solid var(--border-subtle)' }}>
                          {c}
                        </th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {(block.rows || []).map((row, ri) => (
                      <tr key={ri} style={{ borderBottom: ri < block.rows.length - 1 ? '1px solid var(--border-subtle)' : 'none' }}>
                        {row.map((cell, ci) => (
                          <td key={ci} style={{ padding: '7px 12px', textAlign: ci === row.length - 1 ? 'right' : 'left', color: ci === 0 ? 'var(--text-primary)' : 'var(--text-secondary)', fontFamily: (block.monoCols && block.monoCols.includes(ci)) ? 'monospace' : 'inherit', fontSize: 12.5 }}>
                            {typeof cell === 'string' ? inlineRich(cell) : cell}
                          </td>
                        ))}
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )

          if (block.type === 'code') return (
            <div key={i} style={{ borderRadius: 10, overflow: 'hidden', border: '1px solid var(--border-subtle)', background: 'rgba(15, 23, 42, 0.75)', margin: '2px 0' }}>
              {block.title && (
                <div style={{ padding: '6px 12px', fontSize: 11, fontWeight: 600, color: 'var(--text-muted)', borderBottom: '1px solid rgba(255,255,255,0.08)', display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                  <span>{block.title}</span>
                  {block.badge && (
                    <span style={{ fontSize: 10, background: 'rgba(239,68,68,0.2)', color: '#ef4444', padding: '1px 6px', borderRadius: 4, fontWeight: 700 }}>{block.badge}</span>
                  )}
                </div>
              )}
              <pre style={{ margin: 0, padding: '10px 14px', fontSize: 12, fontFamily: 'monospace', color: '#93c5fd', whiteSpace: 'pre-wrap', wordBreak: 'break-all', lineHeight: 1.55 }}>
                {block.content}
              </pre>
            </div>
          )

          if (block.type === 'kv') return (
            <div key={i} style={{ background: 'var(--bg-input)', border: '1px solid var(--border-subtle)', borderRadius: 10, overflow: 'hidden' }}>
              {(block.rows || []).map((row, j) => (
                <div key={j} style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '9px 14px', borderBottom: j < block.rows.length - 1 ? '1px solid var(--border-subtle)' : 'none', gap: 12 }}>
                  <span style={{ fontSize: 12, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.5px', fontWeight: 500, flexShrink: 0 }}>{row.key}</span>
                  <span style={{ fontSize: 13.5, fontWeight: 600, color: row.highlight ? HIGHLIGHT_COLORS[row.highlight] : 'var(--text-primary)', textAlign: 'right', wordBreak: 'break-word' }}>{row.value}</span>
                </div>
              ))}
            </div>
          )

          if (block.type === 'bullets') return (
            <ul key={i} style={{ margin: 0, padding: 0, listStyle: 'none', display: 'flex', flexDirection: 'column', gap: 8 }}>
              {(block.items || []).map((item, j) => {
                const cleanItem = String(item).replace(/^[\u{1F300}-\u{1F9FF}\u{2600}-\u{26FF}\u{2700}-\u{27BF}\u{1F600}-\u{1F64F}\u{1F680}-\u{1F6FF}]\s*/u, '')
                return (
                  <li key={j} style={{
                    display: 'flex', alignItems: 'flex-start', gap: 10,
                    fontSize: 13.5, color: 'var(--text-secondary)', lineHeight: 1.6,
                    background: 'rgba(255,255,255,0.018)',
                    border: '1px solid var(--border-subtle)',
                    borderRadius: 8, padding: '9px 13px'
                  }}>
                    <div style={{
                      width: 18, height: 18, borderRadius: '50%',
                      background: 'rgba(0, 210, 255, 0.12)',
                      border: '1px solid rgba(0, 210, 255, 0.3)',
                      display: 'flex', alignItems: 'center', justifyContent: 'center',
                      flexShrink: 0, marginTop: 2
                    }}>
                      <Check size={11} style={{ color: 'var(--accent-cyan)' }} />
                    </div>
                    <span style={{ flex: 1 }}>{inlineRich(cleanItem)}</span>
                  </li>
                )
              })}
            </ul>
          )

          if (block.type === 'tags') return (
            <div key={i} style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
              {(block.items || []).map((tag, j) => (
                <code key={j} style={{ background: 'rgba(0,210,255,0.08)', border: '1px solid rgba(0,210,255,0.18)', padding: '2px 8px', borderRadius: 6, fontSize: 12, color: 'var(--accent-cyan)', fontFamily: 'monospace' }}>{tag}</code>
              ))}
              {block.overflow > 0 && <span style={{ fontSize: 12, color: 'var(--text-muted)', alignSelf: 'center' }}>+{block.overflow} more</span>}
            </div>
          )

          if (block.type === 'suggestions') return (
            <div key={i} style={{ marginTop: 6, paddingTop: 12, borderTop: '1px solid var(--border-subtle)' }}>
              <div style={{ fontSize: 11, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.5px', marginBottom: 8, fontWeight: 600 }}>Suggested Follow-Ups:</div>
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: 7 }}>
                {(block.items || []).map((s, si) => (
                  <button
                    key={si}
                    type="button"
                    onClick={() => onAskQuestion && onAskQuestion(s)}
                    style={{
                      background: 'rgba(147,51,234,0.08)',
                      border: '1px solid rgba(147,51,234,0.25)',
                      color: '#c084fc',
                      padding: '6px 13px',
                      borderRadius: 16,
                      fontSize: 12.5,
                      cursor: 'pointer',
                      display: 'inline-flex',
                      alignItems: 'center',
                      gap: 6,
                      transition: 'all 0.15s ease'
                    }}
                    onMouseEnter={e => { e.currentTarget.style.background = 'rgba(147,51,234,0.18)'; e.currentTarget.style.borderColor = 'rgba(147,51,234,0.5)' }}
                    onMouseLeave={e => { e.currentTarget.style.background = 'rgba(147,51,234,0.08)'; e.currentTarget.style.borderColor = 'rgba(147,51,234,0.25)' }}
                  >
                    <MessageSquare size={12} style={{ color: '#c084fc' }} />
                    <span>{s}</span>
                  </button>
                ))}
              </div>
            </div>
          )

          if (block.type === 'divider') return (
            <hr key={i} style={{ border: 'none', borderTop: '1px solid var(--border-subtle)', margin: '2px 0' }} />
          )

          return null
        })}
      </div>
    )
  }

  return (
    <section className="view detail-view-refined">
      <div className="unified-banner tech-pattern-bg" style={{ '--glow-rgb': '244, 63, 94', padding: '12px 24px', borderRadius: '0 0 16px 16px' }}>
        <div className="banner-content">
          <div className="banner-title-area" style={{ gap: 12 }}>
            <div className="detail-icon-badge glass-icon" style={{ width: 38, height: 38, minWidth: 38, borderRadius: 8 }}><Bot size={20} /></div>
            <div>
              <div className="banner-subtitle" style={{ fontSize: '0.75rem', marginBottom: 2 }}>Generic Log Analysis Pipeline</div>
              <h1 className="banner-title" style={{ fontSize: '1.2rem', margin: 0 }}>Threat Detector & AI Chatbot</h1>
            </div>
          </div>
        </div>
      </div>

      <div className="page-body refined-body" style={{ padding: '12px 20px' }}>
        {/* Mode toggle */}
        <div style={{ display: 'flex', gap: 8, marginBottom: 12, flexWrap: 'wrap', alignItems: 'center', justifyContent: 'space-between' }}>
          <div style={{ display: 'flex', gap: 8 }}>
            <button className={`action-btn ${mode === 'chatbot' ? 'active-tab' : ''}`} onClick={() => setMode('chatbot')}
              style={{ padding: '6px 14px', fontSize: 13, background: mode === 'chatbot' ? 'var(--bg-card-h)' : 'var(--bg-card)', borderColor: mode === 'chatbot' ? 'var(--accent-cyan)' : 'var(--border-subtle)' }}>
              <MessageSquare size={14} style={{ color: mode === 'chatbot' ? 'var(--accent-cyan)' : 'var(--text-muted)' }} /> AI Log Chatbot
            </button>
            <button className={`action-btn ${mode === 'sandbox' ? 'active-tab' : ''}`} onClick={() => setMode('sandbox')}
              style={{ padding: '6px 14px', fontSize: 13, background: mode === 'sandbox' ? 'var(--bg-card-h)' : 'var(--bg-card)', borderColor: mode === 'sandbox' ? 'var(--accent-cyan)' : 'var(--border-subtle)' }}>
              <Shield size={14} style={{ color: mode === 'sandbox' ? '#34d399' : 'var(--text-muted)' }} /> Threat Analysis Simulator
              <span style={{ fontSize: 9.5, background: 'rgba(52,211,153,0.18)', color: '#34d399', padding: '1px 6px', borderRadius: 8, marginLeft: 5, fontWeight: 700 }}>SIMULATION</span>
            </button>
          </div>
          {mode === 'sandbox' && (
            <div style={{ display: 'flex', alignItems: 'center', gap: 5, fontSize: 11.5, color: '#34d399', background: 'rgba(52,211,153,0.08)', padding: '3px 10px', borderRadius: 10, border: '1px solid rgba(52,211,153,0.2)' }}>
              <Lock size={11} /> Local Analysis Engine • Zero Outbound Traffic
            </div>
          )}
        </div>

        {/* ── CHATBOT MODE ──────────────────────────────────────────────────── */}
        {mode === 'chatbot' && (
          <div className="sandbox-panel" style={{ minHeight: 380, padding: '14px 18px', display: 'flex', flexDirection: 'column' }}>
            <div className="panel-title" style={{ borderBottom: '1px solid var(--border-subtle)', paddingBottom: 10, marginBottom: 10, display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
              <span style={{ display: 'flex', alignItems: 'center', gap: 7, fontSize: 13 }}>
                <Sparkles size={16} style={{ color: '#9333ea' }} /> SOC Analyst AI — Generic Log Analyzer
              </span>
              <span style={{ fontSize: 11.5, color: 'var(--text-muted)', fontWeight: 400 }}>
                Upload any log file • All values from actual parsed data
              </span>
            </div>

            <div className="chat-window" style={{ flex: 1, overflowY: 'auto', padding: '8px 0', display: 'flex', flexDirection: 'column', gap: 12, maxHeight: 'calc(100vh - 250px)' }}>
              {chatLog.map((msg, i) => (
                <div key={i} style={{ display: 'flex', gap: 10, alignItems: 'flex-start', alignSelf: msg.role === 'user' ? 'flex-end' : 'flex-start', maxWidth: '96%', width: msg.type === 'report' ? '100%' : 'auto' }}>
                  {msg.role === 'ai' && (
                    <div style={{ width: 28, height: 28, borderRadius: '50%', background: 'linear-gradient(135deg, #1d4ed8, #9333ea, #e11d48)', display: 'flex', alignItems: 'center', justifyContent: 'center', color: '#fff', flexShrink: 0, boxShadow: 'var(--shadow-sm)' }}>
                      <Bot size={15} />
                    </div>
                  )}
                  <div style={{
                    background: msg.role === 'user' ? 'var(--bg-card-h)' : msg.type === 'report' ? 'transparent' : 'var(--bg-card)',
                    border: msg.type === 'report' ? 'none' : '1px solid var(--border-subtle)',
                    padding: msg.type === 'report' ? '0' : '16px 20px',
                    borderRadius: 14,
                    fontSize: 14, color: 'var(--text-primary)', lineHeight: 1.7,
                    width: msg.type === 'report' ? '100%' : undefined,
                    maxWidth: msg.type === 'report' ? '100%' : '780px',
                    boxShadow: msg.type === 'report' ? 'none' : 'var(--shadow-sm)'
                  }}>
                    {msg.type === 'report' ? (
                      <AnalysisReport parseResult={msg.parseResult} analysis={msg.analysis} />
                    ) : (
                      renderBlocks(msg.blocks || msg.text, askQuestion)
                    )}
                  </div>
                </div>
              ))}
              {isAnalyzing && (
                <div style={{ display: 'flex', gap: 14, alignItems: 'center' }}>
                  <div style={{ width: 36, height: 36, borderRadius: '50%', background: 'linear-gradient(135deg, #1d4ed8, #9333ea, #e11d48)', display: 'flex', alignItems: 'center', justifyContent: 'center', color: '#fff', flexShrink: 0 }}>
                    <Bot size={19} />
                  </div>
                  <div style={{ color: 'var(--text-muted)', fontSize: 13.5, fontStyle: 'italic', display: 'flex', alignItems: 'center', gap: 8 }}>
                    <RefreshCw size={14} className="spin" style={{ color: 'var(--accent-cyan)' }} />
                    Running forensic log analysis pipeline…
                  </div>
                </div>
              )}
              <div ref={chatEndRef} />
            </div>

            {/* Input area */}
            <div style={{ marginTop: 20, paddingTop: 20, display: 'flex', flexDirection: 'column', alignItems: 'center' }}>
              {pendingFile && (
                <div style={{ padding: '6px 12px', background: 'var(--bg-input)', border: '1px solid var(--border-medium)', borderRadius: 16, display: 'flex', alignItems: 'center', gap: 8, marginBottom: 12, maxWidth: 750, width: '100%' }}>
                  <FileText size={14} style={{ color: '#9333ea' }} />
                  <span style={{ fontSize: 13, color: 'var(--text-primary)', flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{pendingFile.name}</span>
                  <button type="button" onClick={() => setPendingFile(null)} style={{ background: 'transparent', border: 'none', color: 'var(--text-muted)', cursor: 'pointer', fontSize: 16, display: 'flex', alignItems: 'center' }}><X size={14} /></button>
                </div>
              )}
              <form onSubmit={handleSendMessage} style={{ width: '100%', maxWidth: 750, background: 'var(--bg-input)', border: '1px solid var(--border-medium)', borderRadius: 28, display: 'flex', alignItems: 'center', padding: '6px 8px' }}>
                <input type="file" ref={fileInputRef} onChange={handleFileUpload} style={{ display: 'none' }} accept=".log,.txt,.json,.csv,.tsv,.out,.trace,.gz" />
                <button type="button" style={{ width: 40, height: 40, borderRadius: '50%', background: 'transparent', border: 'none', display: 'flex', alignItems: 'center', justifyContent: 'center', cursor: isAnalyzing ? 'default' : 'pointer' }}
                  onClick={() => fileInputRef.current?.click()} disabled={isAnalyzing} title="Upload any log file (.log, .txt, .json, .csv, ...)">
                  <UploadCloud size={20} style={{ color: pendingFile ? '#9333ea' : 'var(--text-muted)' }} />
                </button>
                <input type="text" value={chatInput} onChange={e => setChatInput(e.target.value)}
                  placeholder={pendingFile ? "Ask a question about this log (optional)..." : "Upload a log file, or ask about the last analysis..."}
                  style={{ flex: 1, background: 'transparent', border: 'none', padding: '10px 12px', fontSize: 15, color: 'var(--text-primary)', outline: 'none' }}
                  disabled={isAnalyzing} />
                <button type="submit" disabled={(!chatInput.trim() && !pendingFile) || isAnalyzing}
                  style={{ width: 36, height: 36, borderRadius: '50%', background: (!chatInput.trim() && !pendingFile || isAnalyzing) ? 'var(--bg-card-h)' : '#ffffff', border: 'none', display: 'flex', alignItems: 'center', justifyContent: 'center', cursor: (!chatInput.trim() && !pendingFile || isAnalyzing) ? 'default' : 'pointer', transition: 'background 0.2s' }}>
                  <ArrowUp size={20} style={{ color: (!chatInput.trim() && !pendingFile || isAnalyzing) ? 'var(--text-muted)' : '#000000', strokeWidth: 2.5 }} />
                </button>
              </form>
              <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 8, textAlign: 'center' }}>
                Accepts: .log, .txt, .json, .csv, .tsv, or any text-based log file · All analysis is client-side from actual file content
              </div>
            </div>
          </div>
        )}

        {/* ── SANDBOX MODE (CONTROLLED DEFENSIVE SIMULATOR) ────────────────── */}
        {mode === 'sandbox' && (
          <div>
            {/* Top Simulation Safety Banner */}
            <div style={{
              display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: 14,
              padding: '14px 20px', background: 'rgba(52, 211, 153, 0.08)', border: '1px solid rgba(52, 211, 153, 0.28)',
              borderRadius: 12, marginBottom: 20
            }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
                <div style={{ width: 36, height: 36, borderRadius: '50%', background: 'rgba(52, 211, 153, 0.15)', display: 'flex', alignItems: 'center', justifyContent: 'center', color: '#34d399', flexShrink: 0 }}>
                  <Shield size={20} />
                </div>
                <div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
                    <span style={{ fontSize: 13.5, fontWeight: 700, color: '#34d399', letterSpacing: '0.6px' }}>
                      SIMULATION MODE
                    </span>
                    <span style={{ fontSize: 11, background: 'rgba(52, 211, 153, 0.2)', color: '#34d399', padding: '2px 8px', borderRadius: 12, fontWeight: 600 }}>
                      SAFE — LOCAL ANALYSIS ONLY
                    </span>
                    <span style={{ fontSize: 11, background: 'rgba(96, 165, 250, 0.15)', color: '#60a5fa', padding: '2px 8px', borderRadius: 12, fontWeight: 600 }}>
                      ZERO OUTBOUND TRAFFIC
                    </span>
                  </div>
                  <div style={{ fontSize: 12.5, color: 'var(--text-secondary)', marginTop: 3 }}>
                    This sandbox analyzes request characteristics locally. No network request or payload execution is performed.
                  </div>
                </div>
              </div>
              <div style={{ fontSize: 11.5, color: 'var(--text-muted)', background: 'var(--bg-input)', padding: '5px 12px', borderRadius: 8, border: '1px solid var(--border-subtle)' }}>
                Payloads remain inert text data
              </div>
            </div>

            <div className="sandbox-layout" style={{ gridTemplateColumns: 'minmax(350px, 420px) 1fr' }}>
              {/* Left Panel: Test Input & Parameters */}
              <div className="sandbox-panel" style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
                <div className="panel-title" style={{ display: 'flex', alignItems: 'center', gap: 8, borderBottom: '1px solid var(--border-subtle)', paddingBottom: 12 }}>
                  <Shield size={16} style={{ color: '#34d399' }} /> Request Parameters
                  <span style={{ fontSize: 11, color: 'var(--text-muted)', fontWeight: 400, marginLeft: 'auto' }}>
                    Local Evaluation
                  </span>
                </div>

                {/* Preset section (Section 2 & 25) */}
                <div>
                  <div style={{ fontSize: 11.5, fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.5px', marginBottom: 4 }}>
                    LOAD TEST INPUT
                  </div>
                  <div style={{ fontSize: 11.5, color: 'var(--text-muted)', marginBottom: 10 }}>
                    Detection Test Cases — Select to load example request parameters for local analysis:
                  </div>
                  <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 6 }}>
                    {Object.entries(DETECTION_TEST_CASES).map(([k, testCase]) => {
                      const isActive = activePresetKey === k
                      return (
                        <button
                          key={k}
                          type="button"
                          onClick={() => handleLoadPreset(k)}
                          style={{
                            padding: '7px 8px',
                            background: isActive ? 'rgba(0, 210, 255, 0.12)' : 'var(--bg-input)',
                            border: `1px solid ${isActive ? 'var(--accent-cyan)' : 'var(--border-subtle)'}`,
                            borderRadius: 8,
                            fontSize: 11.5,
                            fontWeight: 600,
                            color: isActive ? 'var(--accent-cyan)' : 'var(--text-secondary)',
                            cursor: 'pointer',
                            textAlign: 'center',
                            transition: 'all 0.15s ease'
                          }}
                        >
                          {testCase.title.replace(' Test Case', '')}
                        </button>
                      )
                    })}
                  </div>
                </div>

                {presetNotice && (
                  <div style={{ padding: '8px 12px', background: 'rgba(96, 165, 250, 0.08)', border: '1px solid rgba(96, 165, 250, 0.25)', borderRadius: 8, fontSize: 12, color: '#93c5fd', display: 'flex', alignItems: 'center', gap: 6 }}>
                    <Info size={14} style={{ flexShrink: 0 }} />
                    <span>{presetNotice}</span>
                  </div>
                )}

                {/* Form fields */}
                <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
                  {/* IP Address */}
                  <div className="form-group" style={{ margin: 0 }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 5 }}>
                      <label style={{ fontSize: 12, fontWeight: 600, color: 'var(--text-secondary)' }}>Source IP Address (Metadata)</label>
                      {(() => {
                        const ipClass = classifyIp(form.ip)
                        return (
                          <span style={{ fontSize: 10.5, padding: '1px 6px', borderRadius: 4, fontWeight: 600, background: ipClass.valid ? (ipClass.isPrivate ? 'rgba(96, 165, 250, 0.15)' : 'rgba(52, 211, 153, 0.15)') : 'rgba(239, 68, 68, 0.15)', color: ipClass.valid ? (ipClass.isPrivate ? '#60a5fa' : '#34d399') : '#ef4444' }}>
                            {ipClass.type}
                          </span>
                        )
                      })()}
                    </div>
                    <input
                      type="text"
                      value={form.ip}
                      onChange={e => update('ip', e.target.value)}
                      placeholder="e.g. 198.51.100.42"
                      style={{ width: '100%', background: 'var(--bg-input)', border: '1px solid var(--border-medium)', borderRadius: 8, padding: '8px 12px', fontSize: 13, color: 'var(--text-primary)', fontFamily: 'monospace' }}
                    />
                  </div>

                  {/* Parameter Key */}
                  <div className="form-group" style={{ margin: 0 }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 5 }}>
                      <label style={{ fontSize: 12, fontWeight: 600, color: 'var(--text-secondary)' }}>Parameter Key (Required)</label>
                      <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>{form.key.length} chars</span>
                    </div>
                    <input
                      type="text"
                      value={form.key}
                      onChange={e => update('key', e.target.value)}
                      placeholder="e.g. id, search, file, cmd"
                      style={{ width: '100%', background: 'var(--bg-input)', border: '1px solid var(--border-medium)', borderRadius: 8, padding: '8px 12px', fontSize: 13, color: 'var(--text-primary)', fontFamily: 'monospace' }}
                    />
                  </div>

                  {/* Parameter Value / Payload */}
                  <div className="form-group" style={{ margin: 0 }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 5 }}>
                      <label style={{ fontSize: 12, fontWeight: 600, color: 'var(--text-secondary)' }}>Parameter Value / Payload (Inert Data)</label>
                      <div style={{ display: 'flex', gap: 8, fontSize: 11, color: 'var(--text-muted)' }}>
                        <span>Entropy: {calcEntropy(form.val)} bits</span>
                        <span>•</span>
                        <span>{form.val.length} chars</span>
                      </div>
                    </div>
                    <textarea
                      rows={3}
                      value={form.val}
                      onChange={e => update('val', e.target.value)}
                      placeholder="Enter request payload to analyze..."
                      style={{ width: '100%', background: 'var(--bg-input)', border: '1px solid var(--border-medium)', borderRadius: 8, padding: '8px 12px', fontSize: 13, color: 'var(--text-primary)', fontFamily: 'monospace', resize: 'vertical', minHeight: 70 }}
                    />
                  </div>

                  {/* User-Agent String */}
                  <div className="form-group" style={{ margin: 0 }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 5 }}>
                      <label style={{ fontSize: 12, fontWeight: 600, color: 'var(--text-secondary)' }}>User-Agent Header (Optional)</label>
                      {(() => {
                        const uaClass = analyzeUserAgent(form.ua)
                        return (
                          <span style={{ fontSize: 10.5, padding: '1px 6px', borderRadius: 4, fontWeight: 600, background: uaClass.isScanner ? 'rgba(239, 68, 68, 0.15)' : uaClass.isHeadless ? 'rgba(245, 158, 11, 0.15)' : 'rgba(96, 165, 250, 0.15)', color: uaClass.isScanner ? '#ef4444' : uaClass.isHeadless ? '#f59e0b' : '#60a5fa' }}>
                            {uaClass.category.split(' ')[0]}
                          </span>
                        )
                      })()}
                    </div>
                    <input
                      type="text"
                      value={form.ua}
                      onChange={e => update('ua', e.target.value)}
                      placeholder="e.g. Mozilla/5.0... or sqlmap/1.6"
                      style={{ width: '100%', background: 'var(--bg-input)', border: '1px solid var(--border-medium)', borderRadius: 8, padding: '8px 12px', fontSize: 12.5, color: 'var(--text-primary)', fontFamily: 'monospace' }}
                    />
                  </div>
                </div>

                {/* Validation Errors */}
                {validationErrors.length > 0 && (
                  <div style={{ padding: '10px 14px', background: 'rgba(239, 68, 68, 0.10)', border: '1px solid rgba(239, 68, 68, 0.3)', borderRadius: 8 }}>
                    <div style={{ fontSize: 12, fontWeight: 700, color: '#ef4444', marginBottom: 4, display: 'flex', alignItems: 'center', gap: 6 }}>
                      <AlertCircle size={14} /> Validation Required
                    </div>
                    <ul style={{ margin: 0, paddingLeft: 18, fontSize: 12, color: '#fca5a5' }}>
                      {validationErrors.map((err, ei) => <li key={ei}>{err}</li>)}
                    </ul>
                  </div>
                )}

                {/* Action button */}
                <div style={{ marginTop: 4 }}>
                  <button
                    type="button"
                    className="run-btn"
                    onClick={runSimulation}
                    disabled={isSimulating}
                    style={{
                      width: '100%',
                      padding: '12px 16px',
                      background: isSimulating ? 'var(--bg-card-h)' : 'linear-gradient(135deg, #1d4ed8, #7c3aed)',
                      border: 'none',
                      borderRadius: 10,
                      color: '#ffffff',
                      fontWeight: 700,
                      fontSize: 14,
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'center',
                      gap: 8,
                      cursor: isSimulating ? 'default' : 'pointer',
                      boxShadow: isSimulating ? 'none' : '0 4px 14px rgba(124, 58, 237, 0.35)',
                      transition: 'all 0.2s ease'
                    }}
                  >
                    {isSimulating ? (
                      <>
                        <RefreshCw size={16} style={{ animation: 'spin 1s linear infinite' }} />
                        Analyzing Characteristics...
                      </>
                    ) : (
                      <>
                        <Play size={16} />
                        Run Local Threat Analysis
                      </>
                    )}
                  </button>

                  <div style={{ textAlign: 'center', fontSize: 11, color: 'var(--text-muted)', marginTop: 8, display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 6 }}>
                    <Lock size={11} style={{ color: '#34d399' }} />
                    <span style={{ fontWeight: 600, letterSpacing: '0.3px' }}>LOCAL SIMULATION — NO NETWORK REQUEST SENT</span>
                  </div>
                </div>

                {/* Step indicator during simulation */}
                {isSimulating && (
                  <div style={{ padding: '10px 14px', background: 'var(--bg-input)', border: '1px solid var(--border-subtle)', borderRadius: 8, display: 'flex', alignItems: 'center', gap: 8, fontSize: 12, color: 'var(--accent-cyan)' }}>
                    <RefreshCw size={13} style={{ animation: 'spin 1s linear infinite', flexShrink: 0 }} />
                    <span>{simStep}</span>
                  </div>
                )}
              </div>

              {/* Right Panel: Simulated Analysis Results & Explainability */}
              <div className="sandbox-panel" style={{ minHeight: 450 }}>
                {!result ? (
                  <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', height: '100%', minHeight: 380, textAlign: 'center', padding: 30 }}>
                    <div style={{ width: 64, height: 64, borderRadius: '50%', background: 'rgba(0, 210, 255, 0.08)', border: '1px solid rgba(0, 210, 255, 0.2)', display: 'flex', alignItems: 'center', justifyContent: 'center', color: 'var(--accent-cyan)', marginBottom: 16 }}>
                      <Shield size={32} />
                    </div>
                    <div style={{ fontSize: 17, fontWeight: 700, color: 'var(--text-primary)', marginBottom: 8 }}>
                      Threat Analysis Engine Ready
                    </div>
                    <div style={{ fontSize: 13, color: 'var(--text-muted)', maxWidth: 440, lineHeight: 1.6, marginBottom: 20 }}>
                      Select a detection test case or enter custom parameters, then click <strong>Run Local Threat Analysis</strong>. The engine normalizes inputs, extracts structural features, and calculates risk scores locally without network transmission.
                    </div>
                    <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8, justifyContent: 'center' }}>
                      <span style={{ display: 'inline-flex', alignItems: 'center', gap: 6, fontSize: 11, background: 'var(--bg-input)', border: '1px solid var(--border-subtle)', padding: '4px 10px', borderRadius: 12, color: 'var(--text-secondary)' }}><Lock size={12} style={{ color: '#38bdf8' }} /> Zero Outbound Traffic</span>
                      <span style={{ display: 'inline-flex', alignItems: 'center', gap: 6, fontSize: 11, background: 'var(--bg-input)', border: '1px solid var(--border-subtle)', padding: '4px 10px', borderRadius: 12, color: 'var(--text-secondary)' }}><BarChart2 size={12} style={{ color: '#34d399' }} /> Dynamic Risk Scoring</span>
                      <span style={{ display: 'inline-flex', alignItems: 'center', gap: 6, fontSize: 11, background: 'var(--bg-input)', border: '1px solid var(--border-subtle)', padding: '4px 10px', borderRadius: 12, color: 'var(--text-secondary)' }}><Target size={12} style={{ color: '#f59e0b' }} /> Strict Confidence Separation</span>
                      <span style={{ display: 'inline-flex', alignItems: 'center', gap: 6, fontSize: 11, background: 'var(--bg-input)', border: '1px solid var(--border-subtle)', padding: '4px 10px', borderRadius: 12, color: 'var(--text-secondary)' }}><Search size={12} style={{ color: '#c084fc' }} /> Full Evidence Provenance</span>
                    </div>
                  </div>
                ) : (
                  <div style={{ display: 'flex', flexDirection: 'column', gap: 18 }}>
                    {/* Status header */}
                    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: 8, borderBottom: '1px solid var(--border-subtle)', paddingBottom: 12 }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                        <span style={{ fontSize: 11, background: 'rgba(52, 211, 153, 0.15)', color: '#34d399', padding: '2px 8px', borderRadius: 6, fontWeight: 700, letterSpacing: '0.4px' }}>
                          SIMULATION STATUS: SAFE — LOCAL ANALYSIS ONLY
                        </span>
                        <span style={{ fontSize: 11, background: 'rgba(96, 165, 250, 0.15)', color: '#60a5fa', padding: '2px 8px', borderRadius: 6, fontWeight: 700, letterSpacing: '0.4px' }}>
                          NETWORK ACTION: NOT EXECUTED
                        </span>
                      </div>
                      <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>
                        {new Date(result.timestamp).toLocaleTimeString()}
                      </span>
                    </div>

                    {/* Verdict Banner */}
                    {(() => {
                      const sev = result.risk.severity
                      const isHigh = sev === 'Critical' || sev === 'High'
                      const isMod = sev === 'Moderate'
                      const bannerColor = isHigh ? '#ef4444' : isMod ? '#f59e0b' : '#34d399'
                      const bannerBg = isHigh ? 'rgba(239, 68, 68, 0.10)' : isMod ? 'rgba(245, 158, 11, 0.10)' : 'rgba(52, 211, 153, 0.10)'
                      const bannerBorder = isHigh ? 'rgba(239, 68, 68, 0.3)' : isMod ? 'rgba(245, 158, 11, 0.3)' : 'rgba(52, 211, 153, 0.3)'
                      const Icon = isHigh ? AlertTriangle : isMod ? AlertCircle : CheckCircle2

                      return (
                        <div style={{ background: bannerBg, border: `1px solid ${bannerBorder}`, borderRadius: 12, padding: '16px 18px', display: 'flex', alignItems: 'flex-start', gap: 14 }}>
                          <Icon size={26} style={{ color: bannerColor, marginTop: 2, flexShrink: 0 }} />
                          <div style={{ flex: 1 }}>
                            <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap', marginBottom: 4 }}>
                              <span style={{ fontSize: 16, fontWeight: 700, color: bannerColor }}>
                                {result.classification.label}
                              </span>
                              <span style={{ fontSize: 11, background: `${bannerColor}25`, color: bannerColor, padding: '2px 8px', borderRadius: 12, fontWeight: 700, textTransform: 'uppercase' }}>
                                {result.classification.category}
                              </span>
                            </div>
                            <div style={{ fontSize: 13, color: 'var(--text-secondary)', lineHeight: 1.55 }}>
                              {result.explanation}
                            </div>
                          </div>
                        </div>
                      )
                    })()}

                    {/* KPI Meters (Section 7, 9 - Risk Score vs Confidence Separated!) */}
                    <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(130px, 1fr))', gap: 10 }}>
                      {/* Risk Score */}
                      <div style={{ background: 'var(--bg-input)', border: '1px solid var(--border-medium)', borderRadius: 10, padding: '12px 14px' }}>
                        <div style={{ fontSize: 11, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.4px', fontWeight: 600 }}>Risk Score</div>
                        <div style={{ display: 'flex', alignItems: 'baseline', gap: 4, marginTop: 4 }}>
                          <span style={{ fontSize: 24, fontWeight: 800, color: result.risk.score >= 51 ? '#ef4444' : result.risk.score >= 21 ? '#f59e0b' : '#34d399' }}>
                            {result.risk.score}
                          </span>
                          <span style={{ fontSize: 12, color: 'var(--text-muted)' }}>/ 100</span>
                        </div>
                        <div style={{ fontSize: 11, fontWeight: 600, color: result.risk.score >= 51 ? '#ef4444' : result.risk.score >= 21 ? '#f59e0b' : '#34d399', marginTop: 2 }}>
                          {result.risk.severity} Severity
                        </div>
                        {/* Progress Bar */}
                        <div style={{ width: '100%', height: 4, background: 'rgba(255,255,255,0.08)', borderRadius: 2, marginTop: 8, overflow: 'hidden' }}>
                          <div style={{ width: `${result.risk.score}%`, height: '100%', background: result.risk.score >= 51 ? '#ef4444' : result.risk.score >= 21 ? '#f59e0b' : '#34d399', transition: 'width 0.5s ease' }} />
                        </div>
                      </div>

                      {/* Confidence (Strictly Separated!) */}
                      <div style={{ background: 'var(--bg-input)', border: '1px solid var(--border-medium)', borderRadius: 10, padding: '12px 14px' }}>
                        <div style={{ fontSize: 11, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.4px', fontWeight: 600 }}>Model Confidence</div>
                        <div style={{ display: 'flex', alignItems: 'baseline', gap: 4, marginTop: 4 }}>
                          <span style={{ fontSize: 24, fontWeight: 800, color: 'var(--accent-cyan)' }}>
                            {(result.classification.confidence * 100).toFixed(0)}%
                          </span>
                        </div>
                        <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 2 }}>
                          Classification certainty
                        </div>
                        <div style={{ width: '100%', height: 4, background: 'rgba(255,255,255,0.08)', borderRadius: 2, marginTop: 8, overflow: 'hidden' }}>
                          <div style={{ width: `${(result.classification.confidence * 100).toFixed(0)}%`, height: '100%', background: 'var(--accent-cyan)', transition: 'width 0.5s ease' }} />
                        </div>
                      </div>

                      {/* Encoding */}
                      <div style={{ background: 'var(--bg-input)', border: '1px solid var(--border-medium)', borderRadius: 10, padding: '12px 14px' }}>
                        <div style={{ fontSize: 11, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.4px', fontWeight: 600 }}>Payload Encoding</div>
                        <div style={{ fontSize: 15, fontWeight: 700, color: result.features.has_double_encoding ? '#f59e0b' : 'var(--text-primary)', marginTop: 8 }}>
                          {result.features.encoding}
                        </div>
                        <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 4 }}>
                          {result.features.has_double_encoding ? 'Potential evasion' : 'Normalized'}
                        </div>
                      </div>

                      {/* Entropy */}
                      <div style={{ background: 'var(--bg-input)', border: '1px solid var(--border-medium)', borderRadius: 10, padding: '12px 14px' }}>
                        <div style={{ fontSize: 11, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.4px', fontWeight: 600 }}>Shannon Entropy</div>
                        <div style={{ fontSize: 22, fontWeight: 800, color: result.features.original_entropy > 4.5 ? '#f59e0b' : 'var(--text-primary)', marginTop: 4 }}>
                          {result.features.original_entropy} <span style={{ fontSize: 12, fontWeight: 400, color: 'var(--text-muted)' }}>bits</span>
                        </div>
                        <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 2 }}>
                          Special char ratio: {(result.features.special_char_ratio * 100).toFixed(0)}%
                        </div>
                      </div>
                    </div>

                    {/* Request Envelope Preview (Section 15) */}
                    <div style={{ background: 'var(--bg-input)', border: '1px solid var(--border-subtle)', borderRadius: 10, overflow: 'hidden' }}>
                      <div style={{ padding: '8px 14px', background: 'rgba(255,255,255,0.03)', borderBottom: '1px solid var(--border-subtle)', fontSize: 11, fontWeight: 700, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.5px', display: 'flex', justifyContent: 'space-between' }}>
                        <span>Simulated Request Representation (Sanitized)</span>
                        <span style={{ color: '#34d399' }}>NOT TRANSMITTED</span>
                      </div>
                      <div style={{ padding: '12px 14px', fontFamily: 'monospace', fontSize: 12, color: 'var(--text-secondary)', display: 'flex', flexDirection: 'column', gap: 4, lineHeight: 1.6 }}>
                        <div><strong style={{ color: 'var(--text-primary)' }}>METHOD:</strong> GET (Simulated Client Request)</div>
                        <div><strong style={{ color: 'var(--text-primary)' }}>PARAMETER:</strong> <span style={{ color: 'var(--accent-cyan)' }}>{result.input.parameter_key}</span></div>
                        <div style={{ wordBreak: 'break-all' }}><strong style={{ color: 'var(--text-primary)' }}>RAW VALUE:</strong> {result.input.original_value}</div>
                        {result.input.original_value !== result.input.normalized_value && (
                          <div style={{ wordBreak: 'break-all', color: '#93c5fd' }}><strong style={{ color: 'var(--text-primary)' }}>NORMALIZED:</strong> {result.input.normalized_value}</div>
                        )}
                        <div><strong style={{ color: 'var(--text-primary)' }}>SOURCE IP:</strong> {result.input.ip} <span style={{ color: 'var(--text-muted)' }}>({result.features.ip_type})</span></div>
                        <div><strong style={{ color: 'var(--text-primary)' }}>USER-AGENT:</strong> {result.input.user_agent} <span style={{ color: 'var(--text-muted)' }}>({result.features.ua_category})</span></div>
                        <div style={{ color: '#34d399', marginTop: 4 }}>• Local Inspection Status: SAFE — Executed in secure sandbox without target contact</div>
                      </div>
                    </div>

                    {/* Detected Security Indicators */}
                    {result.indicators.length > 0 && (
                      <div>
                        <div style={{ fontSize: 12, fontWeight: 700, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.5px', marginBottom: 8 }}>
                          Detected Indicators ({result.indicators.length})
                        </div>
                        <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                          {result.indicators.map((ind, ii) => (
                            <div key={ii} style={{ background: 'var(--bg-input)', border: '1px solid var(--border-subtle)', borderRadius: 8, padding: '10px 14px', display: 'flex', alignItems: 'flex-start', gap: 10 }}>
                              <span style={{ fontSize: 10.5, fontWeight: 700, padding: '2px 8px', borderRadius: 4, background: ind.severity === 'High' ? 'rgba(239, 68, 68, 0.15)' : 'rgba(245, 158, 11, 0.15)', color: ind.severity === 'High' ? '#ef4444' : '#f59e0b', flexShrink: 0, marginTop: 1 }}>
                                {ind.severity}
                              </span>
                              <div style={{ flex: 1 }}>
                                <div style={{ fontSize: 13, fontWeight: 600, color: 'var(--text-primary)' }}>{ind.title}</div>
                                <div style={{ fontSize: 12, color: 'var(--text-secondary)', marginTop: 2 }}>{ind.description}</div>
                              </div>
                              <span style={{ fontSize: 11, color: 'var(--text-muted)', fontFamily: 'monospace' }}>+{ind.weight} pts</span>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}

                    {/* Expandable Evidence Section (Section 17) */}
                    {result.evidence.length > 0 && (
                      <div style={{ border: '1px solid var(--border-subtle)', borderRadius: 10, overflow: 'hidden' }}>
                        <div
                          onClick={() => setShowEvidence(v => !v)}
                          style={{ padding: '10px 14px', background: 'var(--bg-input)', cursor: 'pointer', display: 'flex', alignItems: 'center', justifyContent: 'space-between', userSelect: 'none' }}
                        >
                          <span style={{ fontSize: 12.5, fontWeight: 700, color: 'var(--text-primary)', display: 'flex', alignItems: 'center', gap: 6 }}>
                            <Search size={14} style={{ color: 'var(--accent-cyan)' }} />
                            Why was this detected? (Evidence Provenance)
                          </span>
                          {showEvidence ? <ChevronDown size={14} style={{ color: 'var(--text-muted)' }} /> : <ChevronRight size={14} style={{ color: 'var(--text-muted)' }} />}
                        </div>
                        {showEvidence && (
                          <div style={{ padding: '12px 14px', background: 'rgba(15, 23, 42, 0.5)', overflowX: 'auto' }}>
                            <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 12 }}>
                              <thead>
                                <tr style={{ borderBottom: '1px solid var(--border-subtle)', color: 'var(--text-muted)', textAlign: 'left' }}>
                                  <th style={{ padding: '6px 8px' }}>Indicator</th>
                                  <th style={{ padding: '6px 8px' }}>Source</th>
                                  <th style={{ padding: '6px 8px' }}>Matched Evidence Snippet</th>
                                  <th style={{ padding: '6px 8px', textAlign: 'right' }}>Confidence</th>
                                </tr>
                              </thead>
                              <tbody>
                                {result.evidence.map((ev, ei) => (
                                  <tr key={ei} style={{ borderBottom: '1px solid rgba(255,255,255,0.04)' }}>
                                    <td style={{ padding: '8px', color: 'var(--text-primary)', fontWeight: 600 }}>{ev.indicator}</td>
                                    <td style={{ padding: '8px', color: 'var(--text-muted)' }}>{ev.source}</td>
                                    <td style={{ padding: '8px' }}>
                                      <code style={{ background: 'rgba(239, 68, 68, 0.12)', color: '#fca5a5', padding: '2px 8px', borderRadius: 4, fontFamily: 'monospace', fontSize: 12, border: '1px solid rgba(239, 68, 68, 0.25)', wordBreak: 'break-all' }}>
                                        {ev.evidence_snippet}
                                      </code>
                                    </td>
                                    <td style={{ padding: '8px', textAlign: 'right', color: 'var(--accent-cyan)', fontWeight: 700 }}>
                                      {(ev.confidence * 100).toFixed(0)}%
                                    </td>
                                  </tr>
                                ))}
                              </tbody>
                            </table>
                          </div>
                        )}
                      </div>
                    )}

                    {/* Recommendation */}
                    {result.recommendation && (
                      <div style={{ background: 'rgba(96, 165, 250, 0.08)', border: '1px solid rgba(96, 165, 250, 0.25)', borderRadius: 10, padding: '12px 16px' }}>
                        <div style={{ fontSize: 12, fontWeight: 700, color: '#60a5fa', marginBottom: 4, display: 'flex', alignItems: 'center', gap: 6 }}>
                          <Shield size={14} /> Defensive Mitigation Recommendation
                        </div>
                        <div style={{ fontSize: 12.5, color: 'var(--text-secondary)', lineHeight: 1.55 }}>
                          {result.recommendation}
                        </div>
                      </div>
                    )}

                    {/* Limitations Box */}
                    <div style={{ background: 'var(--bg-input)', border: '1px solid var(--border-subtle)', borderRadius: 8, padding: '10px 14px', fontSize: 11.5, color: 'var(--text-muted)' }}>
                      <div style={{ fontWeight: 600, color: 'var(--text-secondary)', marginBottom: 4 }}>Simulation Disclaimers & Safety Notice:</div>
                      <ul style={{ margin: 0, paddingLeft: 16, display: 'flex', flexDirection: 'column', gap: 2 }}>
                        {result.limitations.map((lim, li) => <li key={li}>{lim}</li>)}
                      </ul>
                    </div>
                  </div>
                )}
              </div>
            </div>
          </div>
        )}
      </div>
    </section>
  )
}
