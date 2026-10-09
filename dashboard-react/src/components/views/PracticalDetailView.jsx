import { useState, useEffect, useRef, useCallback } from 'react'
import { useApp } from '../../context/AppContext'
import { Bar, Line, Doughnut } from 'react-chartjs-2'
import { Chart as ChartJS, CategoryScale, LinearScale, BarElement, LineElement, PointElement, ArcElement, Filler, Tooltip, Legend, Title } from 'chart.js'
import { CHART_CONFIGS, COVERS, EXAMPLES } from '../../data/chartConfigs'
import { deepMerge, getChartBaseOptions } from '../../utils/helpers'
import { Tag, Code2, BookOpen, BarChart2, Terminal, FileText, CheckCircle2, HelpCircle, Lightbulb, GitBranch, Cpu, Activity, ArrowLeft, Copy, Check, Database, Search, Shield, PieChart, Filter, Layers, Zap } from 'lucide-react'

ChartJS.register(CategoryScale, LinearScale, BarElement, LineElement, PointElement, ArcElement, Filler, Tooltip, Legend, Title)

// ── COMBINED VIEW ──────────────────────────────────────────────────────────────
export default function PracticalDetailView() {
  const { currentPractical: p, setActiveView, theme, openLightbox } = useApp()
  const [copied, setCopied] = useState(false)
  const canvasRef = useRef(null)

  if (!p) return null
  const cover = COVERS[(p.id - 1) % COVERS.length]
  const isDark = theme === 'dark'

  const ICONS = [Database, Search, Filter, Shield, GitBranch, PieChart, Layers, Activity, Cpu, Zap]
  const BannerIcon = ICONS[(p.id - 1) % ICONS.length] || Activity

  const GLOW_RGBS = [
    '74, 155, 224',  // Blue
    '133, 91, 230',  // Purple
    '57, 177, 131',  // Emerald
    '214, 73, 85',   // Rose
    '229, 157, 53',  // Amber
    '46, 170, 220',  // Cyan
    '94, 106, 210',  // Indigo
    '16, 185, 129',  // Green
    '244, 63, 94',   // Pink
    '245, 158, 11',  // Yellow
  ]
  const glowRgb = GLOW_RGBS[(p.id - 1) % GLOW_RGBS.length]

  const handleCopy = () => {
    navigator.clipboard.writeText(p.py_code || '').then(() => {
      setCopied(true)
      setTimeout(() => setCopied(false), 2000)
    })
  }

  return (
    <section className="view detail-view-refined">
      {/* Unified Banner with Tech Pattern */}
      <div className="unified-banner tech-pattern-bg" style={{ '--glow-rgb': glowRgb }}>
        <div className="banner-content">
          <button
            className="action-btn glass-btn"
            onClick={() => setActiveView('dashboard')}
          >
            <ArrowLeft size={14} /> Dashboard
          </button>
          
          <div className="banner-title-area">
            <div className="detail-icon-badge glass-icon"><BannerIcon size={28} /></div>
            <div>
              <div className="banner-subtitle">Practical {p.id} • {p.category}</div>
              <h1 className="banner-title">{p.title.replace(/^Practical \d+:\s*/, '')}</h1>
            </div>
          </div>
        </div>
      </div>

      <div className="page-body refined-body">
        
        {/* Info & Metrics Grid */}
        <div className="info-grid-container">
          
          {/* Left Column: Objective & Meta */}
          <div className="info-main">
            <div className="callout callout-elegant">
              <Lightbulb size={20} style={{color:'var(--accent-amber)',flexShrink:0}} />
              <div>
                <strong style={{color:'var(--accent-amber)', display:'block', marginBottom:4}}>Academic Objective</strong>
                <span className="objective-text">{p.learning?.concept_summary}</span>
              </div>
            </div>

            <div className="meta-pills elegant-pills" style={{marginTop: 16}}>
              <span className="tag tag-green"><CheckCircle2 size={13} /> Completed &amp; Verified</span>
              {p.tags?.map(t => <span key={t} className="tag tag-glass">{t}</span>)}
            </div>
          </div>

          {/* Right Column: Files & Metrics */}
          <div className="info-sidebar">
            <div className="file-card">
              <div className="file-row">
                <Code2 size={14} className="file-icon" /> 
                <span className="file-val">{p.py_file}</span>
              </div>
              <div className="file-row">
                <FileText size={14} className="file-icon" /> 
                <span className="file-val">{p.ipynb_file}</span>
              </div>
            </div>

            {p.key_metrics?.length > 0 && (
              <div className="metrics-grid small-metrics">
                {p.key_metrics.map((m, i) => (
                  <div key={i} className="metric-card minimal-metric">
                    <span className="metric-label">{m.label}</span>
                    <span className={`metric-value ${m.label.toLowerCase().includes('accuracy') || m.label.toLowerCase().includes('rate') ? 'highlight-cyan' : ''}`}>{m.value}</span>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>

        {/* Combined Content Sections */}
        <div className="combined-content">
          <div className="section-divider">
            <BookOpen size={16} /> <h2>Theory &amp; Learning</h2>
          </div>
          <LearnTab p={p} />

          <div className="section-divider" id="chart-section">
            <BarChart2 size={16} /> <h2>Visualizations</h2>
          </div>
          <ChartTab p={p} isDark={isDark} onLightbox={openLightbox} />

          <div className="section-divider" id="code-section">
            <Code2 size={16} /> <h2>Python Script</h2>
          </div>
          <CodeTab p={p} copied={copied} onCopy={handleCopy} />

          <div className="section-divider" id="terminal-section">
            <Terminal size={16} /> <h2>Terminal Output</h2>
          </div>
          <TerminalTab p={p} />

          <div className="section-divider" id="notebook-section">
            <FileText size={16} /> <h2>Jupyter Notebook</h2>
          </div>
          <NotebookTab p={p} />
        </div>
      </div>
    </section>
  )
}

// ── LEARN TAB ─────────────────────────────────────────────────────────────────
function LearnTab({ p }) {
  const l = p.learning
  if (!l) return <p style={{color:'var(--text-muted)',padding:'20px 0'}}>Learning content not available.</p>
  const ex = EXAMPLES[p.id]
  return (
    <div className="tab-pane">
      {/* Analogy */}
      <div className="learn-section analogy-section">
        <div className="learn-section-h" style={{color:'var(--accent-cyan)'}}>
          <Lightbulb size={18} style={{color:'var(--accent-cyan)'}} />
          <span className="learn-section-title" style={{color:'var(--accent-cyan)'}}>Understand in 30 Seconds: {l.analogy_title}</span>
        </div>
        <div className="learn-body"><p className="analogy-text">{l.analogy_desc}</p></div>
      </div>

      {/* Concept */}
      <div className="learn-section">
        <div className="learn-section-h">
          <BookOpen size={18} style={{color:'var(--accent-blue)'}} />
          <span className="learn-section-title">1. Core Concept &amp; Academic Importance</span>
        </div>
        <div className="learn-body"><p className="concept-text">{l.concept_summary}</p></div>
      </div>

      {/* Data Examples */}
      {ex && (
        <div className="learn-section">
          <div className="learn-section-h">
            <Activity size={18} style={{color:'var(--accent-emerald)'}} />
            <span className="learn-section-title">{ex.title}</span>
          </div>
          <div className="learn-body" style={{paddingTop:0}}>
            <div className="table-wrap" style={{marginTop:14}}>
              <table className="data-table">
                <thead><tr>{ex.headers.map(h => <th key={h}>{h}</th>)}</tr></thead>
                <tbody>{ex.rows.map((row,i) => <tr key={i}>{row.map((cell,j) => <td key={j}>{cell}</td>)}</tr>)}</tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      {/* Theory */}
      {l.theoretical_foundations?.length > 0 && (
        <div className="learn-section">
          <div className="learn-section-h">
            <Cpu size={18} style={{color:'var(--accent-indigo)'}} />
            <span className="learn-section-title">2. Technical Principles &amp; Mathematical Foundations</span>
          </div>
          <div className="learn-body">
            <ul className="theory-list">
              {l.theoretical_foundations.map((t,i) => (
                <li key={i} className="theory-item" dangerouslySetInnerHTML={{__html: t.replace(/\*\*(.*?)\*\*/g,'<strong>$1</strong>').replace(/`(.*?)`/g,'<code>$1</code>')}} />
              ))}
            </ul>
          </div>
        </div>
      )}

      {/* Steps */}
      {l.methodology_steps?.length > 0 && (
        <div className="learn-section">
          <div className="learn-section-h">
            <GitBranch size={18} style={{color:'var(--accent-purple)'}} />
            <span className="learn-section-title">3. Step-by-Step Execution Sequence</span>
          </div>
          <div className="learn-body">
            <div className="steps-list">
              {l.methodology_steps.map((s,i) => (
                <div key={i} className="step-item">
                  <div className="step-num">{i+1}</div>
                  <div className="step-text" dangerouslySetInnerHTML={{__html: s.replace(/\*\*(.*?)\*\*/g,'<strong>$1</strong>').replace(/`(.*?)`/g,'<code>$1</code>')}} />
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* Viva Q&A */}
      {l.viva_questions?.length > 0 && (
        <div className="learn-section">
          <div className="learn-section-h">
            <HelpCircle size={18} style={{color:'var(--accent-amber)'}} />
            <span className="learn-section-title">4. Viva &amp; Interview Q&amp;A</span>
          </div>
          <div className="learn-body">
            {l.viva_questions.map((v,i) => (
              <div key={i} className="viva-card">
                <div className="viva-q"><HelpCircle size={15} style={{color:'var(--accent-indigo)',flexShrink:0}} /><span>{v.q}</span></div>
                <div className="viva-a"><strong>Answer:</strong> {v.a}</div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}

// ── CHART TAB ─────────────────────────────────────────────────────────────────
function ChartTab({ p, isDark, onLightbox }) {
  const cfg = CHART_CONFIGS[p.id]
  if (!cfg) return <div className="tab-pane"><p style={{color:'var(--text-muted)'}}>Chart not available for this practical.</p></div>

  const baseOpts = getChartBaseOptions(isDark)
  let opts = deepMerge(baseOpts, cfg.options || {})
  if (cfg.type === 'doughnut' || cfg.type === 'pie') {
    delete opts.scales
  }

  const ChartComp = cfg.type === 'line' ? Line : cfg.type === 'doughnut' ? Doughnut : Bar

  return (
    <div className="tab-pane">
      <div className="chart-panel">
        <div className="chart-panel-header">
          <div>
            <div className="chart-panel-title">{cfg.title}</div>
            <div className="chart-panel-desc">Practical {p.id} · {p.category} · Chart.js Interactive</div>
          </div>
          <span className="chart-panel-badge">{cfg.badge}</span>
        </div>
        <div className="chart-body">
          <div className="chart-container">
            <ChartComp key={`${p.id}-${isDark}`} data={cfg.data} options={opts} />
          </div>
          <div className="chart-insight" dangerouslySetInnerHTML={{__html: cfg.insight}} />
        </div>
      </div>

      {/* Matplotlib figure */}
      {p.chart_path && (
        <div className="chart-panel">
          <div className="chart-panel-header">
            <div>
              <div className="chart-panel-title">Matplotlib Figure — {p.chart_title}</div>
              <div className="chart-panel-desc">{p.chart_desc}</div>
            </div>
            <span className="chart-panel-badge">180 DPI PNG</span>
          </div>
          <div className="chart-body">
            <img
              className="mpl-img"
              src={`../${p.chart_path}`}
              alt={p.chart_title}
              onClick={() => onLightbox(`../${p.chart_path}`, p.chart_title)}
              loading="lazy"
            />
          </div>
        </div>
      )}
    </div>
  )
}

// ── CODE TAB ──────────────────────────────────────────────────────────────────
function CodeTab({ p, copied, onCopy }) {
  return (
    <div className="tab-pane">
      <div className="code-viewer">
        <div className="code-header">
          <div className="code-dots">
            <span className="dot dot-r" /><span className="dot dot-y" /><span className="dot dot-g" />
          </div>
          <span className="code-filename">{p.py_file}</span>
          <button className="action-btn" onClick={onCopy}>
            {copied ? <><Check size={13} /> Copied!</> : <><Copy size={13} /> Copy</>}
          </button>
        </div>
        <pre className="code-pre"><code>{p.py_code || '# Code not available'}</code></pre>
      </div>
    </div>
  )
}

// ── TERMINAL TAB ──────────────────────────────────────────────────────────────
function TerminalTab({ p }) {
  return (
    <div className="tab-pane">
      <div className="terminal-window">
        <div className="term-header">
          <div className="code-dots">
            <span className="dot dot-r" /><span className="dot dot-y" /><span className="dot dot-g" />
          </div>
          <span className="term-title-text">bash — python3 (PDS Environment)</span>
          <span className="term-exit"><CheckCircle2 size={12} color="#10b981" /> Exit 0</span>
        </div>
        <div className="term-body">
          <div className="term-prompt">
            <span className="term-user">khush@pds</span>:<span className="term-dir">~/PDS_Practicals</span>
            $ <span>{`python ${p.py_file}`}</span>
          </div>
          <pre className="term-out">{p.terminal_output || 'Execution output not recorded.'}</pre>
          <div className="term-cursor">
            <span className="term-user">khush@pds</span>:<span className="term-dir">~/PDS_Practicals</span>
            $ <span className="cursor-blink">█</span>
          </div>
        </div>
      </div>
    </div>
  )
}

// ── NOTEBOOK TAB ─────────────────────────────────────────────────────────────
function NotebookTab({ p }) {
  const [cells, setCells] = useState(null)
  const [error, setError] = useState(false)

  useEffect(() => {
    if (!p.ipynb_file) return
    fetch(`../${p.ipynb_file}`)
      .then(r => r.json())
      .then(nb => setCells(nb.cells || []))
      .catch(() => setError(true))
  }, [p.ipynb_file])

  if (error) return (
    <div className="tab-pane">
      <div className="callout callout-blue">
        <FileText size={16} style={{color:'#60a5fa',flexShrink:0}} />
        <div>Notebook preview unavailable in this context. Open the .ipynb file directly in Jupyter Lab.</div>
      </div>
    </div>
  )
  if (!cells) return <div className="tab-pane" style={{color:'var(--text-muted)'}}>Loading notebook cells...</div>

  return (
    <div className="tab-pane">
      <div className="nb-wrapper">
        {cells.map((cell, i) => {
          const src = Array.isArray(cell.source) ? cell.source.join('') : cell.source
          if (cell.cell_type === 'markdown') {
            return <div key={i} className="nb-cell markdown" dangerouslySetInnerHTML={{__html: src}} />
          }
          if (cell.cell_type === 'code') {
            let out = ''
            ;(cell.outputs || []).forEach(o => {
              if (o.text) out += Array.isArray(o.text) ? o.text.join('') : o.text
            })
            return (
              <div key={i} className="nb-cell code">
                <div className="nb-in">
                  <span className="nb-label">In [{cell.execution_count || i+1}]:</span>
                  <pre><code>{src}</code></pre>
                </div>
                {out && (
                  <div className="nb-out">
                    <span className="nb-label">Out [{cell.execution_count || i+1}]:</span>
                    <pre><code>{out}</code></pre>
                  </div>
                )}
              </div>
            )
          }
          return null
        })}
      </div>
    </div>
  )
}
