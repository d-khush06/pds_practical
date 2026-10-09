import { useState, useEffect, useMemo } from 'react'
import { useApp } from '../../context/AppContext'
import { COVERS } from '../../data/chartConfigs'
import { Layers, Grid, Table2, CheckCircle2, Database, Activity, Crosshair, Check, DollarSign, Search, Filter, Shield, GitBranch, PieChart, Zap, Cpu } from 'lucide-react'

const CATEGORIES = ['all','Data Exploration','Data Engineering','Preprocessing','Cybersecurity','Feature Engineering','Data Balancing','Analytics','Visualization','Machine Learning','MLOps Pipeline']
const CATEGORY_LABELS = { 'all':'All (10)', 'Data Exploration':'Exploration', 'Data Engineering':'Engineering', 'Preprocessing':'Preprocessing', 'Cybersecurity':'Cybersecurity', 'Feature Engineering':'Features', 'Data Balancing':'Balancing', 'Analytics':'Analytics', 'Visualization':'Visualization', 'Machine Learning':'ML', 'MLOps Pipeline':'MLOps' }

export default function DashboardView() {
  const { openPractical, searchQuery, activeCategory, setActiveCategory, dbView, setDbView } = useApp()
  const [data, setData] = useState([])
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    fetch('../web_data.json')
      .then(r => r.json())
      .then(d => { setData(d); setLoading(false) })
      .catch(() => setLoading(false))
  }, [])

  const filtered = useMemo(() => {
    let items = data
    if (activeCategory !== 'all') items = items.filter(p => p.category === activeCategory)
    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase()
      items = items.filter(p =>
        p.title.toLowerCase().includes(q) ||
        p.short_title.toLowerCase().includes(q) ||
        p.category.toLowerCase().includes(q) ||
        p.tags?.some(t => t.toLowerCase().includes(q)) ||
        p.learning?.concept_summary?.toLowerCase().includes(q)
      )
    }
    return items
  }, [data, activeCategory, searchQuery])

  return (
    <section className="view">
      {/* Hero */}
      <div className="hero-cover tech-pattern-bg" style={{ '--glow-rgb': '94, 106, 210' }}>
        <div className="cover-content">
          <div className="hero-badge">
            <DollarSign size={14} />
            Academic Practicals Lab · 2026
          </div>
          <h1 className="hero-title">Python for Data Science</h1>
          <p className="hero-sub">End-to-end Cybersecurity Analytics on Honeypot Telemetry</p>
        </div>
      </div>

      <div className="page-body">
        <div className="callout callout-blue">
          <Database size={18} style={{color:'#60a5fa',flexShrink:0}} />
          <div>
            <strong>Curriculum Alignment:</strong> All 10 practicals fully implemented with Python scripts, Jupyter Notebooks, Matplotlib figures, and interactive Chart.js visualizations with detailed learning modules.
          </div>
        </div>

        {/* Global Stats */}
        <div className="stats-grid">
          <div className="stat-card">
            <div className="stat-icon stat-blue"><Database size={20} /></div>
            <div className="stat-info">
              <span className="stat-label">RAW DATASET</span>
              <span className="stat-value">215.4 MB</span>
              <span className="stat-sub">cj.log honeypot</span>
            </div>
          </div>
          <div className="stat-card">
            <div className="stat-icon stat-purple"><Activity size={20} /></div>
            <div className="stat-info">
              <span className="stat-label">TOTAL EVENTS</span>
              <span className="stat-value">2,062,365</span>
              <span className="stat-sub">Attacks &amp; benign</span>
            </div>
          </div>
          <div className="stat-card">
            <div className="stat-icon stat-cyan"><Crosshair size={20} /></div>
            <div className="stat-info">
              <span className="stat-label">MODEL ACCURACY</span>
              <span className="stat-value accent">99.21%</span>
              <span className="stat-sub">Random Forest</span>
            </div>
          </div>
          <div className="stat-card">
            <div className="stat-icon stat-green"><Check size={20} /></div>
            <div className="stat-info">
              <span className="stat-label">STATUS</span>
              <span className="stat-value green">10 / 10 Done</span>
              <span className="stat-sub">All exit code 0</span>
            </div>
          </div>
        </div>

        {/* Toolbar */}
        <div className="db-toolbar">
          <div className="db-title-row">
            <div className="db-title">
              <Layers size={16} /> Practicals Database
            </div>
            <div className="view-toggle-group">
              <button className={`view-toggle ${dbView==='gallery'?'active':''}`} onClick={() => setDbView('gallery')}>
                <Grid size={13} /> Gallery
              </button>
              <button className={`view-toggle ${dbView==='table'?'active':''}`} onClick={() => setDbView('table')}>
                <Table2 size={13} /> Table
              </button>
            </div>
          </div>
          <div className="filter-chips">
            {CATEGORIES.map(cat => (
              <button
                key={cat}
                className={`chip ${activeCategory===cat?'active':''}`}
                onClick={() => setActiveCategory(cat)}
              >
                {CATEGORY_LABELS[cat]}
              </button>
            ))}
          </div>
        </div>

        {loading && (
          <div style={{display:'grid',gridTemplateColumns:'repeat(auto-fill,minmax(300px,1fr))',gap:16}}>
            {Array.from({length:6}).map((_,i) => (
              <div key={i} style={{height:230,borderRadius:16,background:'var(--bg-card)',border:'1px solid var(--border-subtle)',animation:'pulse-orb 2s ease-in-out infinite'}} />
            ))}
          </div>
        )}

        {!loading && dbView === 'gallery' && (
          <div className="gallery-grid">
            {filtered.map(p => <GalleryCard key={p.id} practical={p} onOpen={openPractical} />)}
            {filtered.length === 0 && <p style={{color:'var(--text-muted)',gridColumn:'1/-1',padding:'40px 0',textAlign:'center'}}>No practicals match your search.</p>}
          </div>
        )}

        {!loading && dbView === 'table' && (
          <div className="table-wrap">
            <table className="data-table">
              <thead>
                <tr><th>Practical</th><th>Category</th><th>Tags</th><th>Script</th><th>Status</th><th>Open</th></tr>
              </thead>
              <tbody>
                {filtered.map(p => (
                  <tr key={p.id} onClick={() => openPractical(p)}>
                    <td style={{fontWeight:600}}>P{p.id}: {p.short_title}</td>
                    <td><span className="tag tag-blue">{p.category}</span></td>
                    <td>{p.tags?.slice(0,2).map(t => <span key={t} className="tag tag-gray" style={{marginRight:4}}>{t}</span>)}</td>
                    <td><code>{p.py_file}</code></td>
                    <td><span className="tag tag-green"><CheckCircle2 size={11} /> Verified</span></td>
                    <td><button className="action-btn" onClick={e=>{e.stopPropagation();openPractical(p)}}>Open</button></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </section>
  )
}

function GalleryCard({ practical: p, onOpen }) {
  const ICONS = [Database, Search, Filter, Shield, GitBranch, PieChart, Layers, Activity, Cpu, Zap]
  const CardIcon = ICONS[(p.id - 1) % ICONS.length] || Activity
  
  const GLOW_RGBS = [
    '74, 155, 224', '133, 91, 230', '57, 177, 131', '214, 73, 85', '229, 157, 53',
    '46, 170, 220', '94, 106, 210', '16, 185, 129', '244, 63, 94', '245, 158, 11'
  ]
  const glowRgb = GLOW_RGBS[(p.id - 1) % GLOW_RGBS.length]
  
  return (
    <div className="gallery-card" onClick={() => onOpen(p)} role="button" tabIndex={0} onKeyDown={e => e.key==='Enter' && onOpen(p)}>
      <div className="card-cover tech-pattern-bg" style={{ '--glow-rgb': glowRgb, borderBottom: '1px solid var(--border-subtle)' }}>
        <div className="card-cover-num">Practical {p.id} · {p.category}</div>
        <div className="card-cover-icon" style={{ color: `rgb(${glowRgb})`, borderColor: `rgba(${glowRgb}, 0.3)`, background: `rgba(${glowRgb}, 0.1)` }}>
          <CardIcon size={22} />
        </div>
      </div>
      <div className="card-body">
        <div className="card-head-row">
          <span className="card-module">Practical {p.id}</span>
          <span className="card-verified"><CheckCircle2 size={12} /> Verified</span>
        </div>
        <h3 className="card-title">{p.title.replace(/^Practical \d+:\s*/, '')}</h3>
        <p className="card-desc">{p.learning?.concept_summary?.slice(0,130)}...</p>
        <div className="card-tags">
          {p.tags?.slice(0,3).map(t => <span key={t} className="tag tag-gray">{t}</span>)}
        </div>
      </div>
    </div>
  )
}
