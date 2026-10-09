import { useState } from 'react'
import { useApp } from '../context/AppContext'
import { Layers, Zap, Database, GitBranch, Search, Sun, Moon, TerminalSquare, Command } from 'lucide-react'

const NAV_ITEMS = [
  { id: 'dashboard', label: 'Dashboard', icon: Layers, badge: '10' },
  { id: 'sandbox',   label: 'AI Log & Threat Analyzer', icon: Zap, badge: 'AI', badgeCls: 'live' },
  { id: 'dataset',   label: 'Dataset Profile', icon: Database },
  { id: 'pipeline',  label: 'Pipeline Flow', icon: GitBranch },
]

export default function Sidebar({ practicals }) {
  const { activeView, setActiveView, theme, toggleTheme, searchQuery, setSearchQuery, openPractical } = useApp()

  const handleNav = (id) => {
    setActiveView(id)
  }

  return (
    <aside className="sidebar">
      {/* Header */}
      <div className="sidebar-header">
        <div className="brand">
          <div className="brand-icon">
            <Command size={16} strokeWidth={2.5} />
          </div>
          <div className="brand-text">
            <span className="brand-name">PDS PRACTICALS</span>
            <span className="brand-sub">B.E. Comp Sci · 5th Sem</span>
          </div>
        </div>
      </div>

      {/* Search */}
      <div className="sidebar-search">
        <Search size={14} color="var(--text-muted)" />
        <input
          type="text"
          placeholder="Search practicals..."
          value={searchQuery}
          onChange={e => setSearchQuery(e.target.value)}
          autoComplete="off"
        />
      </div>

      {/* Main Nav */}
      <div className="sidebar-section">
        <div className="section-label">NAVIGATION</div>
        <nav className="nav-menu">
          {NAV_ITEMS.map(item => (
            <button
              key={item.id}
              className={`nav-item ${activeView === item.id ? 'active' : ''}`}
              onClick={() => handleNav(item.id)}
            >
              <item.icon size={15} style={{ flexShrink: 0 }} />
              <span className="flex-1">{item.label}</span>
              {item.badge && <span className={`nav-badge ${item.badgeCls || ''}`}>{item.badge}</span>}
            </button>
          ))}
        </nav>
      </div>

      {/* Practicals Nav — populated dynamically */}
      <div className="sidebar-section scroll">
        <div className="section-label">PRACTICALS 1 — 10</div>
        <nav className="nav-menu" id="practicals-nav-list">
          {/* Injected by DashboardView after data loads */}
          <PracticalNavItems />
        </nav>
      </div>

      {/* Footer */}
      <div className="sidebar-footer">
        <div className="status-pill">
          <div className="pulse-dot" />
          <span>cj.log · 2,062,365 records</span>
        </div>
        <button className="theme-btn" onClick={toggleTheme}>
          {theme === 'dark' ? <Sun size={14} /> : <Moon size={14} />}
          <span>{theme === 'dark' ? 'Light Mode' : 'Dark Mode'}</span>
        </button>
      </div>
    </aside>
  )
}

// Renders the list of practicals in the sidebar nav
function PracticalNavItems() {
  const { activeView, currentPractical, openPractical } = useApp()
  const [data, setData] = useState(null)

  // Fetch data on mount
  useState(() => {
    fetch('../web_data.json')
      .then(r => r.json())
      .then(setData)
      .catch(() => {})
  })

  if (!data) {
    return Array.from({length:10},(_,i) => (
      <div key={i} style={{height:32,margin:'2px 8px',borderRadius:6,background:'var(--border-subtle)',animation:'pulse-orb 2s ease-in-out infinite'}} />
    ))
  }

  return data.map(p => (
    <button
      key={p.id}
      className={`nav-item ${activeView === 'practical' && currentPractical?.id === p.id ? 'active' : ''}`}
      onClick={() => openPractical(p)}
    >
      <div style={{
        width: 20, height: 20, borderRadius: 4, background: 'var(--bg-hover)', 
        display: 'flex', alignItems: 'center', justifyContent: 'center', 
        fontSize: '10px', fontWeight: 'bold', color: 'var(--text-base)', flexShrink: 0
      }}>
        {p.id}
      </div>
      <span className="flex-1" style={{fontSize:'12.5px', paddingLeft: 4}}>{p.short_title}</span>
    </button>
  ))
}
