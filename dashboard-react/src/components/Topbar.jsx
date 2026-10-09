import { useApp } from '../context/AppContext'
import { Terminal, Sun, Moon, CheckCircle2, ChevronRight, Menu } from 'lucide-react'
import { useState } from 'react'

const VIEW_LABELS = {
  dashboard: 'Dashboard',
  practical: 'Practical Detail',
  sandbox: 'Live Threat Detector',
  dataset: 'Dataset Profile',
  pipeline: 'Pipeline Flow',
}

export default function Topbar() {
  const { activeView, currentPractical, theme, toggleTheme } = useApp()
  const [sidebarOpen, setSidebarOpen] = useState(true)

  const crumb = activeView === 'practical' && currentPractical
    ? `Practical ${currentPractical.id}`
    : VIEW_LABELS[activeView] || 'Dashboard'

  const handleTerminalClick = () => {
    // Dispatch to switch to terminal tab — handled by PracticalDetailView
    window.dispatchEvent(new CustomEvent('switch-to-terminal'))
  }

  return (
    <header className="topbar">
      <div className="topbar-left">
        <button
          className="icon-btn"
          onClick={() => {
            const s = document.querySelector('.sidebar')
            s?.classList.toggle('collapsed')
          }}
          title="Toggle sidebar"
        >
          <Menu size={15} />
        </button>
        <div className="breadcrumbs">
          <span className="crumb">Python for Data Science</span>
          <ChevronRight size={12} color="var(--text-muted)" />
          <span className="crumb active">{crumb}</span>
        </div>
      </div>
      <div className="topbar-right">
        <div className="topbar-status">
          <CheckCircle2 size={12} color="#10b981" />
          <span>10/10 Complete</span>
        </div>
        {activeView === 'practical' && (
          <button className="topbar-btn" onClick={handleTerminalClick}>
            <Terminal size={13} />
            Terminal
          </button>
        )}
        <button className="icon-btn" onClick={toggleTheme} title="Toggle theme">
          {theme === 'dark' ? <Sun size={15} /> : <Moon size={15} />}
        </button>
      </div>
    </header>
  )
}
