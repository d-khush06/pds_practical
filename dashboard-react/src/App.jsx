import { AppProvider, useApp } from './context/AppContext'
import Sidebar from './components/Sidebar'
import Topbar from './components/Topbar'
import DashboardView from './components/views/DashboardView'
import PracticalDetailView from './components/views/PracticalDetailView'
import SandboxView from './components/views/SandboxView'
import DatasetView from './components/views/DatasetView'
import PipelineView from './components/views/PipelineView'
import Lightbox from './components/Lightbox'

function AppInner() {
  const { activeView, theme } = useApp()

  return (
    <div className={`workspace theme-${theme}`}>
      {/* Ambient background */}
      <div className="ambient-bg">
        <div className="orb orb-1" />
        <div className="orb orb-2" />
        <div className="orb orb-3" />
        <div className="grid-pattern" />
      </div>

      <Sidebar />

      <main className="main-content">
        <Topbar />
        <div className="canvas" id="main-canvas">
          {activeView === 'dashboard'  && <DashboardView />}
          {activeView === 'practical'  && <PracticalDetailView />}
          {activeView === 'sandbox'    && <SandboxView />}
          {activeView === 'dataset'    && <DatasetView />}
          {activeView === 'pipeline'   && <PipelineView />}
        </div>
      </main>

      <Lightbox />
    </div>
  )
}

export default function App() {
  return (
    <AppProvider>
      <AppInner />
    </AppProvider>
  )
}
