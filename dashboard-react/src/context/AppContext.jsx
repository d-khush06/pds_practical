// Context for app state — theme, active view, current practical
import { createContext, useContext, useState, useEffect } from 'react'

const AppContext = createContext(null)

export function AppProvider({ children }) {
  const [theme, setThemeState] = useState(() => localStorage.getItem('pds_theme') || 'dark')
  const [activeView, setActiveView] = useState('dashboard')
  const [currentPractical, setCurrentPractical] = useState(null)
  const [searchQuery, setSearchQuery] = useState('')
  const [activeCategory, setActiveCategory] = useState('all')
  const [dbView, setDbView] = useState('gallery') // 'gallery' | 'table'
  const [lightbox, setLightbox] = useState(null)  // { src, caption }

  useEffect(() => {
    document.documentElement.className = `theme-${theme}`
    document.body.className = `theme-${theme}`
    localStorage.setItem('pds_theme', theme)
  }, [theme])

  const toggleTheme = () => setThemeState(t => t === 'dark' ? 'light' : 'dark')

  const openPractical = (practical) => {
    setCurrentPractical(practical)
    setActiveView('practical')
  }

  const openLightbox = (src, caption) => setLightbox({ src, caption })
  const closeLightbox = () => setLightbox(null)

  return (
    <AppContext.Provider value={{
      theme, toggleTheme,
      activeView, setActiveView,
      currentPractical, openPractical,
      searchQuery, setSearchQuery,
      activeCategory, setActiveCategory,
      dbView, setDbView,
      lightbox, openLightbox, closeLightbox,
    }}>
      {children}
    </AppContext.Provider>
  )
}

export const useApp = () => useContext(AppContext)
