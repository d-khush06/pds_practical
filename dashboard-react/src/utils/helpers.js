// Utility: escape HTML for safe rendering
export function escHtml(s) {
  if (!s) return ''
  return String(s)
    .replace(/&/g,'&amp;')
    .replace(/</g,'&lt;')
    .replace(/>/g,'&gt;')
    .replace(/"/g,'&quot;')
}

// Utility: deep merge objects (for Chart.js options)
export function deepMerge(target, source) {
  const out = { ...target }
  for (const key in source) {
    if (source[key] && typeof source[key] === 'object' && !Array.isArray(source[key])) {
      out[key] = deepMerge(target[key] || {}, source[key])
    } else {
      out[key] = source[key]
    }
  }
  return out
}

// Utility: Shannon entropy calculation
export function calcEntropy(s) {
  if (!s || s === 'none') return 0
  const len = s.length
  if (len <= 1) return 0
  const freq = {}
  for (const c of s) freq[c] = (freq[c] || 0) + 1
  return parseFloat(
    Object.values(freq).reduce((h, f) => { const p = f/len; return h - p * Math.log2(p) }, 0).toFixed(3)
  )
}

// Utility: get chart base options for current theme
export function getChartBaseOptions(isDark) {
  const textColor = isDark ? '#8b9ec0' : '#3d4f80'
  const gridColor = isDark ? 'rgba(255,255,255,0.06)' : 'rgba(0,0,0,0.08)'
  return {
    responsive: true,
    maintainAspectRatio: false,
    animation: { duration: 600, easing: 'easeInOutQuart' },
    plugins: {
      legend: {
        labels: { color: textColor, padding: 16, font: { size: 12, family: 'Inter' } }
      },
      tooltip: {
        backgroundColor: 'rgba(6,12,28,0.95)',
        titleColor: '#f0f4ff',
        bodyColor: '#8b9ec0',
        padding: 12, borderColor: 'rgba(0,210,255,0.3)', borderWidth: 1, cornerRadius: 8
      },
    },
    scales: {
      x: { grid: { color: gridColor }, ticks: { color: textColor }, border: { display: false } },
      y: { grid: { color: gridColor }, ticks: { color: textColor }, border: { display: false } },
    }
  }
}
