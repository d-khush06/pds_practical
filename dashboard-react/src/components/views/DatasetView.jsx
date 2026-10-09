import { useRef, useEffect } from 'react'
import { Bar, Doughnut } from 'react-chartjs-2'
import { Chart as ChartJS, CategoryScale, LinearScale, BarElement, ArcElement, Tooltip, Legend } from 'chart.js'
import { DATASET_DONUT, DATASET_BAR } from '../../data/chartConfigs'
import { getChartBaseOptions } from '../../utils/helpers'
import { useApp } from '../../context/AppContext'
import { Database, Shield, Activity, CheckCircle2 } from 'lucide-react'

ChartJS.register(CategoryScale, LinearScale, BarElement, ArcElement, Tooltip, Legend)

export default function DatasetView() {
  const { theme } = useApp()
  const isDark = theme === 'dark'
  const baseOpts = getChartBaseOptions(isDark)
  const donutOpts = { ...baseOpts, scales: undefined, plugins: { ...baseOpts.plugins, legend: { position:'bottom', labels:{color:isDark?'#8b9ec0':'#3d4f80',padding:14,font:{size:12}} } } }
  const barOpts = { ...baseOpts, indexAxis:'y', plugins: { ...baseOpts.plugins, legend:{display:false} } }

  return (
    <section className="view">
      <div className="hero-cover cover-dataset">
        <div className="cover-content">
          <div className="hero-badge">Dataset Intelligence Profile</div>
          <h1 className="hero-title">cj.log — Honeypot Dataset</h1>
          <p className="hero-sub">Real web attack traffic from January 2023 honeypot sensors</p>
        </div>
      </div>
      <div className="page-body">
        <div className="stats-grid">
          {[
            { icon:<Database size={20}/>, cls:'stat-blue', label:'FILE SIZE', val:'215.40 MB', sub:'225,867,389 bytes raw' },
            { icon:<Activity size={20}/>, cls:'stat-purple', label:'TOTAL RECORDS', val:'2,062,365', sub:'JSON array lines' },
            { icon:<Shield size={20}/>, cls:'stat-rose', label:'ATTACK EVENTS', val:'15,896', sub:'31.8% of sampled data' },
            { icon:<CheckCircle2 size={20}/>, cls:'stat-green', label:'JSON VALIDITY', val:'99.99%', sub:'8-field arrays', accent:true },
          ].map((s,i) => (
            <div key={i} className="stat-card">
              <div className={`stat-icon ${s.cls}`}>{s.icon}</div>
              <div className="stat-info">
                <span className="stat-label">{s.label}</span>
                <span className={`stat-value${s.accent?' accent':''}`}>{s.val}</span>
                <span className="stat-sub">{s.sub}</span>
              </div>
            </div>
          ))}
        </div>

        <div className="section-title">Schema Field Reference</div>
        <div className="table-wrap" style={{marginBottom:28}}>
          <table className="data-table">
            <thead>
              <tr><th>Index</th><th>Field Name</th><th>Data Type</th><th>Missing %</th><th>Analytical Purpose</th></tr>
            </thead>
            <tbody>
              {[
                ['0','param_key','str / null','81.64%','high','HTTP parameter name, shell command (ls, ps, cmd)'],
                ['1','param_value','str / null','81.64%','high','Payload value — SQLi, path traversals, XSS scripts'],
                ['2','timestamp','datetime','0.00%','low','ISO 8601 event time for temporal analysis'],
                ['3','client_ip','str','0.00%','low','Source IP — geolocation, frequency profiling'],
                ['4','client_port','int','0.00%','low','Ephemeral source port number'],
                ['5','user_agent','str / null','4.64%','med','Browser / bot / scanner identification string'],
                ['6','accept_language','str / null','51.76%','high','Language header — None for headless scripts'],
                ['7','target_ip','str / null','74.37%','high','Honeypot server destination IP address'],
              ].map(([idx,name,dtype,miss,lvl,note]) => (
                <tr key={idx}>
                  <td><code>{idx}</code></td>
                  <td><strong>{name}</strong></td>
                  <td><span className={`tag tag-${dtype.includes('null')?'blue':'purple'}`}>{dtype}</span></td>
                  <td><span className={`missing-${lvl}`}>{miss}</span></td>
                  <td>{note}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        <div className="section-title">Attack Distribution Overview</div>
        <div className="two-col">
          <div className="chart-card">
            <div className="chart-card-title">Attack vs Benign Split</div>
            <div className="chart-container" style={{height:260}}>
              <Doughnut key={`donut-${isDark}`} data={DATASET_DONUT} options={donutOpts} />
            </div>
          </div>
          <div className="chart-card">
            <div className="chart-card-title">Attack Category Breakdown</div>
            <div className="chart-container" style={{height:260}}>
              <Bar key={`dbar-${isDark}`} data={DATASET_BAR} options={barOpts} />
            </div>
          </div>
        </div>
      </div>
    </section>
  )
}
