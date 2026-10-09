import { useState, useEffect } from 'react'
import { useApp } from '../../context/AppContext'
import { STAGE_COLORS, STAGE_OUTPUTS } from '../../data/chartConfigs'
import { CheckCircle2, GitBranch, Activity } from 'lucide-react'

export default function PipelineView() {
  const { openPractical } = useApp()
  const [data, setData] = useState([])

  useEffect(() => {
    fetch('../web_data.json')
      .then(r => r.json())
      .then(setData)
      .catch(() => {})
  }, [])

  return (
    <section className="view">
      <div className="hero-cover cover-pipeline">
        <div className="cover-content">
          <div className="hero-badge">End-to-End Data Science Workflow</div>
          <h1 className="hero-title">Pipeline Flow</h1>
          <p className="hero-sub">10-stage pipeline from raw JSON logs to production threat classifier</p>
        </div>
      </div>
      <div className="page-body">
        <div className="callout callout-blue">
          <GitBranch size={18} style={{color:'#60a5fa',flexShrink:0}} />
          <div>Click any stage to open its full detail view with code, charts, and learning materials.</div>
        </div>

        <div className="pipeline-stages">
          {data.map((p, i) => {
            const color = STAGE_COLORS[(p.id-1) % STAGE_COLORS.length]
            return (
              <div key={p.id} className="pipeline-stage" onClick={() => openPractical(p)}>
                <div className="stage-connector">
                  <div className="stage-num" style={{background: color, boxShadow: `0 0 12px ${color}55`}}>
                    {p.id}
                  </div>
                  {i < data.length - 1 && <div className="stage-line" />}
                </div>
                <div className="stage-card">
                  <div className="stage-top">
                    <div className="stage-icon-badge" style={{background:`${color}20`,border:`1px solid ${color}30`}}>
                      <Activity size={16} style={{color}} />
                    </div>
                    <span className="stage-cat">{p.category}</span>
                  </div>
                  <div className="stage-title">Practical {p.id}: {p.short_title}</div>
                  <div className="stage-desc">{p.learning?.concept_summary?.slice(0,130)}...</div>
                  <div className="stage-tags">
                    {p.tags?.slice(0,2).map(t => <span key={t} className="tag tag-gray">{t}</span>)}
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
