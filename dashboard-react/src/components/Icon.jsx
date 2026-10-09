import { Layers, Zap, Database, GitBranch, Activity, Cpu, BarChart2, Shield, Scale, Network } from 'lucide-react'

// Icon registry used across components
export const ICON_MAP = {
  layers: Layers,
  zap: Zap,
  database: Database,
  workflow: GitBranch,
  activity: Activity,
  cpu: Cpu,
  'bar-chart-2': BarChart2,
  shield: Shield,
  scale: Scale,
  network: Network,
}

export function Icon({ name, size = 16, className = '', style = {} }) {
  const Comp = ICON_MAP[name] || Activity
  return <Comp size={size} className={className} style={style} />
}
