import { useApp } from '../context/AppContext'
import { X } from 'lucide-react'

export default function Lightbox() {
  const { lightbox, closeLightbox } = useApp()
  if (!lightbox) return null

  return (
    <div className="lightbox" onClick={closeLightbox}>
      <div className="lb-backdrop" />
      <div className="lb-inner" onClick={e => e.stopPropagation()}>
        <button className="lb-close" onClick={closeLightbox}><X size={16} /></button>
        <img src={lightbox.src} alt={lightbox.caption} />
        {lightbox.caption && <div className="lb-caption">{lightbox.caption}</div>}
      </div>
    </div>
  )
}
