import { useEffect, useState } from 'react'
import { useLang } from '../i18n'
import { api } from '../api'

/* Einfaches Overlay: schließt per Backdrop-Klick oder Escape */
export function Modal({ title, onClose, children }) {
  useEffect(() => {
    const onKey = (e) => e.key === 'Escape' && onClose()
    document.addEventListener('keydown', onKey)
    return () => document.removeEventListener('keydown', onKey)
  }, [onClose])
  return (
    <div className="modal-backdrop" onMouseDown={(e) => e.target === e.currentTarget && onClose()}>
      <div className="modal" role="dialog" aria-modal="true" aria-label={title}>
        <div className="modal-head">
          <h2>{title}</h2>
          <button className="btn btn-ghost" onClick={onClose} aria-label="Schließen">✕</button>
        </div>
        {children}
      </div>
    </div>
  )
}

export const STATUS_LABELS = {
  draft: 'Entwurf',
  in_review: 'Im Review',
  approved: 'Freigegeben',
  rejected: 'Abgelehnt',
  deactivated: 'Deaktiviert',
}

export const PLATFORM_LABELS = { juniper: 'Juniper', checkpoint: 'Check Point', aci: 'ACI' }

export function StatusBadge({ status }) {
  const { t } = useLang()
  return <span className={`badge status-${status}`}>{t(STATUS_LABELS[status] || status)}</span>
}

export function PlatformBadges({ platforms }) {
  return (
    <span className="platforms">
      {(platforms || []).map((p) => (
        <span key={p} className={`badge platform-${p}`}>{PLATFORM_LABELS[p] || p}</span>
      ))}
    </span>
  )
}

/* Komponenten einer Regel: Name, eingefärbt nach Typ (juniper/checkpoint/aci) */
export function ComponentBadges({ components }) {
  return (
    <span className="platforms">
      {(components || []).map((c) => (
        <span key={c.id || c.name || c} className={`badge platform-${c.type || 'unknown'}`}
          title={c.type ? PLATFORM_LABELS[c.type] : undefined}>
          {c.name || c}
        </span>
      ))}
    </span>
  )
}

/* Adress-Eintrag {ip, alias} als Text: "alias (ip)" oder nur "ip" */
export function formatEntry(entry) {
  if (typeof entry === 'string') return entry
  const ip = (entry.ip || '').trim()
  const alias = (entry.alias || '').trim()
  return alias ? `${alias} (${ip})` : ip
}

export function AddressList({ entries, max = 0 }) {
  const list = entries || []
  const shown = max > 0 ? list.slice(0, max) : list
  return (
    <span className="addr-entries">
      {shown.map((e, i) => (
        <div key={i}>
          <code>{typeof e === 'string' ? e : e.ip}</code>
          {e.alias ? <span className="muted"> {e.alias}</span> : null}
        </div>
      ))}
      {max > 0 && list.length > max ? <div className="muted">… +{list.length - max}</div> : null}
    </span>
  )
}

export function ServiceList({ services }) {
  return (
    <span>
      {(services || []).map((s, i) => (
        <code key={i} className="svc">
          {s.protocol}{s.port ? `/${s.port}` : ''}
        </code>
      ))}
    </span>
  )
}

/* Einfaches Syntax-Highlighting für die Export-Vorschau */
function tokenize(line, fmt) {
  if (fmt === 'juniper') {
    if (line.startsWith('#')) return [['comment', line]]
    return line.split(/(\s+)/).map((word) => {
      if (['set', 'match', 'then', 'permit', 'deny'].includes(word)) return ['keyword', word]
      if (/^\d+$/.test(word) || /^[\d.:/]+$/.test(word)) return ['number', word]
      return ['plain', word]
    })
  }
  if (fmt === 'checkpoint-cli') {
    if (line.startsWith('#')) return [['comment', line]]
    return line.split(/(\s+)/).map((word) => {
      if (['mgmt_cli', 'add', 'publish', 'login', 'logout', 'set'].includes(word)) return ['keyword', word]
      if (word.startsWith('"')) return ['string', word]
      return ['plain', word]
    })
  }
  // JSON/YAML
  return line.split(/("[^"]*"|'[^']*')/).map((part) => {
    if (/^["'].*["']$/.test(part)) return ['string', part]
    if (/^\s*[\w-]+:/.test(part)) return ['key', part]
    return ['plain', part]
  })
}

export function Highlighted({ text, fmt }) {
  return (
    <pre className="code-preview">
      {text.split('\n').map((line, i) => (
        <div key={i} className="code-line">
          {tokenize(line, fmt).map(([cls, word], j) => (
            <span key={j} className={`tok-${cls}`}>{word}</span>
          ))}
        </div>
      ))}
    </pre>
  )
}


/* Löst eine Zonen-Referenz (ID oder Name) auf die Anzeige "ID-Name" auf.
   Zieht die Zonenliste einmal und liefert eine Label-Funktion. */
export function useZoneLabels() {
  const [map, setMap] = useState({})
  useEffect(() => {
    api.zones().then((zones) => {
      const m = {}
      zones.forEach((z) => {
        const label = z.code ? `${z.code}-${z.name}` : z.name
        m[(z.code || '').toUpperCase()] = label
        m[z.name.toUpperCase()] = label
      })
      setMap(m)
    }).catch(() => {})
  }, [])
  return (ref) => map[(ref || '').toUpperCase()] || ref || '–'
}
