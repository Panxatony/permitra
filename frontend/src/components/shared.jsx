import { useEffect, useState } from 'react'
import { useLang } from '../i18n'
import { api } from '../api'

/* Simple overlay: closes on backdrop click or Escape */
export function Modal({ title, onClose, children }) {
  const { t } = useLang()
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
          <button className="btn btn-ghost" onClick={onClose} aria-label={t('Close')}>✕</button>
        </div>
        {children}
      </div>
    </div>
  )
}

/* In workflow order. The keys are English like every other dictionary key -
   with German ones the labels stayed German on an English instance, because a
   key that is not in the dictionary falls back to itself. */
export const STATUS_LABELS = {
  draft: 'Draft',
  in_review: 'In review',
  approved: 'Approved',
  active: 'Active',
  rejected: 'Rejected',
  deactivated: 'Deactivated',
  deleted: 'Deleted',
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

/* Components of a rule: name, colored by type (juniper/checkpoint/aci) */
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

/* Address entry {ip, alias} as text: "alias (ip)" or just "ip" */
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

/* Simple syntax highlighting for the export preview */
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


/* Resolves a zone reference (ID or name) to the display form "ID-name".
   Fetches the zone list once and returns a label function. */
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
