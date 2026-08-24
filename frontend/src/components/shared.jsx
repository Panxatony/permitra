import { Link } from 'react-router-dom'
import { useEffect, useState } from 'react'
import { createPortal } from 'react-dom'
import { useLang } from '../i18n'
import { api } from '../api'
import { HelpBody, helpSection, helpTitle } from '../helpContent'

/* Simple overlay: closes on backdrop click or Escape */
export function Modal({ title, onClose, children, wide = false }) {
  const { t } = useLang()
  useEffect(() => {
    const onKey = (e) => e.key === 'Escape' && onClose()
    document.addEventListener('keydown', onKey)
    return () => document.removeEventListener('keydown', onKey)
  }, [onClose])
  /* Rendered into <body> rather than where it was opened. A dialogue is not
     part of the sentence that opened it: inline, it inherits the typography of
     its trigger's surroundings, so a "?" inside a heading rendered its whole
     explanation in bold. The backdrop is position: fixed, so nothing about the
     layout changes - only what it inherits and which stacking context it is in. */
  return createPortal(
    <div className="modal-backdrop" onMouseDown={(e) => e.target === e.currentTarget && onClose()}>
      <div className={`modal${wide ? ' modal-wide' : ''}`} role="dialog"
        aria-modal="true" aria-label={title}>
        <div className="modal-head">
          <h2>{title}</h2>
          <button className="btn btn-ghost" onClick={onClose} aria-label={t('Close')}>✕</button>
        </div>
        {children}
      </div>
    </div>,
    document.body,
  )
}

/* In workflow order. The keys are English like every other dictionary key -
   with German ones the labels stayed German on an English instance, because a
   key that is not in the dictionary falls back to itself. */
/* A "?" that lands on the paragraph explaining the feature it sits next to.
   Help that has to be searched for answers a different, easier question than
   the one being asked. */
/* Explains a feature over the page you are standing on.

   It used to navigate to /help#topic, which answered the question but moved you
   to the help page to do it - and closing the overlay left you there instead of
   back where you asked. The explanation belongs on top of the thing being
   explained. Falls back to the link when the topic is unknown, so a typo in a
   topic name is a working link rather than a dead control. */
export function HelpLink({ topic, label }) {
  const { lang } = useLang()
  const [open, setOpen] = useState(false)
  const section = helpSection(topic)

  if (!section) {
    return (
      <Link to={`/help#${topic}`} className="help-link"
        title={label} aria-label={label}>?</Link>
    )
  }
  return (
    <>
      <button type="button" className="help-link" title={label} aria-label={label}
        onClick={(e) => { e.preventDefault(); e.stopPropagation(); setOpen(true) }}>?</button>
      {open && (
        <Modal title={helpTitle(section, lang)} onClose={() => setOpen(false)}>
          <HelpBody section={section} />
        </Modal>
      )}
    </>
  )
}

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
/* A stored zone reference is either the zone's code or its name, in whichever
   case it was typed. Resolving that to the zone lives here once: the label and
   the protection-level colouring both need the same rule, and two copies of it
   is how they drift apart. */
export function useZoneMap() {
  const [map, setMap] = useState({})
  useEffect(() => {
    api.zones().then((zones) => {
      const m = {}
      zones.forEach((z) => {
        // Only a real code, or every zone without one would claim the "" key
        // and the last of them would answer for all the others.
        if (z.code) m[z.code.toUpperCase()] = z
        m[z.name.toUpperCase()] = z
      })
      setMap(m)
    }).catch(() => {})
  }, [])
  return (ref) => map[(ref || '').toUpperCase()] || null
}

export function useZoneLabels() {
  const zoneOf = useZoneMap()
  return (ref) => {
    const zone = zoneOf(ref)
    if (!zone) return ref || '–'
    return zone.code ? `${zone.code}-${zone.name}` : zone.name
  }
}

/* Protection level as colour, the same three steps as the security zones page:
   normal is unremarkable, high is amber, very high is red. A zone that cannot
   be resolved reads as normal rather than inventing a fourth state. */
export const SB_BADGE = {
  normal: 'status-draft',
  high: 'status-in_review',
  'very high': 'status-rejected',
}

export function zoneBadgeClass(zone) {
  return SB_BADGE[zone?.protection_level] || 'status-draft'
}
