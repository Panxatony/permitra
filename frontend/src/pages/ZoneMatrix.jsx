import { useCallback, useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { api, getUser } from '../api'
import { Modal } from '../components/shared'
import { useLang } from '../i18n'

const SB_BADGE = { normal: 'status-draft', 'hoch': 'status-in_review', 'sehr hoch': 'status-rejected' }
const zoneLabel = (z) => (z.code ? `${z.code}-${z.name}` : z.name)
const zref = (z) => z.code || z.name
const SB_LABEL = (z) => `${z.schutzbedarf || 'normal'} (C:${z.cia_c || 'normal'} I:${z.cia_i || 'normal'} V:${z.cia_a || 'normal'})`

function cellLabel(p) {
  if (!p) return ''
  const base = p.policy === 'allow_only' ? 'Allow' : 'Block'
  return `${base}${p.temporary ? ' (Temp)' : ''}`
}

const FW_COLORS = {
  juniper: { fill: '#dbe9ff', stroke: '#1c53b8' },
  checkpoint: { fill: '#ffe4e0', stroke: '#b83a1c' },
}

/* Zonenplan-Exporte (Issue #15): SVG mit einkopierten Stilen -> PNG/Druck-PDF,
   Mermaid über den Backend-Endpunkt (für Wikis/GitLab, die Mermaid rendern). */
const SVG_STYLE_PROPS = ['fill', 'stroke', 'stroke-width', 'stroke-dasharray', 'opacity',
  'font-size', 'font-weight', 'font-family', 'text-anchor', 'font-style']

function inlinedPlanSvg() {
  const svg = document.getElementById('zone-plan-svg')
  if (!svg) return null
  const clone = svg.cloneNode(true)
  const srcEls = [svg, ...svg.querySelectorAll('*')]
  const dstEls = [clone, ...clone.querySelectorAll('*')]
  srcEls.forEach((el, i) => {
    const computed = window.getComputedStyle(el)
    const style = SVG_STYLE_PROPS.map((p) => `${p}:${computed.getPropertyValue(p)}`).join(';')
    dstEls[i].setAttribute('style', style)
  })
  clone.setAttribute('xmlns', 'http://www.w3.org/2000/svg')
  const [, , w, h] = (svg.getAttribute('viewBox') || '0 0 960 600').split(' ').map(Number)
  clone.setAttribute('width', w)
  clone.setAttribute('height', h)
  return { markup: new XMLSerializer().serializeToString(clone), w, h }
}

function planTitle() {
  return `Zonenplan (bereinigter Netzplan) · BSI NET.1.1 / NET.3.2 · Stand ${new Date().toLocaleString('de-DE')} · generiert von Permitra`
}

function exportPlanPng() {
  const plan = inlinedPlanSvg()
  if (!plan) return
  const scale = 2
  const img = new Image()
  img.onload = () => {
    const canvas = document.createElement('canvas')
    canvas.width = plan.w * scale
    canvas.height = plan.h * scale + 60
    const ctx = canvas.getContext('2d')
    ctx.fillStyle = '#ffffff'
    ctx.fillRect(0, 0, canvas.width, canvas.height)
    ctx.fillStyle = '#1d2733'
    ctx.font = 'bold 22px sans-serif'
    ctx.fillText(planTitle(), 20, 38)
    ctx.drawImage(img, 0, 60, plan.w * scale, plan.h * scale)
    canvas.toBlob((blob) => {
      const a = document.createElement('a')
      a.href = URL.createObjectURL(blob)
      a.download = `permitra-zonenplan-${new Date().toISOString().slice(0, 10)}.png`
      a.click()
    })
  }
  img.src = 'data:image/svg+xml;charset=utf-8,' + encodeURIComponent(plan.markup)
}

function exportPlanPdf() {
  const plan = inlinedPlanSvg()
  if (!plan) return
  const win = window.open('', '_blank')
  win.document.write(`<!DOCTYPE html><html><head><title>Permitra Zonenplan</title>
    <style>@page { size: A4 landscape; margin: 12mm; } body { font-family: sans-serif; }
    h1 { font-size: 14px; } svg { width: 100%; height: auto; }</style></head>
    <body><h1>${planTitle()}</h1>${plan.markup}
    <script>window.onload = () => window.print()</scr` + `ipt></body></html>`)
  win.document.close()
}

async function exportPlanMermaid() {
  const res = await fetch('/api/zones/plan/mermaid', {
    headers: { Authorization: `Bearer ${localStorage.getItem('permitra_token') || ''}` },
  })
  const text = await res.text()
  const a = document.createElement('a')
  a.href = URL.createObjectURL(new Blob([text], { type: 'text/plain' }))
  a.download = 'permitra-zonenplan.mmd'
  a.click()
}

/* Nord-Süd-Sicht nach BSI P-A-P: externe Zonen (Nord) – P-A-P-Ebene mit den
   Firewall-Clustern und DMZ-/Transferzonen – interne Zonen (Süd). */
function ZoneReachability({ overview }) {
  // Hover auf Zone/Firewall hebt alle zugehörigen Verbindungen hervor
  const [hover, setHover] = useState(null)
  if (!overview || !overview.zones.length) return null
  const zones = overview.zones
  const firewalls = {}
  zones.forEach((z) => z.firewalls.forEach((f) => { firewalls[f.id] = f }))
  const fwList = Object.values(firewalls).sort(
    (a, b) => (a.ns_tier ?? 100) - (b.ns_tier ?? 100) || a.name.localeCompare(b.name))

  const byLevel = (lvl) => zones.filter((z) => (z.pap_level || 'intern') === lvl)
  const chunk = (arr, n = 6) => {
    const out = []
    for (let i = 0; i < arr.length; i += n) out.push(arr.slice(i, i + n))
    return out
  }

  const W = 960, BOX_W = 128, BOX_H = 44, ROW_H = 76, LABEL_H = 26, PAD = 10
  const zonePos = {}, fwPos = {}
  const bands = []
  let y = 0

  const layoutZoneRows = (zoneList, startY) => {
    const rows = chunk(zoneList)
    rows.forEach((row, ri) => {
      row.forEach((z, j) => {
        zonePos[z.name] = {
          x: 80 + (W - 160) * ((j + 0.5) / row.length),
          y: startY + ri * ROW_H + ROW_H / 2,
        }
      })
    })
    return rows.length * ROW_H
  }

  const layoutZoneRowsHeight = (list) => chunk(list).length * ROW_H

  // Firewall-x-Positionen vorab bestimmen (nur x nötig), damit die Zonen nach dem
  // "Schwerpunkt" ihrer Firewalls sortiert werden können -> weniger Überschneidungen
  const fwTiersPre = [...new Set(fwList.map((f) => f.ns_tier ?? 100))].sort((a, b) => a - b)
  const northPre = fwTiersPre.length > 1 ? fwList.filter((f) => (f.ns_tier ?? 100) === fwTiersPre[0]) : []
  const southPre = fwTiersPre.length > 1 ? fwList.filter((f) => (f.ns_tier ?? 100) !== fwTiersPre[0]) : fwList
  const fwX = {}
  const spreadX = (list) => list.forEach((f, i) => { fwX[f.id] = 110 + (W - 220) * ((i + 0.5) / list.length) })
  spreadX(northPre)
  spreadX(southPre)
  const sortByBarycenter = (list) => [...list].sort((a, b) => {
    const bary = (z) => {
      const xs = z.firewalls.map((f) => fwX[f.id]).filter((x) => x !== undefined)
      return xs.length ? xs.reduce((s, x) => s + x, 0) / xs.length : W / 2
    }
    return bary(a) - bary(b) || a.name.localeCompare(b.name)
  })

  // Band 1: Extern (Nord)
  const extern = sortByBarycenter(byLevel('extern'))
  bands.push({ key: 'extern', label: 'Extern (Nord) — Internet / Partner', y, h: LABEL_H + layoutZoneRowsHeight(extern) + PAD })
  layoutZoneRows(extern, y + LABEL_H)
  y += bands[0].h

  // Band 2: P-A-P-Ebene, geschichtet nach Nord-Süd-Ebene der Firewalls:
  // nördlichste FW-Gruppe (z.B. Provider) -> DMZ-/Transferzonen -> übrige FW-Cluster
  const pap = sortByBarycenter(byLevel('pap'))
  const northFws = northPre
  const southFws = southPre
  const northRowH = northFws.length ? ROW_H : 0
  const southRowH = southFws.length ? ROW_H : 0
  const papZonesH = layoutZoneRowsHeight(pap)
  const papH = LABEL_H + northRowH + papZonesH + southRowH + PAD
  bands.push({ key: 'pap', label: 'P-A-P-Ebene (BSI): Paketfilter – ALG – Paketfilter', y, h: papH })
  const placeFwRow = (list, rowY) => list.forEach((f, i) => {
    fwPos[f.id] = { x: 110 + (W - 220) * ((i + 0.5) / list.length), y: rowY + ROW_H / 2 }
  })
  placeFwRow(northFws, y + LABEL_H)
  layoutZoneRows(pap, y + LABEL_H + northRowH)
  placeFwRow(southFws, y + LABEL_H + northRowH + papZonesH)
  y += papH

  // Band 3: Intern (Süd), vertikal zweigeteilt:
  // OBEN die Zonen mit mehreren (oder ohne) Firewall-Anbindungen – nah an den
  // Clustern, mit aufgefächerten Kanten; DARUNTER die Spalten der Zonen mit
  // genau einer Firewall, direkt unter ihrem Cluster (gerade Spine-Verbindung).
  const intern = byLevel('intern')
  const southIds = new Set(southFws.map((f) => f.id))
  const columns = {}  // fwId -> Zonen (genau eine Anbindung)
  const multi = []    // mehrere oder keine Anbindungen
  intern.forEach((z) => {
    const attached = z.firewalls.filter((f) => southIds.has(f.id))
    if (attached.length === 1) {
      ;(columns[attached[0].id] = columns[attached[0].id] || []).push(z)
    } else {
      multi.push(z)
    }
  })
  Object.values(columns).forEach((list) => list.sort((a, b) => a.name.localeCompare(b.name)))
  multi.sort((a, b) => a.name.localeCompare(b.name))

  const S_ROW = BOX_H + 18

  // Oberer Bereich: Mehrfach-Zonen in den LÜCKEN zwischen den Firewall-Spalten,
  // damit die Spine-Linien der Spalten nicht durch die Boxen laufen
  const colXs = southFws.map((f) => fwX[f.id]).sort((a, b) => a - b)
  const slotEdges = [70, ...colXs, W - 70]
  const slots = []
  for (let i = 0; i < slotEdges.length - 1; i += 1) slots.push((slotEdges[i] + slotEdges[i + 1]) / 2)
  const multiRows = []
  for (let i = 0; i < multi.length; i += slots.length) multiRows.push(multi.slice(i, i + slots.length))
  const S_TOP = 12  // Label steht unten – oben reicht ein kleiner Abstand
  multiRows.forEach((row, ri) => {
    row.forEach((z, i) => {
      const idx = row.length >= slots.length
        ? i
        : Math.min(slots.length - 1, Math.round((i + 0.5) * (slots.length / row.length) - 0.5))
      zonePos[z.name] = { x: slots[idx], y: y + S_TOP + ri * S_ROW + S_ROW / 2 }
    })
  })
  const multiH = multiRows.length * S_ROW + (multiRows.length ? 10 : 0)

  // Unterer Bereich: Spalten unter den Firewalls
  let maxColumn = 0
  southFws.forEach((f) => {
    const list = columns[f.id] || []
    list.forEach((z, i) => {
      zonePos[z.name] = { x: fwX[f.id], y: y + S_TOP + multiH + i * S_ROW + S_ROW / 2 }
    })
    maxColumn = Math.max(maxColumn, list.length)
  })

  const internH = S_TOP + multiH + Math.max(maxColumn, multiRows.length ? 0 : 1) * S_ROW + 26
  bands.push({ key: 'intern', label: 'Intern (Süd) — unterhalb der P-A-P-Struktur', y, h: internH })
  y += internH
  const H = y

  return (
    <div className={`topology-wrap zone-reach${hover ? ' has-hover' : ''}`}>
      <div className="plan-head">
        <div>
          <strong>Zonenplan (bereinigter Netzplan)</strong>
          <span className="muted small"> · BSI NET.1.1 / NET.3.2 · Stand {new Date().toLocaleString('de-DE')} · generiert von Permitra</span>
        </div>
        <div className="plan-actions">
          <button type="button" className="btn btn-ghost" onClick={() => exportPlanPng()}>PNG</button>
          <button type="button" className="btn btn-ghost" onClick={() => exportPlanPdf()}>PDF</button>
          <a className="btn btn-ghost" href="/api/zones/plan/mermaid?download=true"
            onClick={(e) => { e.preventDefault(); exportPlanMermaid() }}>Mermaid</a>
        </div>
      </div>
      <svg viewBox={`0 0 ${W} ${H}`} id="zone-plan-svg" className="topology-svg" role="img"
        aria-label="Nord-Süd-Sicht der Sicherheitszonen nach BSI P-A-P (Zonenplan)">
        {bands.map((b) => (
          <g key={b.key}>
            <rect x={4} y={b.y + 2} width={W - 8} height={b.h - 6} rx={10} className={`pap-band band-${b.key}`} />
            <text x={16} y={b.key === 'intern' ? b.y + b.h - 12 : b.y + 19} className="pap-band-label">{b.label}</text>
          </g>
        ))}
        {(() => {
          // Anschlusspunkte je Firewall auffächern (statt alle Linien am Mittelpunkt)
          const anchors = {}
          fwList.forEach((f) => {
            const connected = zones
              .filter((z) => zonePos[z.name] && z.firewalls.some((x) => x.id === f.id))
              .sort((a, b) => zonePos[a.name].x - zonePos[b.name].x)
            connected.forEach((z, i) => {
              anchors[`${f.id}|${z.name}`] =
                fwPos[f.id].x - 70 + ((i + 0.5) / connected.length) * 140
            })
          })
          return zones.map((z) => z.firewalls.map((f) => {
            const zp = zonePos[z.name], fp = fwPos[f.id]
            if (!zp || !fp) return null
            const up = fp.y < zp.y
            const zy = zp.y + (up ? -BOX_H / 2 : BOX_H / 2)
            const fy = fp.y + (up ? BOX_H / 2 : -BOX_H / 2)
            // Zonen direkt unter ihrem Cluster: gerade Verbindung (Spine-Optik)
            const sameColumn = Math.abs(zp.x - fp.x) < 20
            const ax = sameColumn ? fp.x : (anchors[`${f.id}|${z.name}`] ?? fp.x)
            const my = (zy + fy) / 2
            const active = hover === z.name || hover === `fw:${f.id}`
            return (
              <path key={`${z.name}-${f.id}`}
                d={`M ${zp.x} ${zy} C ${zp.x} ${my}, ${ax} ${my}, ${ax} ${fy}`}
                className={`topo-link zone-link${active ? ' link-active' : ''}`}>
                <title>{`${z.name} ist über ${f.name} erreichbar`}</title>
              </path>
            )
          }))
        })()}
        {fwList.map((f) => {
          const p = fwPos[f.id]
          const color = FW_COLORS[f.type] || { fill: '#eef1f6', stroke: '#66707c' }
          return (
            <g key={f.id} onMouseEnter={() => setHover(`fw:${f.id}`)} onMouseLeave={() => setHover(null)}>
              <rect x={p.x - 85} y={p.y - BOX_H / 2} width={170} height={BOX_H} rx={8}
                fill={color.fill} stroke={color.stroke} strokeWidth="2.5">
                <title>{`${f.name} (${f.type === 'juniper' ? 'Juniper SRX' : 'Check Point'}) – ${f.location}`}</title>
              </rect>
              <text x={p.x} y={p.y + 4.5} className="zone-node-text fw-text">{f.name}</text>
            </g>
          )
        })}
        {zones.map((z) => {
          const p = zonePos[z.name]
          if (!p) return null
          const sub = `${z.schutzbedarf || 'normal'}${z.owner ? ' · ' + z.owner : ''}`
          const subShort = sub.length > 24 ? sub.slice(0, 23) + '…' : sub
          return (
            <g key={z.name} onMouseEnter={() => setHover(z.name)} onMouseLeave={() => setHover(null)}>
              <rect x={p.x - BOX_W / 2} y={p.y - BOX_H / 2} width={BOX_W} height={BOX_H} rx={8}
                className={`zone-box zone-sb-${(z.schutzbedarf || 'normal').replace(' ', '_')}`
                  + (z.has_firewall ? '' : ' zone-box-warn')}>
                <title>{(z.has_firewall
                  ? `${z.name}: erreichbar über ${z.firewalls.map((f) => f.name).join(', ')}`
                  : `${z.name}: kein Firewall-Cluster angebunden („Angebunden an“ pflegen)`)
                  + `\nSchutzbedarf: ${SB_LABEL(z)}`
                  + (z.owner ? `\nVerantwortlich: ${z.owner}` : '')
                  + (z.aci?.length ? `\nACI intra-zonal: ${z.aci.map((a) => a.name).join(', ')}` : '')}</title>
              </rect>
              <text x={p.x} y={p.y - 3} className="zone-node-text">{zoneLabel(z)}</text>
              <text x={p.x} y={p.y + 12} className="zone-node-sub">{subShort}</text>
              {z.aci?.length > 0 && (
                <g>
                  <rect x={p.x + BOX_W / 2 - 30} y={p.y - BOX_H / 2 - 7} width={30} height={14} rx={7}
                    className="zone-aci-chip" />
                  <text x={p.x + BOX_W / 2 - 15} y={p.y - BOX_H / 2 + 4} className="zone-aci-text">ACI</text>
                </g>
              )}
            </g>
          )
        })}
      </svg>
      <div className="sb-legend">
        <span><strong>Schutzbedarf:</strong></span>
        <span><span className="sb-swatch" style={{ background: '#eef1f6' }} />normal</span>
        <span><span className="sb-swatch" style={{ background: '#fff0d2', borderColor: '#cfa64e' }} />hoch</span>
        <span><span className="sb-swatch" style={{ background: '#fadddd', borderColor: '#cf7b7b' }} />sehr hoch</span>
        <span><span className="sb-swatch" style={{ borderColor: 'var(--red)', borderStyle: 'dashed' }} />keine Firewall-Anbindung</span>
      </div>
    </div>
  )
}

export default function ZoneMatrix() {
  const { t } = useLang()
  const user = getUser()
  const canEdit = user.role === 'architect' || user.role === 'admin'
  const [zones, setZones] = useState([])
  const [overview, setOverview] = useState(null)
  const [fwComponents, setFwComponents] = useState([])
  const [policies, setPolicies] = useState({})
  const [changes, setChanges] = useState([])
  const [notice, setNotice] = useState('')
  const [error, setError] = useState('')
  const [newZone, setNewZone] = useState('')
  const [newZoneCode, setNewZoneCode] = useState('')
  const [newZoneLevel, setNewZoneLevel] = useState('intern')
  const [newZoneCia, setNewZoneCia] = useState({ cia_c: 'normal', cia_i: 'normal', cia_a: 'normal' })
  const [netInputs, setNetInputs] = useState({})  // Zone -> CIDR-Eingabe
  const [saving, setSaving] = useState('')
  const [settings, setSettings] = useState({})
  const [metaZone, setMetaZone] = useState(null)  // Zone im BSI-Doku-Editor
  const [editMode, setEditMode] = useState(false)
  const [draft, setDraft] = useState({})        // "from|to" -> neue Policy
  const [draftZones, setDraftZones] = useState([])  // [{name, pap_level}]

  const isApprover = ['change_approver', 'admin'].includes(user.role)
  const pendingMap = {}
  changes.filter((c) => c.status === 'pending' && c.change_type === 'policy')
    .forEach((c) => { pendingMap[`${c.from_zone}|${c.to_zone}`] = c })

  // Anträge nach Batch gruppieren (ein Sammelantrag = eine Entscheidung)
  const batches = []
  {
    const byBatch = {}
    changes.forEach((c) => {
      const key = c.batch_id || `single-${c.id}`
      if (!byBatch[key]) {
        byBatch[key] = { key, items: [], status: c.status, requested_by: c.requested_by,
          requested_at: c.requested_at, decided_by: c.decided_by, decided_at: c.decided_at,
          first_approved_by: c.first_approved_by, first_approved_at: c.first_approved_at }
        batches.push(byBatch[key])
      }
      byBatch[key].items.push(c)
    })
  }
  const itemLabel = (c) => {
    if (c.change_type === 'zone_create') return `Neue Zone: ${c.from_zone} (${c.new_policy})`
    if (c.change_type === 'zone_delete') return `Zone löschen: ${c.from_zone}`
    if (c.change_type === 'net_add') return `Netz ${c.to_zone} → Zone ${c.from_zone}`
    if (c.change_type === 'net_delete') return `Netz ${c.to_zone} aus Zone ${c.from_zone} entfernen`
    if (c.change_type === 'net_update') {
      const oldZone = c.extra?.old_zone, oldCidr = c.extra?.old_cidr
      const parts = []
      if (oldCidr && oldCidr !== c.to_zone) parts.push(`${oldCidr} → ${c.to_zone}`)
      if (oldZone && oldZone !== c.from_zone) parts.push(`Zone ${oldZone} → ${c.from_zone}`)
      return `Netz ${oldCidr || c.to_zone}: ${parts.join(', ') || `Zone ${c.from_zone}`}`
    }
    return `${c.from_zone} → ${c.to_zone}: ${c.old_policy ? (c.old_policy === 'allow_only' ? 'Allow' : 'Block') : 'neu'}`
      + ` → ${c.new_policy === 'allow_only' ? 'Allow' : 'Block'}`
  }

  const load = useCallback(async () => {
    try {
      api.zoneOverview().then(setOverview).catch(() => setOverview(null))
      api.components().then((cs) => setFwComponents(cs.filter((c) => c.type !== 'aci'))).catch(() => {})
      api.matrixChanges().then(setChanges).catch(() => setChanges([]))
      api.settings().then(setSettings).catch(() => setSettings({}))
      api.zoneNextCode().then((r) => setNewZoneCode((c) => c || r.code)).catch(() => {})
      const data = await api.zoneMatrix()
      setZones(data.zones)
      const map = {}
      for (const p of data.policies) map[`${p.from_zone}|${p.to_zone}`] = p
      setPolicies(map)
    } catch (err) {
      setError(err.message)
    }
  }, [])

  useEffect(() => { load() }, [load])

  // Im Editier-Modus werden Klicks lokal gesammelt und erst mit
  // „Matrixänderungen beantragen“ als EIN Sammelantrag eingereicht.
  const cycle = (from, to) => {
    if (!canEdit || from === to) return
    if (!editMode) {
      setNotice('Zum Ändern zuerst „Matrix ändern“ klicken.')
      return
    }
    const key = `${from}|${to}`
    if (pendingMap[key]) {
      setNotice(`Für ${from} → ${to} wartet bereits ein Antrag auf Freigabe.`)
      return
    }
    setNotice('')
    const original = policies[key]?.policy || 'block_all'
    const effective = draft[key] ?? policies[key]?.policy
    const next = effective === 'allow_only' ? 'block_all' : 'allow_only'
    setDraft((d) => {
      const copy = { ...d }
      if (next === original && policies[key]) delete copy[key]  // zurück auf Ausgangswert
      else copy[key] = next
      return copy
    })
  }

  const draftCount = Object.keys(draft).length + draftZones.length

  const startEdit = () => {
    setEditMode(true)
    setDraft({})
    setDraftZones([])
    setNotice('')
    setError('')
  }
  const cancelEdit = () => {
    setEditMode(false)
    setDraft({})
    setDraftZones([])
  }

  const submitBatch = async () => {
    if (!draftCount) {
      setNotice('Keine Änderungen erfasst.')
      return
    }
    setError('')
    try {
      const items = [
        ...draftZones.map((z) => ({ type: 'zone_create', name: z.name, code: z.code, pap_level: z.pap_level, cia_c: z.cia_c, cia_i: z.cia_i, cia_a: z.cia_a })),
        ...Object.entries(draft).map(([key, policy]) => {
          const [from_zone, to_zone] = key.split('|')
          return { type: 'policy', from_zone, to_zone, policy, temporary: false }
        }),
      ]
      const res = await api.submitMatrixBatch(items)
      setNotice(res.detail)
      cancelEdit()
      load()
    } catch (err) {
      setError(err.message)
    }
  }

  const decide = async (change, approve) => {
    setError('')
    setNotice('')
    try {
      const res = approve
        ? await api.approveMatrixChange(change.id)
        : await api.rejectMatrixChange(change.id)
      if (res.detail) setNotice(res.detail)
      load()
    } catch (err) {
      setError(err.message)
    }
  }

  // Zonen-Anlage läuft über den Sammelantrag; das Formular ist immer sichtbar
  // und aktiviert den Editier-Modus bei Bedarf automatisch
  const addZone = (e) => {
    e.preventDefault()
    const name = newZone.trim()
    const code = newZoneCode.trim()
    if (!name || !code) { setError('Bitte Zonen-ID und Name angeben.'); return }
    if (!editMode) setEditMode(true)
    if (zones.some((z) => z.name.toUpperCase() === name.toUpperCase() || (z.code || '').toUpperCase() === code.toUpperCase())
      || draftZones.some((z) => z.name.toUpperCase() === name.toUpperCase() || z.code.toUpperCase() === code.toUpperCase())) {
      setError(`Zone '${code} / ${name}' existiert bereits.`)
      return
    }
    setError('')
    setDraftZones((list) => [...list, { name, code, pap_level: newZoneLevel, ...newZoneCia }])
    setNewZone('')
    api.zoneNextCode().then((r) => setNewZoneCode(r.code)).catch(() => setNewZoneCode(''))
  }

  const removeZone = async (name) => {
    if (!window.confirm(`Löschung der Zone "${name}" beantragen? (Freigabe durch zwei Change Approver)`)) return
    setError('')
    try {
      const r = await api.deleteZone(name)
      if (r?.status === 'pending') {
        setError('')
        alert('Löschung beantragt – wird erst nach Freigabe durch zwei Change Approver wirksam.')
      }
      load()
    } catch (err) {
      setError(err.message)
    }
  }

  return (
    <div>
      <div className="page-head">
        <h1>{t('Sicherheitszonen')}</h1>
        <span className="muted">
          Übersicht, Firewall-Erreichbarkeit und Kommunikationsmatrix der Zonen
        </span>
      </div>

      <div className="infobox">
        <strong>BSI-Prinzip:</strong> Der Übergang zwischen Sicherheitszonen erfolgt
        <strong> immer über eine Firewall</strong>. Cisco ACI ist als Sicherheitskomponente
        für den Zonenübergang <strong>nicht ausreichend</strong> (keine Firewall nach
        BSI-Definition) — ACI Contracts sind das Mittel <em>innerhalb</em> einer Zone.
        Permitra erzwingt das: Eine zonenübergreifende Regel ohne Firewall-Komponente
        wird abgelehnt.
      </div>

      {error && <div className="error">{error}</div>}
      {notice && <div className="okbox">{notice}</div>}

      <section className="card wide zone-overview">
        <h2>{t('Zonen-Übersicht & Firewall-Erreichbarkeit')}</h2>
        <ZoneReachability overview={overview} />
        {overview && (
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>{t('Zone')}</th><th>{t('Schutzbedarf & Verantwortlicher')}</th>
                  <th>{t('Netzwerke')}</th><th>{t('P-A-P-Einstufung')}</th><th>{t('Regeln')}</th>
                  <th>{t('Angebunden an')}</th><th>{t('ACI (intra-zonal)')}</th><th></th>
                </tr>
              </thead>
              <tbody>
                {overview.zones.map((z) => (
                  <tr key={z.name}>
                    <td><strong>{zoneLabel(z)}</strong><div className="muted small">{z.description}</div></td>
                    <td>
                      <span className={`badge ${SB_BADGE[z.schutzbedarf] || 'status-draft'}`}
                        title={`C: ${z.cia_c} · I: ${z.cia_i} · V: ${z.cia_a} (Maximumprinzip)`}>
                        {z.schutzbedarf || 'normal'}
                      </span>
                      <div className="muted small">{z.owner || t('kein Verantwortlicher')}</div>
                    </td>
                    <td>
                      <Link to="/networks" className="rule-link"
                        title={(z.networks || []).map((n) => n.cidr).join(', ') || t('Zonen-Zuordnung auf der Seite Netzwerke pflegen')}>
                        {(z.networks || []).length} {t('Netzwerke')}
                      </Link>
                    </td>
                    <td>
                      {{ extern: 'extern (Nord)', pap: 'P-A-P-Ebene', intern: 'intern (Süd)' }[z.pap_level || 'intern']}
                    </td>
                    <td>{z.rule_count}</td>
                    <td>
                      {z.firewalls.length
                        ? z.firewalls.map((f) => (
                            <span key={f.id} className={`badge platform-${f.type}`}>{f.name}</span>
                          ))
                        : <span className="badge status-rejected">{t('keine Firewall-Anbindung')}</span>}
                    </td>
                    <td>
                      {z.aci.map((a) => <span key={a.id} className="badge platform-aci">{a.name}</span>)}
                    </td>
                    <td className="row-actions">
                      {canEdit && (
                        <button className="btn btn-ghost"
                          onClick={() => setMetaZone({ ...z, component_ids: z.firewalls.map((f) => f.id) })}>
                          {t('Bearbeiten')}
                        </button>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>

      {metaZone && (
        <Modal title={`${t('Zone bearbeiten')}: ${metaZone.name}`} onClose={() => setMetaZone(null)}>
          <form className="modal-form" onSubmit={async (e) => {
            e.preventDefault()
            try {
              await api.setZoneMeta(metaZone.name, {
                owner: metaZone.owner, description: metaZone.description, code: metaZone.code,
                cia_c: metaZone.cia_c, cia_i: metaZone.cia_i, cia_a: metaZone.cia_a,
              })
              await api.setZonePapLevel(metaZone.name, metaZone.pap_level || 'intern')
              await api.setZoneComponents(metaZone.name, metaZone.component_ids || [])
              setMetaZone(null)
              load()
            } catch (err) { setError(err.message) }
          }}>
            <div className="grid-2">
              <label>{t('Kennung (z.B. Z020)')}
                <input value={metaZone.code || ''} autoFocus placeholder="Z020"
                  onChange={(e) => setMetaZone({ ...metaZone, code: e.target.value })} />
              </label>
              <label>{t('Verantwortlicher (Person/Team)')}
                <input value={metaZone.owner || ''}
                  onChange={(e) => setMetaZone({ ...metaZone, owner: e.target.value })} />
              </label>
            </div>
            <label>{t('Beschreibung (Zweck der Zone)')}
              <input value={metaZone.description || ''}
                onChange={(e) => setMetaZone({ ...metaZone, description: e.target.value })} />
            </label>
            <div className="grid-3">
              {[['cia_c', t('Vertraulichkeit')], ['cia_i', t('Integrität')], ['cia_a', t('Verfügbarkeit')]].map(([field, label]) => (
                <label key={field}>{label}
                  <select value={metaZone[field] || 'normal'}
                    onChange={(e) => setMetaZone({ ...metaZone, [field]: e.target.value })}>
                    <option value="normal">normal</option>
                    <option value="hoch">hoch</option>
                    <option value="sehr hoch">sehr hoch</option>
                  </select>
                </label>
              ))}
            </div>
            <div className="grid-2">
              <label>{t('P-A-P-Einstufung')}
                <select value={metaZone.pap_level || 'intern'}
                  onChange={(e) => setMetaZone({ ...metaZone, pap_level: e.target.value })}>
                  <option value="extern">extern (Nord)</option>
                  <option value="pap">P-A-P-Ebene</option>
                  <option value="intern">intern (Süd)</option>
                </select>
              </label>
              <label>{t('Angebunden an')}
                <span className="attach-select">
                  {fwComponents.map((f) => {
                    const ids = metaZone.component_ids || []
                    const attached = ids.includes(f.id)
                    return (
                      <label key={f.id} className="checkbox">
                        <input type="checkbox" checked={attached}
                          onChange={() => setMetaZone({
                            ...metaZone,
                            component_ids: attached ? ids.filter((x) => x !== f.id) : [...ids, f.id],
                          })} />
                        <span className={`badge platform-${f.type}`}>{f.name}</span>
                      </label>
                    )
                  })}
                </span>
              </label>
            </div>
            <p className="muted small">
              {t('Gesamt-Schutzbedarf nach Maximumprinzip:')}{' '}
              <strong>{['sehr hoch', 'hoch'].find((l) =>
                [metaZone.cia_c, metaZone.cia_i, metaZone.cia_a].includes(l)) || 'normal'}</strong>
            </p>
            <div className="actions">
              <button className="btn btn-primary" type="submit">{t('Speichern')}</button>
              <button className="btn btn-ghost" type="button" onClick={() => setMetaZone(null)}>{t('Abbrechen')}</button>
            </div>
          </form>
        </Modal>
      )}

      <div className="matrix-toolbar">
        <h2>{t('Kommunikationsmatrix')} <span className="muted small">{t('(Zeile = Quelle, Spalte = Ziel)')}</span></h2>
        {canEdit && !editMode && (
          <button className="btn btn-primary" onClick={startEdit}>Matrix ändern</button>
        )}
        {canEdit && editMode && (
          <>
            <span className="badge status-in_review">Editier-Modus – {draftCount} Änderung(en) erfasst</span>
            <button className="btn btn-approve" onClick={submitBatch} disabled={!draftCount}>
              Matrixänderungen beantragen{draftCount ? ` (${draftCount})` : ''}
            </button>
            <button className="btn btn-ghost" onClick={cancelEdit}>Verwerfen</button>
          </>
        )}
      </div>

      {settings.zone_matrix_default === 'deny' && (
        <div className="infobox">
          {t('Minimalprinzip aktiv (default-deny): Für Zonen-Beziehungen ohne Matrix-Eintrag werden Sicherheitsregeln abgelehnt, bis die Beziehung hier per Antrag auf Allow gesetzt ist.')}
        </div>
      )}
      <div className="matrix-legend">
        <span className="badge cell-allow">Allow</span> Regeln erlaubt (Durchsetzung per Firewall)
        <span className="badge cell-block">Block</span> keine Regeln zulässig
        <span className="badge cell-undef">leer</span> nicht gepflegt (Regeln erlaubt, mit Hinweis)
        <span className="badge cell-self">–</span> gleiche Zone
        {canEdit && <em className="muted"> – Klick auf eine Zelle wechselt Allow ↔ Block</em>}
      </div>

      <div className="table-wrap matrix-wrap">
        <table className="matrix">
          <thead>
            <tr>
              <th className="corner">Von \ Nach</th>
              {zones.map((z) => <th key={z.id} className="col-head"><span>{zoneLabel(z)}</span></th>)}
            </tr>
          </thead>
          <tbody>
            {zones.map((from) => (
              <tr key={from.id}>
                <th className="row-head">{zoneLabel(from)}</th>
                {zones.map((to) => {
                  if (from.id === to.id) return <td key={to.id} className="cell-self">–</td>
                  const key = `${zref(from)}|${zref(to)}`
                  const p = policies[key]
                  const pend = pendingMap[key]
                  const draftPolicy = draft[key]
                  const shown = draftPolicy ?? p?.policy
                  const cls = !shown ? 'cell-undef' : shown === 'allow_only' ? 'cell-allow' : 'cell-block'
                  const label = draftPolicy
                    ? (draftPolicy === 'allow_only' ? 'Allow' : 'Block')
                    : (p ? cellLabel(p) : '')
                  return (
                    <td
                      key={to.id}
                      className={`${cls} ${canEdit && editMode ? 'cell-edit' : ''}`
                        + `${pend ? ' cell-pending' : ''}${draftPolicy ? ' cell-draft' : ''}`}
                      title={`${from.name} → ${to.name}: ${p ? cellLabel(p)
                        : settings.zone_matrix_default === 'deny'
                          ? 'nicht gepflegt – default-deny: Regeln werden abgelehnt'
                          : 'nicht gepflegt – erlaubt mit Hinweis'}`
                        + (draftPolicy ? ` – Entwurf: ${draftPolicy === 'allow_only' ? 'Allow' : 'Block'} (noch nicht beantragt)` : '')
                        + (pend ? ` – Antrag auf ${pend.new_policy === 'allow_only' ? 'Allow' : 'Block'} wartet auf Freigabe (${pend.requested_by})` : '')}
                      onClick={() => cycle(zref(from), zref(to))}
                    >
                      {`${label}${draftPolicy ? ' ✎' : ''}${pend ? ' ⏳' : ''}`}
                    </td>
                  )
                })}
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {canEdit && (
        <div className="zone-manage">
          {true ? (
            <form className="zone-add" onSubmit={addZone}>
              <input value={newZoneCode} onChange={(e) => setNewZoneCode(e.target.value)}
                placeholder="Zonen-ID, z.B. Z130" style={{ maxWidth: '120px' }} />
              <input value={newZone} onChange={(e) => setNewZone(e.target.value)}
                placeholder="Zonen-Name, z.B. T-NEW" />
              <select value={newZoneLevel} onChange={(e) => setNewZoneLevel(e.target.value)}>
                <option value="extern">extern (Nord)</option>
                <option value="pap">P-A-P-Ebene</option>
                <option value="intern">intern (Süd)</option>
              </select>
              {[['cia_c', 'C'], ['cia_i', 'I'], ['cia_a', 'V']].map(([f, lbl]) => (
                <select key={f} title={t('Schutzbedarf')} value={newZoneCia[f]}
                  onChange={(e) => setNewZoneCia({ ...newZoneCia, [f]: e.target.value })}
                  style={{ maxWidth: '110px' }}>
                  <option value="normal">{lbl}: normal</option>
                  <option value="hoch">{lbl}: hoch</option>
                  <option value="sehr hoch">{lbl}: sehr hoch</option>
                </select>
              ))}
              <span className="muted small">
                {t('Schutzbedarf')}: <strong>{['sehr hoch', 'hoch'].find((l) => Object.values(newZoneCia).includes(l)) || 'normal'}</strong>
              </span>
              <button className="btn btn-primary" type="submit">{t('Zone anlegen')} (in Antrag)</button>
              {draftZones.map((z) => (
                <span key={z.name} className="zone-chip">
                  ✎ {z.code}-{z.name} <span className="muted small">({z.pap_level})</span>
                  <button type="button"
                    onClick={() => setDraftZones(draftZones.filter((x) => x.name !== z.name))}>✕</button>
                </span>
              ))}
            </form>
          ) : null}
          <p className="muted small">
            Neue Zonen landen im Sammelantrag und werden erst nach zweifacher Freigabe durch
            Change Approver angelegt – „Matrixänderungen beantragen" schließt die Erfassung ab.
          </p>
          <div className="zone-chips">
            {zones.map((z) => (
              <span key={z.id} className="zone-chip">
                {z.name}
                <button type="button" title={`Zone ${z.name} löschen`}
                  onClick={() => removeZone(z.name)}>✕</button>
              </span>
            ))}
          </div>
          <p className="muted small">
            Löschen ist nur möglich, wenn keine Regel die Zone verwendet; die Matrix-Einträge
            der Zone werden mitgelöscht.
          </p>
        </div>
      )}

      <section className="card wide">
        <h2>Matrix-Änderungen: Freigaben & Historie</h2>
        <p className="muted small">
          Jede Matrix-Änderung wird als Antrag protokolliert und erst nach Freigabe durch den
          Betrieb wirksam (Vier-Augen-Prinzip: eigene Anträge können nicht selbst freigegeben werden).
        </p>
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>{t('Änderung')}en</th><th>{t('Status')}</th>
                <th>Beantragt</th><th>Entschieden</th><th></th>
              </tr>
            </thead>
            <tbody>
              {batches.map((b) => (
                <tr key={b.key} className={b.status === 'pending' ? '' : 'row-any'}>
                  <td>
                    {b.items.map((c) => (
                      <div key={c.id}>
                        {(c.change_type === 'zone_create' || c.change_type === 'zone_delete') && <span className="badge platform-unknown comp-badge">Zone</span>}
                        {c.change_type.startsWith('net_') && <span className="badge platform-unknown comp-badge">Netz</span>}
                        {itemLabel(c)}
                        {c.affected_count > 0 && (
                          <span className="badge status-rejected comp-badge"
                            title={`Betroffene Regeln: ${c.affected_rules.map((r) => r.rule_id).join(', ')}`}>
                            ⚠ {c.affected_count} Regel(n) betroffen
                          </span>
                        )}
                      </div>
                    ))}
                  </td>
                  <td>
                    <span className={`badge ${
                      { pending: 'status-in_review', approved: 'status-approved', rejected: 'status-rejected' }[b.status]
                    }`}>
                      {b.status === 'pending' && b.first_approved_by
                        ? `1/2 Freigaben (${b.first_approved_by})`
                        : { pending: 'wartet auf Freigabe (0/2)', approved: 'freigegeben', rejected: 'abgelehnt' }[b.status]}
                    </span>
                    {b.items.length > 1 && <div className="muted small">{b.items.length} Änderungen</div>}
                  </td>
                  <td>{b.requested_by}<span className="muted small"> · {b.requested_at ? new Date(b.requested_at).toLocaleString('de-DE') : ''}</span></td>
                  <td>{b.decided_by
                    ? <>{b.decided_by}<span className="muted small"> · {b.decided_at ? new Date(b.decided_at).toLocaleString('de-DE') : ''}</span></>
                    : '–'}</td>
                  <td className="row-actions">
                    {b.status === 'pending' && isApprover && (
                      <>
                        <button className="btn btn-approve" onClick={() => decide(b.items[0], true)}>{t('✓ Freigeben')}</button>
                        <button className="btn btn-reject" onClick={() => decide(b.items[0], false)}>{t('✕ Ablehnen')}</button>
                      </>
                    )}
                  </td>
                </tr>
              ))}
              {!batches.length && <tr><td colSpan={5} className="muted">Noch keine Matrix-Änderungen protokolliert.</td></tr>}
            </tbody>
          </table>
        </div>
      </section>
    </div>
  )
}
