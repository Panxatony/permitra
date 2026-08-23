import { useEffect, useState } from 'react'
import { api } from '../api'
import { Modal, StatusBadge} from '../components/shared'
import { dateLocale, useLang } from '../i18n'

const TYPE_LABELS = { juniper: 'Juniper SRX', checkpoint: 'Check Point', aci: 'Cisco ACI' }
const EMPTY = {
  name: '', type: 'checkpoint', location: '', mgmt_address: '',
  ns_tier: 100, description: '', active: true,
}

const NODE_COLORS = {
  juniper: 'fw-juniper',
  checkpoint: 'fw-checkpoint',
  aci: 'fw-aci',
}

const LINK_TYPE_SUGGESTIONS = [
  'OSPF routing', 'BGP peering', 'Static routing', 'PBR / service graph',
  'L2 Trunk', 'IPsec VPN', 'VXLAN', 'L3Out',
]

function TopologySection({ components }) {
  const { lang, t } = useLang()
  const [links, setLinks] = useState([])
  const [form, setForm] = useState({ component_a_id: '', component_b_id: '', link_type: '', description: '' })
  const [error, setError] = useState('')

  const load = () => api.componentLinks().then(setLinks).catch((e) => setError(e.message))
  useEffect(() => { load() }, [])

  const submit = async (e) => {
    e.preventDefault()
    setError('')
    try {
      await api.createComponentLink({
        component_a_id: Number(form.component_a_id),
        component_b_id: Number(form.component_b_id),
        link_type: form.link_type,
        description: form.description,
      })
      setForm({ component_a_id: '', component_b_id: '', link_type: '', description: '' })
      load()
    } catch (err) {
      setError(err.message)
    }
  }

  const remove = async (link) => {
    if (!window.confirm(t('Remove the link {a} ↔ {b}?')
      .replace('{a}', link.a_name).replace('{b}', link.b_name))) return
    try { await api.deleteComponentLink(link.id); load() } catch (err) { setError(err.message) }
  }

  // Layout in north-south tiers: lower ns_tier at the top (north), higher at the bottom (south)
  const tiers = [...new Set(components.map((c) => c.ns_tier))].sort((a, b) => a - b)
  const rows = tiers.map((t) =>
    components.filter((c) => c.ns_tier === t).sort((a, b) => a.name.localeCompare(b.name)))
  const W = 780, ROW_H = 140, TOP = 60
  const H = TOP + Math.max(rows.length, 1) * ROW_H + 6
  const pos = {}
  rows.forEach((row, i) => {
    row.forEach((c, j) => {
      // Use the full width so the connecting lines have room for their labels
      pos[c.id] = {
        x: 90 + (W - 170) * ((j + 0.5) / row.length),
        y: TOP + i * ROW_H + 30,
      }
    })
  })

  return (
    <section className="card wide">
      <h2>{t('Communication links between components')}</h2>
      <p className="muted small">
        {t('Arranged by north-south tier (a lower tier is further north, closer to the internet). The tier is maintained per component; the lines document who talks to whom directly.')}
      </p>
      {error && <div className="error">{error}</div>}

      <div className="topology-wrap">
        <svg viewBox={`0 0 ${W} ${H}`} className="topology-svg" role="img"
          aria-label={t('Topology of the security components (north at the top, south at the bottom)')}>
          <text x="14" y="26" className="topo-compass">{t('North ▲')}</text>
          <text x="14" y={H - 12} className="topo-compass">{t('South ▼')}</text>
          <line x1="30" y1="34" x2="30" y2={H - 26} className="topo-axis" />
          {rows.map((row, i) => (
            <text key={tiers[i]} x="46" y={TOP + i * ROW_H + 34} className="topo-tier-label">
              {tiers[i]}
            </text>
          ))}
          {links.map((l) => {
            const a = pos[l.a_id], b = pos[l.b_id]
            if (!a || !b) return null
            // Start/end the line at the circle's edge (r=30 + 2px of clearance)
            const dx = b.x - a.x, dy = b.y - a.y
            const dist = Math.hypot(dx, dy) || 1
            const ux = dx / dist, uy = dy / dist
            const R = 32
            const x1 = a.x + ux * R, y1 = a.y + uy * R
            const x2 = b.x - ux * R, y2 = b.y - uy * R
            // Offset the label perpendicular to the line so it covers neither the line nor the node names
            const mx = (x1 + x2) / 2, my = (y1 + y2) / 2
            const nx = -uy, ny = ux
            const lx = mx + nx * 17, ly = my + ny * 17
            // The line carries the link type; details live in the tooltip and the table
            const raw = l.link_type || l.description || ''
            const label = raw.length > 30 ? raw.slice(0, 28) + '…' : raw
            const boxW = label.length * 6.4 + 14
            const tooltip = `${l.a_name} ↔ ${l.b_name}`
              + (l.link_type ? ` · ${l.link_type}` : '')
              + (l.description ? ` – ${l.description}` : '')
            return (
              <g key={l.id}>
                <line x1={x1} y1={y1} x2={x2} y2={y2} className="topo-link">
                  <title>{tooltip}</title>
                </line>
                {label && (
                  <g className="topo-pill">
                    <title>{tooltip}</title>
                    <rect x={lx - boxW / 2} y={ly - 10} width={boxW} height={19} rx={9.5} />
                    <text x={lx} y={ly + 3.5}>{label}</text>
                  </g>
                )}
              </g>
            )
          })}
          {components.map((c) => {
            const p = pos[c.id]
            if (!p) return null
            const cls = NODE_COLORS[c.type] || 'fw-unknown'
            return (
              <g key={c.id}>
                <circle cx={p.x} cy={p.y} r={30} className={`fw-box ${cls}`}
                  strokeWidth="2.5">
                  <title>{`${c.name} (${TYPE_LABELS[c.type]}) – ${c.location} – Ebene ${c.ns_tier}`}</title>
                </circle>
                <text x={p.x} y={p.y + 4} className="topo-node-icon">
                  {{ juniper: 'FW', checkpoint: 'FW', aci: 'ACI' }[c.type]}
                </text>
                <text x={p.x} y={p.y + 48} className="topo-node-label">{c.name}</text>
              </g>
            )
          })}
        </svg>
      </div>

      <div className="table-wrap">
        <table>
          <thead><tr><th>{t('Component')}</th><th></th><th>{t('Component')}</th><th>{t('Link type')}</th><th>{t('Description')}</th><th></th></tr></thead>
          <tbody>
            {links.map((l) => (
              <tr key={l.id}>
                <td><span className={`badge platform-${l.a_type}`}>{l.a_name}</span></td>
                <td>↔</td>
                <td><span className={`badge platform-${l.b_type}`}>{l.b_name}</span></td>
                <td>{l.link_type ? <span className="badge linktype-badge">{l.link_type}</span> : '–'}</td>
                <td>{l.description}</td>
                <td className="row-actions">
                  <button className="btn btn-ghost" onClick={() => remove(l)}>{t('Delete')}</button>
                </td>
              </tr>
            ))}
            {!links.length && <tr><td colSpan={6} className="muted">{t('No links documented.')}</td></tr>}
          </tbody>
        </table>
      </div>

      <form onSubmit={submit} className="object-form">
        <div className="grid-3">
          <label>{t('Component A')}
            <select value={form.component_a_id} required
              onChange={(e) => setForm({ ...form, component_a_id: e.target.value })}>
              <option value="">{t('– select –')}</option>
              {components.map((c) => <option key={c.id} value={c.id}>{c.name}</option>)}
            </select>
          </label>
          <label>{t('Component B')}
            <select value={form.component_b_id} required
              onChange={(e) => setForm({ ...form, component_b_id: e.target.value })}>
              <option value="">{t('– select –')}</option>
              {components.filter((c) => String(c.id) !== form.component_a_id)
                .map((c) => <option key={c.id} value={c.id}>{c.name}</option>)}
            </select>
          </label>
          <label>{t('Link type')}
            <input value={form.link_type} list="link-type-suggestions"
              onChange={(e) => setForm({ ...form, link_type: e.target.value })}
              placeholder={t('e.g. OSPF routing')} />
            <datalist id="link-type-suggestions">
              {LINK_TYPE_SUGGESTIONS.map((t) => <option key={t} value={t} />)}
            </datalist>
          </label>
          <label>{t('Description')}<input value={form.description}
            onChange={(e) => setForm({ ...form, description: e.target.value })}
            placeholder={t('e.g. site transit FFM–BER')} /></label>
        </div>
        <div className="actions">
          <button className="btn btn-primary" type="submit">{t('Create link')}</button>
        </div>
      </form>
    </section>
  )
}

function DriftPanel({ components }) {
  const { lang, t } = useLang()
  const [selected, setSelected] = useState('')
  const [report, setReport] = useState(null)
  const [config, setConfig] = useState('')
  const [error, setError] = useState('')
  const [notice, setNotice] = useState('')

  const loadReport = (id) => {
    if (!id) return
    api.drift(id).then(setReport).catch((e) => setError(e.message))
  }

  const select = (e) => {
    const id = e.target.value
    setSelected(id)
    setReport(null)
    setConfig('')
    setError('')
    setNotice('')
    loadReport(id)
  }

  const upload = async (e) => {
    e.preventDefault()
    setError('')
    try {
      await api.uploadActualConfig(selected, config)
      setNotice('Ist-Konfiguration gespeichert – Abgleich aktualisiert.')
      setConfig('')
      loadReport(selected)
    } catch (err) {
      setError(err.message)
    }
  }

  return (
    <section className="card wide">
      <h2>{t('Target/actual comparison (drift)')}</h2>
      <p className="muted small">
        {t('Paste the device’s actual configuration (e.g. “show configuration | display set” or a management API export) – the comparison runs over the rule IDs (SR####) that Permitra carries in every export. A direct device query can be added later as an adapter.')}
      </p>
      {error && <div className="error">{error}</div>}
      {notice && <div className="okbox">{notice}</div>}
      <label className="inline">{t('Component')}:
        <select value={selected} onChange={select}>
          <option value="">{t('– select –')}</option>
          {components.map((c) => <option key={c.id} value={c.id}>{c.name}</option>)}
        </select>
      </label>

      {selected && report && (
        report.has_config ? (
          <div className="drift-report">
            <div className={report.in_sync ? 'okbox' : 'warnbox'}>
              {report.in_sync
                ? `✓ ${t('{component} is in sync ({expected} approved rules, {actual} on the device).')
                  .replace('{component}', report.component)
                  .replace('{expected}', report.expected_rule_count)
                  .replace('{actual}', report.actual_rule_count)}`
                : `⚠ ${t('Deviations on {component} – state as of {when} ({who})')
                  .replace('{component}', report.component)
                  .replace('{when}', new Date(report.fetched_at).toLocaleString(dateLocale(lang)))
                  .replace('{who}', report.uploaded_by)}`}
            </div>
            {!report.in_sync && (
              <div className="detail-grid">
                <div>
                  <h3>{t('Missing on the device')} ({report.missing.length})</h3>
                  <ul>{report.missing.map((r) => <li key={r.rule_id}><strong>{r.rule_id}</strong> {r.justification || r.name}</li>)}</ul>
                </div>
                <div>
                  <h3>{t('On the device but no longer approved')} ({report.stale.length})</h3>
                  <ul>{report.stale.map((r) => <li key={r.rule_id}><strong>{r.rule_id}</strong> <StatusBadge status={r.status} /></li>)}</ul>
                </div>
                <div>
                  <h3>{t('Unknown rule IDs / shadow rules')} ({report.unknown.length})</h3>
                  <ul>{report.unknown.map((rid) => <li key={rid}><code>{rid}</code></li>)}</ul>
                </div>
              </div>
            )}
          </div>
        ) : (
          <p className="muted">{t('No actual configuration has been stored for this component yet.')}</p>
        )
      )}

      {selected && (
        <form onSubmit={upload} className="drift-upload">
          <textarea rows={6} value={config} onChange={(e) => setConfig(e.target.value)}
            placeholder={t('Paste the actual configuration here…\nset security policies from-zone ... policy SR0101 ...')} />
          <button className="btn btn-primary" type="submit" disabled={!config.trim()}>
            {t('Save actual configuration & compare')}
          </button>
        </form>
      )}
    </section>
  )
}

export default function Components() {
  const { lang, t } = useLang()
  const [components, setComponents] = useState([])
  const [form, setForm] = useState(EMPTY)
  const [editId, setEditId] = useState(null)
  const [showModal, setShowModal] = useState(false)
  const [error, setError] = useState('')
  const [modalError, setModalError] = useState('')

  const load = () => api.components().then(setComponents).catch((e) => setError(e.message))
  useEffect(() => { load() }, [])

  const set = (key) => (e) =>
    setForm({ ...form, [key]: key === 'active' ? e.target.checked : e.target.value })

  const openCreate = () => {
    setEditId(null)
    setForm(EMPTY)
    setModalError('')
    setShowModal(true)
  }
  const openEdit = (c) => {
    setEditId(c.id)
    setForm({ name: c.name, type: c.type, location: c.location, mgmt_address: c.mgmt_address,
      ns_tier: c.ns_tier, description: c.description, active: c.active })
    setModalError('')
    setShowModal(true)
  }
  const close = () => setShowModal(false)

  const submit = async (e) => {
    e.preventDefault()
    setModalError('')
    const payload = { ...form, ns_tier: Number(form.ns_tier) }
    try {
      if (editId) await api.updateComponent(editId, payload)
      else await api.createComponent(payload)
      close()
      load()
    } catch (err) {
      setModalError(err.message)
    }
  }

  const remove = async (c) => {
    if (!window.confirm(t('Delete component "{name}"?').replace('{name}', c.name))) return
    setError('')
    try {
      await api.deleteComponent(c.id)
      load()
    } catch (err) {
      setError(err.message)
    }
  }

  return (
    <div>
      <div className="page-head">
        <h1>{t('Security components')}</h1>
        <span className="muted">{t('Firewall clusters and ACI fabrics the rules are implemented on')}</span>
        <button className="btn btn-primary head-action" onClick={openCreate}>{t('＋ New component')}</button>
      </div>
      {error && <div className="error">{error}</div>}

      <TopologySection components={components} />

      <div className="table-wrap">
        <table>
          <thead>
            <tr>
              <th>{t('Name')}</th><th>{t('Type')}</th><th>{t('Site/zone')}</th><th>{t('Tier (N→S)')}</th>
              <th>{t('Management address')}</th><th>{t('Description')}</th><th>{t('Status')}</th><th></th>
            </tr>
          </thead>
          <tbody>
            {components.map((c) => (
              <tr key={c.id} className={c.active ? '' : 'row-any'}>
                <td><strong>{c.name}</strong></td>
                <td><span className={`badge platform-${c.type}`}>{TYPE_LABELS[c.type]}</span></td>
                <td>{c.location}</td>
                <td><code>{c.ns_tier}</code></td>
                <td className="addr">{c.mgmt_address}</td>
                <td>{c.description}</td>
                <td>{c.active ? <span className="badge status-approved">{t('active')}</span>
                  : <span className="badge status-deactivated">{t('inactive')}</span>}</td>
                <td className="row-actions">
                  <button className="btn btn-ghost" onClick={() => openEdit(c)}>{t('Edit')}</button>
                  <button className="btn btn-ghost" onClick={() => remove(c)}>{t('Delete')}</button>
                </td>
              </tr>
            ))}
            {!components.length && <tr><td colSpan={8} className="muted">{t('No components created.')}</td></tr>}
          </tbody>
        </table>
      </div>

      {showModal && (
        <Modal title={editId ? t('Edit component') : t('Create new component')} onClose={close}>
          {modalError && <div className="error">{modalError}</div>}
          <form onSubmit={submit} className="modal-form">
            <div className="grid-2">
              <label>{t('Name')}<input value={form.name} onChange={set('name')}
                placeholder={t('e.g. FW-Cluster-FFM')} required autoFocus /></label>
              <label>{t('Type')}
                <select value={form.type} onChange={set('type')}>
                  <option value="checkpoint">Check Point</option>
                  <option value="juniper">Juniper SRX</option>
                  <option value="aci">Cisco ACI</option>
                </select>
              </label>
              <label>{t('Site/zone')}<input value={form.location} onChange={set('location')}
                placeholder={t('e.g. Zone FFM')} /></label>
              <label>{t('North-south tier')}
                <input type="number" min="0" max="1000" value={form.ns_tier} onChange={set('ns_tier')} />
                <span className="muted small">{t('0 = north (close to the internet), higher = further south')}</span>
              </label>
              <label>{t('Management address')}<input value={form.mgmt_address} onChange={set('mgmt_address')}
                placeholder={t('e.g. cpmgmt.ffm.demo.local - 10.10.80.20')} /></label>
              <label>{t('Description')}<input value={form.description} onChange={set('description')} /></label>
            </div>
            <div className="actions">
              <label className="checkbox">
                <input type="checkbox" checked={form.active} onChange={set('active')} /> {t('active')}
              </label>
              <button className="btn btn-primary" type="submit">{editId ? t('Save') : t('Create')}</button>
              <button className="btn btn-ghost" type="button" onClick={close}>{t('Cancel')}</button>
            </div>
          </form>
        </Modal>
      )}

      <DriftPanel components={components} />
    </div>
  )
}
