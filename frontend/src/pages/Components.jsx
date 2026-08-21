import { useEffect, useState } from 'react'
import { api } from '../api'
import { Modal } from '../components/shared'
import { useLang } from '../i18n'

const TYPE_LABELS = { juniper: 'Juniper SRX', checkpoint: 'Check Point', aci: 'Cisco ACI' }
const EMPTY = {
  name: '', type: 'checkpoint', location: '', mgmt_address: '',
  ns_tier: 100, description: '', active: true,
}

const NODE_COLORS = {
  juniper: { fill: '#dbe9ff', stroke: '#1c53b8' },
  checkpoint: { fill: '#ffe4e0', stroke: '#b83a1c' },
  aci: { fill: '#e3f5ec', stroke: '#157a52' },
}

const LINK_TYPE_SUGGESTIONS = [
  'OSPF Routing', 'BGP Peering', 'Statisches Routing', 'PBR / Service Graph',
  'L2 Trunk', 'IPsec VPN', 'VXLAN', 'L3Out',
]

function TopologySection({ components }) {
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
    if (!window.confirm(`Beziehung ${link.a_name} ↔ ${link.b_name} löschen?`)) return
    try { await api.deleteComponentLink(link.id); load() } catch (err) { setError(err.message) }
  }

  // Layout in Nord-Süd-Ebenen: kleinere ns_tier oben (nördlich), größere unten (südlich)
  const tiers = [...new Set(components.map((c) => c.ns_tier))].sort((a, b) => a - b)
  const rows = tiers.map((t) =>
    components.filter((c) => c.ns_tier === t).sort((a, b) => a.name.localeCompare(b.name)))
  const W = 780, ROW_H = 140, TOP = 60
  const H = TOP + Math.max(rows.length, 1) * ROW_H + 6
  const pos = {}
  rows.forEach((row, i) => {
    row.forEach((c, j) => {
      // Volle Breite nutzen, damit die Verbindungslinien Platz für Beschriftungen haben
      pos[c.id] = {
        x: 90 + (W - 170) * ((j + 0.5) / row.length),
        y: TOP + i * ROW_H + 30,
      }
    })
  })

  return (
    <section className="card wide">
      <h2>Kommunikationsbeziehungen der Komponenten</h2>
      <p className="muted small">
        Anordnung nach Nord-Süd-Ebene (kleinere Ebene = nördlicher/Internet-nah). Die Ebene wird
        je Komponente gepflegt; Linien dokumentieren, wer direkt mit wem spricht.
      </p>
      {error && <div className="error">{error}</div>}

      <div className="topology-wrap">
        <svg viewBox={`0 0 ${W} ${H}`} className="topology-svg" role="img"
          aria-label="Topologie der Sicherheitskomponenten (Nord oben, Süd unten)">
          <text x="14" y="26" className="topo-compass">Nord ▲</text>
          <text x="14" y={H - 12} className="topo-compass">Süd ▼</text>
          <line x1="30" y1="34" x2="30" y2={H - 26} className="topo-axis" />
          {rows.map((row, i) => (
            <text key={tiers[i]} x="46" y={TOP + i * ROW_H + 34} className="topo-tier-label">
              {tiers[i]}
            </text>
          ))}
          {links.map((l) => {
            const a = pos[l.a_id], b = pos[l.b_id]
            if (!a || !b) return null
            // Linie am Kreisrand beginnen/enden lassen (r=30 + 2px Luft)
            const dx = b.x - a.x, dy = b.y - a.y
            const dist = Math.hypot(dx, dy) || 1
            const ux = dx / dist, uy = dy / dist
            const R = 32
            const x1 = a.x + ux * R, y1 = a.y + uy * R
            const x2 = b.x - ux * R, y2 = b.y - uy * R
            // Label senkrecht zur Linie versetzen, damit es weder Linie noch Knoten-Namen überdeckt
            const mx = (x1 + x2) / 2, my = (y1 + y2) / 2
            const nx = -uy, ny = ux
            const lx = mx + nx * 17, ly = my + ny * 17
            // Auf der Linie steht die Verbindungsart; Details im Tooltip und in der Tabelle
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
            const color = NODE_COLORS[c.type] || { fill: '#eef1f6', stroke: '#66707c' }
            return (
              <g key={c.id}>
                <circle cx={p.x} cy={p.y} r={30} fill={color.fill} stroke={color.stroke}
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
          <thead><tr><th>Komponente</th><th></th><th>Komponente</th><th>Verbindungsart</th><th>Beschreibung</th><th></th></tr></thead>
          <tbody>
            {links.map((l) => (
              <tr key={l.id}>
                <td><span className={`badge platform-${l.a_type}`}>{l.a_name}</span></td>
                <td>↔</td>
                <td><span className={`badge platform-${l.b_type}`}>{l.b_name}</span></td>
                <td>{l.link_type ? <span className="badge linktype-badge">{l.link_type}</span> : '–'}</td>
                <td>{l.description}</td>
                <td className="row-actions">
                  <button className="btn btn-ghost" onClick={() => remove(l)}>Löschen</button>
                </td>
              </tr>
            ))}
            {!links.length && <tr><td colSpan={6} className="muted">Keine Beziehungen dokumentiert.</td></tr>}
          </tbody>
        </table>
      </div>

      <form onSubmit={submit} className="object-form">
        <div className="grid-3">
          <label>Komponente A
            <select value={form.component_a_id} required
              onChange={(e) => setForm({ ...form, component_a_id: e.target.value })}>
              <option value="">– wählen –</option>
              {components.map((c) => <option key={c.id} value={c.id}>{c.name}</option>)}
            </select>
          </label>
          <label>Komponente B
            <select value={form.component_b_id} required
              onChange={(e) => setForm({ ...form, component_b_id: e.target.value })}>
              <option value="">– wählen –</option>
              {components.filter((c) => String(c.id) !== form.component_a_id)
                .map((c) => <option key={c.id} value={c.id}>{c.name}</option>)}
            </select>
          </label>
          <label>Verbindungsart
            <input value={form.link_type} list="link-type-suggestions"
              onChange={(e) => setForm({ ...form, link_type: e.target.value })}
              placeholder="z.B. OSPF Routing" />
            <datalist id="link-type-suggestions">
              {LINK_TYPE_SUGGESTIONS.map((t) => <option key={t} value={t} />)}
            </datalist>
          </label>
          <label>Beschreibung<input value={form.description}
            onChange={(e) => setForm({ ...form, description: e.target.value })}
            placeholder="z.B. Standort-Transit FFM–BER" /></label>
        </div>
        <div className="actions">
          <button className="btn btn-primary" type="submit">Beziehung anlegen</button>
        </div>
      </form>
    </section>
  )
}

function DriftPanel({ components }) {
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
      <h2>Soll-Ist-Abgleich (Drift)</h2>
      <p className="muted small">
        Ist-Konfiguration des Geräts einfügen (z.B. „show configuration | display set“ bzw.
        Management-API-Export) – der Abgleich erfolgt über die Rule-IDs (SR####), die Permitra
        in allen Exporten mitführt. Ein direkter Geräte-Abruf kann später als Adapter andocken.
      </p>
      {error && <div className="error">{error}</div>}
      {notice && <div className="okbox">{notice}</div>}
      <label className="inline">Komponente:
        <select value={selected} onChange={select}>
          <option value="">– wählen –</option>
          {components.map((c) => <option key={c.id} value={c.id}>{c.name}</option>)}
        </select>
      </label>

      {selected && report && (
        report.has_config ? (
          <div className="drift-report">
            <div className={report.in_sync ? 'okbox' : 'warnbox'}>
              {report.in_sync
                ? `✓ ${report.component} ist synchron (${report.expected_rule_count} freigegebene Regeln, `
                  + `${report.actual_rule_count} auf dem Gerät).`
                : `⚠ Abweichungen auf ${report.component} – Stand vom `
                  + `${new Date(report.fetched_at).toLocaleString('de-DE')} (${report.uploaded_by})`}
            </div>
            {!report.in_sync && (
              <div className="detail-grid">
                <div>
                  <h3>Fehlt auf dem Gerät ({report.missing.length})</h3>
                  <ul>{report.missing.map((r) => <li key={r.rule_id}><strong>{r.rule_id}</strong> {r.justification || r.name}</li>)}</ul>
                </div>
                <div>
                  <h3>Auf dem Gerät, aber nicht (mehr) freigegeben ({report.stale.length})</h3>
                  <ul>{report.stale.map((r) => <li key={r.rule_id}><strong>{r.rule_id}</strong> <span className="badge status-deactivated">{r.status}</span></li>)}</ul>
                </div>
                <div>
                  <h3>Unbekannte Regel-IDs / Schatten-Regeln ({report.unknown.length})</h3>
                  <ul>{report.unknown.map((rid) => <li key={rid}><code>{rid}</code></li>)}</ul>
                </div>
              </div>
            )}
          </div>
        ) : (
          <p className="muted">Für diese Komponente ist noch keine Ist-Konfiguration hinterlegt.</p>
        )
      )}

      {selected && (
        <form onSubmit={upload} className="drift-upload">
          <textarea rows={6} value={config} onChange={(e) => setConfig(e.target.value)}
            placeholder={'Ist-Konfiguration hier einfügen…\nset security policies from-zone ... policy SR0101 ...'} />
          <button className="btn btn-primary" type="submit" disabled={!config.trim()}>
            Ist-Konfiguration speichern & abgleichen
          </button>
        </form>
      )}
    </section>
  )
}

export default function Components() {
  const { t } = useLang()
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
    if (!window.confirm(`Komponente "${c.name}" löschen?`)) return
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
        <h1>{t('Sicherheitskomponenten')}</h1>
        <span className="muted">Firewall-Cluster und ACI-Fabrics, auf denen die Regeln umgesetzt werden</span>
        <button className="btn btn-primary head-action" onClick={openCreate}>{t('＋ Neue Komponente')}</button>
      </div>
      {error && <div className="error">{error}</div>}

      <TopologySection components={components} />

      <div className="table-wrap">
        <table>
          <thead>
            <tr>
              <th>Name</th><th>Typ</th><th>Standort/Zone</th><th>Ebene (N→S)</th>
              <th>Management-Adresse</th><th>Beschreibung</th><th>Status</th><th></th>
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
                <td>{c.active ? <span className="badge status-approved">aktiv</span>
                  : <span className="badge status-deactivated">inaktiv</span>}</td>
                <td className="row-actions">
                  <button className="btn btn-ghost" onClick={() => openEdit(c)}>Bearbeiten</button>
                  <button className="btn btn-ghost" onClick={() => remove(c)}>Löschen</button>
                </td>
              </tr>
            ))}
            {!components.length && <tr><td colSpan={8} className="muted">Keine Komponenten angelegt.</td></tr>}
          </tbody>
        </table>
      </div>

      {showModal && (
        <Modal title={editId ? t('Komponente bearbeiten') : t('Neue Komponente anlegen')} onClose={close}>
          {modalError && <div className="error">{modalError}</div>}
          <form onSubmit={submit} className="modal-form">
            <div className="grid-2">
              <label>Name<input value={form.name} onChange={set('name')}
                placeholder="z.B. FW-Cluster-FFM" required autoFocus /></label>
              <label>Typ
                <select value={form.type} onChange={set('type')}>
                  <option value="checkpoint">Check Point</option>
                  <option value="juniper">Juniper SRX</option>
                  <option value="aci">Cisco ACI</option>
                </select>
              </label>
              <label>Standort/Zone<input value={form.location} onChange={set('location')}
                placeholder="z.B. Zone FFM" /></label>
              <label>Nord-Süd-Ebene
                <input type="number" min="0" max="1000" value={form.ns_tier} onChange={set('ns_tier')} />
                <span className="muted small">0 = nördlich (Internet-nah), größer = südlicher</span>
              </label>
              <label>Management-Adresse<input value={form.mgmt_address} onChange={set('mgmt_address')}
                placeholder="z.B. cpmgmt.ffm.demo.local - 10.10.80.20" /></label>
              <label>Beschreibung<input value={form.description} onChange={set('description')} /></label>
            </div>
            <div className="actions">
              <label className="checkbox">
                <input type="checkbox" checked={form.active} onChange={set('active')} /> aktiv
              </label>
              <button className="btn btn-primary" type="submit">{editId ? 'Speichern' : 'Anlegen'}</button>
              <button className="btn btn-ghost" type="button" onClick={close}>Abbrechen</button>
            </div>
          </form>
        </Modal>
      )}

      <DriftPanel components={components} />
    </div>
  )
}
