import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { api, getUser, getVrfName } from '../api'
import { Modal } from '../components/shared'
import { useLang } from '../i18n'

const SOURCE_LABELS = { manual: 'manuell', netbox: 'NetBox' }

export default function Networks() {
  const { t } = useLang()
  const user = getUser()
  const canEdit = ['architect', 'operations', 'admin'].includes(user.role)
  const [networks, setNetworks] = useState([])
  const [zones, setZones] = useState([])
  const [changes, setChanges] = useState([])
  const [filter, setFilter] = useState('')
  const [form, setForm] = useState({ cidr: '', zone: '', description: '' })
  const [editNet, setEditNet] = useState(null)  // Eintrag im Overlay-Editor
  const [error, setError] = useState('')
  const [notice, setNotice] = useState('')

  const [nbPrefixes, setNbPrefixes] = useState([])
  const [nbZone, setNbZone] = useState({})  // prefixId -> Zonenname

  const load = () => {
    api.zoneNetworks().then(setNetworks).catch((e) => setError(e.message))
    api.zones().then(setZones).catch(() => setZones([]))
    api.matrixChanges().then(setChanges).catch(() => setChanges([]))
    if (canEdit) api.netboxPrefixes().then(setNbPrefixes).catch(() => setNbPrefixes([]))
  }
  useEffect(() => { load() }, [])

  const adoptNetbox = async () => {
    const items = nbPrefixes
      .filter((p) => nbZone[p.id])
      .map((p) => ({ prefix_id: p.id, zone: nbZone[p.id] }))
    if (!items.length) { setError(t('Bitte mindestens einem Prefix eine Zone zuweisen.')); return }
    setError(''); setNotice('')
    try {
      const r = await api.netboxAdopt(items)
      setNotice(r?.detail || t('Übernahme beantragt.'))
      setNbZone({})
      load()
    } catch (err) { setError(err.message) }
  }

  // Offene Anträge für Netzwerk-Zuordnungen: Markierung je Eintrag/CIDR
  const pendingNet = changes.filter(
    (c) => c.status === 'pending' && c.change_type.startsWith('net_'))
  const isPending = (n) => pendingNet.some(
    (c) => c.to_zone === n.cidr || (c.extra && c.extra.network_id === n.id))

  const netChangeLabel = (c) => {
    if (c.change_type === 'net_add') return `${c.to_zone} → ${t('Zone')} ${c.from_zone}`
    if (c.change_type === 'net_delete') return `${c.to_zone} ${t('aus Zone')} ${c.from_zone} ${t('entfernen')}`
    const oldZone = c.extra?.old_zone, oldCidr = c.extra?.old_cidr
    const parts = []
    if (oldCidr && oldCidr !== c.to_zone) parts.push(`${oldCidr} → ${c.to_zone}`)
    if (oldZone && oldZone !== c.from_zone) parts.push(`${t('Zone')} ${oldZone} → ${c.from_zone}`)
    return `${oldCidr || c.to_zone}: ${parts.join(', ') || c.from_zone}`
  }

  const submit = async (fn) => {
    setError('')
    setNotice('')
    try {
      const result = await fn()
      if (result?.status === 'pending') {
        setNotice(t('Änderung beantragt – sie wird erst nach Freigabe durch zwei Change Approver wirksam.'))
      } else if (result?.detail) {
        setNotice(result.detail)
      }
      load()
      return true
    } catch (err) {
      setError(err.message)
      return false
    }
  }

  const add = async (e) => {
    e.preventDefault()
    const ok = await submit(() => api.addZoneNetwork(form.zone, form.cidr, form.description))
    if (ok) setForm({ cidr: '', zone: form.zone, description: '' })
  }

  const remove = (network) => {
    if (!window.confirm(t('Entfernen der Zuordnung beantragen?') + ` (${network.cidr} → ${network.zone})`)) return
    submit(() => api.deleteZoneNetwork(network.id))
  }

  const shown = networks.filter((n) =>
    !filter.trim()
    || n.cidr.includes(filter.trim())
    || n.zone.toLowerCase().includes(filter.trim().toLowerCase())
    || (n.description || '').toLowerCase().includes(filter.trim().toLowerCase()))

  return (
    <div>
      <div className="page-head">
        <h1>{t('Netzwerke')}</h1>
        <span className="muted">
          {t('Zuordnung Netzwerk → Sicherheitszone – jedes Netzwerk gehört zu genau einer Zone')}
        </span>
      </div>

      <div className="infobox">
        {t('Die Verwaltung der Netzwerke selbst erfolgt in dedizierten Tools (z.B. NetBox/IPAM) – Permitra pflegt hier nur das Mapping auf die Sicherheitszonen. Ein automatischer Import aus externen Quellen kann über das Herkunftsfeld andocken; importierte Einträge erscheinen dann z.B. als „NetBox“.')}
        {' '}
        {t('Änderungen an der Zuordnung sind sicherheitsrelevant und werden erst nach Freigabe durch zwei Change Approver wirksam.')}
      </div>

      {error && <div className="error">{error}</div>}
      {notice && <div className="infobox">{notice}</div>}

      {canEdit && nbPrefixes.length > 0 && (
        <div className="card">
          <h3>{t('Aus NetBox importiert')} ({nbPrefixes.filter((p) => !p.in_registry).length})</h3>
          <p className="muted small">
            {t('Jedem Prefix eine Zone zuweisen und übernehmen – die Zuordnung durchläuft den Freigabe-Workflow.')}
          </p>
          <div className="table-wrap">
            <table>
              <thead>
                <tr><th>{t('Netzwerk (CIDR)')}</th><th>Status</th><th>{t('Beschreibung')}</th><th>{t('Zone')}</th></tr>
              </thead>
              <tbody>
                {nbPrefixes.map((p) => (
                  <tr key={p.id}>
                    <td><code>{p.cidr}</code></td>
                    <td><span className={`badge ${p.status === 'active' ? 'status-approved' : 'status-in_review'}`}>{p.status}</span></td>
                    <td className="small">{p.description}</td>
                    <td>
                      {p.in_registry ? <span className="muted small">{t('bereits vorhanden')}</span> : (
                        <select value={nbZone[p.id] || ''} onChange={(e) => setNbZone({ ...nbZone, [p.id]: e.target.value })}>
                          <option value="">{t('– später –')}</option>
                          {zones.map((z) => <option key={z.id} value={z.name}>{z.name}</option>)}
                        </select>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <div className="actions" style={{ marginTop: '.5rem' }}>
            <button className="btn btn-primary" onClick={adoptNetbox}>{t('Ausgewählte übernehmen')}</button>
          </div>
        </div>
      )}

      {pendingNet.length > 0 && (
        <div className="card">
          <h3>{t('Offene Anträge')} ({pendingNet.length})</h3>
          <ul className="plain-list">
            {pendingNet.map((c) => (
              <li key={c.id}>
                <span className="badge platform-unknown comp-badge">⏳</span>{' '}
                {netChangeLabel(c)}
                <span className="muted small">
                  {' – '}{c.requested_by}
                  {c.first_approved_by ? ` · ${t('Freigaben')}: 1/2 (${c.first_approved_by})` : ` · ${t('Freigaben')}: 0/2`}
                </span>
              </li>
            ))}
          </ul>
          <p className="muted small">
            {t('Freigabe durch Change Approver auf der Seite')}{' '}
            <Link to="/zones">{t('Sicherheitszonen')}</Link>.
          </p>
        </div>
      )}

      <form className="filterbar" onSubmit={(e) => e.preventDefault()}>
        <input value={filter} onChange={(e) => setFilter(e.target.value)}
          placeholder={t('Filtern nach CIDR, Zone oder Beschreibung…')} />
        <span className="muted">{shown.length} / {networks.length}</span>
      </form>

      <div className="table-wrap">
        <table>
          <thead>
            <tr>
              <th>{t('Netzwerk (CIDR)')}</th><th>{t('Umgebung')}</th><th>{t('Zone')}</th>
              <th>{t('Beschreibung')}</th><th>{t('Herkunft')}</th><th></th>
            </tr>
          </thead>
          <tbody>
            {shown.map((n) => (
              <tr key={n.id}>
                <td><code>{n.cidr}</code></td>
                <td><span className="badge platform-unknown">{n.vrf}</span></td>
                <td>
                  {n.zone}
                  {isPending(n) && <span className="badge platform-unknown comp-badge" title={t('Antrag wartet auf Freigabe')}> ⏳</span>}
                </td>
                <td>{n.description}</td>
                <td>
                  <span className={`badge ${n.source === 'manual' ? 'platform-unknown' : 'platform-aci'}`}>
                    {SOURCE_LABELS[n.source] || n.source}
                  </span>
                </td>
                <td className="row-actions">
                  {canEdit && !isPending(n) && (
                    <>
                      <button className="btn btn-ghost"
                        onClick={() => setEditNet({ ...n })}>{t('Bearbeiten')}</button>
                      <button className="btn btn-ghost" onClick={() => remove(n)}>{t('Löschen')}</button>
                    </>
                  )}
                </td>
              </tr>
            ))}
            {!shown.length && <tr><td colSpan={6} className="muted">{t('Keine Treffer.')}</td></tr>}
          </tbody>
        </table>
      </div>

      {editNet && (
        <Modal title={`${t('Bearbeiten')}: ${editNet.cidr}`} onClose={() => setEditNet(null)}>
          <form className="modal-form" onSubmit={async (e) => {
            e.preventDefault()
            const ok = await submit(() => api.updateZoneNetwork(editNet.id, {
              cidr: editNet.cidr, zone: editNet.zone, description: editNet.description,
            }))
            if (ok) setEditNet(null)
          }}>
            <p className="muted small">
              {t('CIDR- und Zonen-Änderungen werden als Antrag eingereicht (zwei Freigaben); Beschreibungs-Änderungen wirken sofort.')}
            </p>
            <div className="grid-2">
              <label>{t('Netzwerk (CIDR)')}
                <input value={editNet.cidr} required autoFocus
                  onChange={(e) => setEditNet({ ...editNet, cidr: e.target.value })} />
              </label>
              <label>{t('Zone')}
                <select value={editNet.zone}
                  onChange={(e) => setEditNet({ ...editNet, zone: e.target.value })}>
                  {zones.map((z) => <option key={z.id} value={z.name}>{z.name}</option>)}
                </select>
              </label>
            </div>
            <label>{t('Beschreibung')}
              <input value={editNet.description || ''}
                onChange={(e) => setEditNet({ ...editNet, description: e.target.value })} />
            </label>
            <div className="actions">
              <button className="btn btn-primary" type="submit">{t('Speichern')}</button>
              <button className="btn btn-ghost" type="button" onClick={() => setEditNet(null)}>{t('Abbrechen')}</button>
            </div>
          </form>
        </Modal>
      )}

      {canEdit && (
        <form onSubmit={add} className="object-form card">
          <div className="grid-3">
            <label>{t('Netzwerk (CIDR)')}
              <input value={form.cidr} onChange={(e) => setForm({ ...form, cidr: e.target.value })}
                placeholder='z.B. 10.10.35.0/24 oder "any"' required />
            </label>
            <label>{t('Zone')}
              <select value={form.zone} required
                onChange={(e) => setForm({ ...form, zone: e.target.value })}>
                <option value="">{t('– Zone wählen –')}</option>
                {zones.map((z) => <option key={z.id} value={z.name}>{z.name}</option>)}
              </select>
            </label>
            <label>{t('Beschreibung')}
              <input value={form.description}
                onChange={(e) => setForm({ ...form, description: e.target.value })} />
            </label>
          </div>
          <div className="actions">
            <button className="btn btn-primary" type="submit">{t('Zuordnung beantragen')}</button>
            <span className="muted small">{t('Umgebung')}: {getVrfName() || 'Default'}</span>
          </div>
        </form>
      )}
    </div>
  )
}
