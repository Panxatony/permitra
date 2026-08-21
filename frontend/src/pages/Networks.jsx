import { useEffect, useState } from 'react'
import { api, getUser, getVrfName } from '../api'
import { Modal } from '../components/shared'
import { useLang } from '../i18n'

const SOURCE_LABELS = { manual: 'manuell', netbox: 'NetBox' }

export default function Networks() {
  const { t } = useLang()
  const user = getUser()
  const canEdit = ['architect', 'admin'].includes(user.role)
  const [networks, setNetworks] = useState([])
  const [zones, setZones] = useState([])
  const [filter, setFilter] = useState('')
  const [form, setForm] = useState({ cidr: '', zone: '', description: '' })
  const [editNet, setEditNet] = useState(null)  // Eintrag im Overlay-Editor
  const [error, setError] = useState('')

  const load = () => {
    api.zoneNetworks().then(setNetworks).catch((e) => setError(e.message))
    api.zones().then(setZones).catch(() => setZones([]))
  }
  useEffect(() => { load() }, [])

  const add = async (e) => {
    e.preventDefault()
    setError('')
    try {
      await api.addZoneNetwork(form.zone, form.cidr, form.description)
      setForm({ cidr: '', zone: form.zone, description: '' })
      load()
    } catch (err) {
      setError(err.message)
    }
  }

  const reassign = async (network, zoneName) => {
    setError('')
    try {
      await api.updateZoneNetwork(network.id, { zone: zoneName })
      load()
    } catch (err) {
      setError(err.message)
    }
  }

  const remove = async (network) => {
    if (!window.confirm(`Zuordnung ${network.cidr} → ${network.zone} entfernen?`)) return
    setError('')
    try {
      await api.deleteZoneNetwork(network.id)
      load()
    } catch (err) {
      setError(err.message)
    }
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
      </div>

      {error && <div className="error">{error}</div>}

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
                  {canEdit ? (
                    <select value={n.zone} onChange={(e) => reassign(n, e.target.value)}>
                      {zones.map((z) => <option key={z.id} value={z.name}>{z.name}</option>)}
                    </select>
                  ) : n.zone}
                </td>
                <td>{n.description}</td>
                <td>
                  <span className={`badge ${n.source === 'manual' ? 'platform-unknown' : 'platform-aci'}`}>
                    {SOURCE_LABELS[n.source] || n.source}
                  </span>
                </td>
                <td className="row-actions">
                  {canEdit && (
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
            setError('')
            try {
              await api.updateZoneNetwork(editNet.id, {
                cidr: editNet.cidr, zone: editNet.zone, description: editNet.description,
              })
              setEditNet(null)
              load()
            } catch (err) { setError(err.message) }
          }}>
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
            <button className="btn btn-primary" type="submit">{t('Zuordnung speichern')}</button>
            <span className="muted small">{t('Umgebung')}: {getVrfName() || 'Default'}</span>
          </div>
        </form>
      )}
    </div>
  )
}
