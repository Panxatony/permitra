import { useEffect, useState } from 'react'
import { api } from '../api'
import { useLang } from '../i18n'

const EMPTY_GW = {
  name: '', tenant: '', vrf: '', bridge_domain: '', gateway_ip: '', zone_name: '',
  pbr_enabled: false, pbr_component_id: '', pbr_node_ip: '', pbr_node_mac: '',
  pbr_service_graph: '', pbr_health_group: '', description: '', active: true,
}

export default function Gateways() {
  const { t } = useLang()
  const [components, setComponents] = useState([])
  const [zones, setZones] = useState([])
  const [gateways, setGateways] = useState([])
  const [form, setForm] = useState(EMPTY_GW)
  const [editId, setEditId] = useState(null)
  const [error, setError] = useState('')

  const checkpoints = components.filter((c) => c.type === 'checkpoint')
  const load = () => api.aciGateways().then(setGateways).catch((e) => setError(e.message))

  useEffect(() => {
    load()
    api.components().then(setComponents).catch(() => setComponents([]))
    api.zones().then(setZones).catch(() => setZones([]))
  }, [])

  const set = (key) => (e) =>
    setForm({ ...form, [key]: ['pbr_enabled', 'active'].includes(key) ? e.target.checked : e.target.value })

  const startEdit = (g) => {
    setEditId(g.id)
    setForm({ ...g, pbr_component_id: g.pbr_component_id || '' })
  }
  const cancel = () => { setEditId(null); setForm(EMPTY_GW) }

  const submit = async (e) => {
    e.preventDefault()
    setError('')
    const payload = { ...form, pbr_component_id: form.pbr_component_id ? Number(form.pbr_component_id) : null }
    delete payload.pbr_component_name
    delete payload.id
    try {
      if (editId) await api.updateAciGateway(editId, payload)
      else await api.createAciGateway(payload)
      cancel()
      load()
    } catch (err) {
      setError(err.message)
    }
  }

  const remove = async (g) => {
    if (!window.confirm(t('Delete ACI gateway "{name}"?').replace('{name}', g.name))) return
    try {
      await api.deleteAciGateway(g.id)
      load()
    } catch (err) {
      setError(err.message)
    }
  }

  return (
    <section className="card wide">
      <h2>{t('ACI gateways')}</h2>
      <p className="muted small">
        {t('Bridge domain gateways, optionally with PBR redirection to a Check Point cluster')}
      </p>
      {error && <div className="error">{error}</div>}

      <div className="table-wrap">
        <table>
          <thead>
            <tr>
              <th>{t('Name')}</th><th>Tenant / VRF</th><th>Bridge Domain</th><th>{t('Gateway IP')}</th>
              <th>Zone</th><th>PBR → Firewall</th><th>{t('PBR node')}</th><th>Service Graph</th><th>{t('Status')}</th><th></th>
            </tr>
          </thead>
          <tbody>
            {gateways.map((g) => (
              <tr key={g.id} className={g.active ? '' : 'row-any'}>
                <td><strong>{g.name}</strong></td>
                <td>{g.tenant}{g.vrf ? ` / ${g.vrf}` : ''}</td>
                <td>{g.bridge_domain}</td>
                <td><code>{g.gateway_ip}</code></td>
                <td>{g.zone_name}</td>
                <td>
                  {g.pbr_enabled
                    ? <span className="badge platform-checkpoint">{g.pbr_component_name || '?'}</span>
                    : <span className="muted">{t('no PBR')}</span>}
                </td>
                <td className="addr">{g.pbr_enabled ? `${g.pbr_node_ip}\n${g.pbr_node_mac}` : ''}</td>
                <td>{g.pbr_service_graph}</td>
                <td>{g.active ? <span className="badge status-approved">{t('active')}</span>
                  : <span className="badge status-deactivated">{t('inactive')}</span>}</td>
                <td className="row-actions">
                  <button className="btn btn-ghost" onClick={() => startEdit(g)}>{t('Edit')}</button>
                  <button className="btn btn-ghost" onClick={() => remove(g)}>{t('Delete')}</button>
                </td>
              </tr>
            ))}
            {!gateways.length && <tr><td colSpan={10} className="muted">{t('No gateways documented.')}</td></tr>}
          </tbody>
        </table>
      </div>

      <form className="rule-form component-form" onSubmit={submit}>
        <fieldset>
          <legend>{editId ? t('Edit ACI gateway') : t('Document a new ACI gateway')}</legend>
          <div className="grid-3">
            <label>{t('Name')}<input value={form.name} onChange={set('name')} placeholder={t('e.g. GW-PROD-APP')} required /></label>
            <label>Tenant<input value={form.tenant} onChange={set('tenant')} /></label>
            <label>VRF<input value={form.vrf} onChange={set('vrf')} /></label>
            <label>Bridge Domain<input value={form.bridge_domain} onChange={set('bridge_domain')} /></label>
            <label>{t('Anycast gateway IP')}<input value={form.gateway_ip} onChange={set('gateway_ip')}
              placeholder={t('e.g. 10.10.30.1/24')} required /></label>
            <label>Zone
              <select value={form.zone_name} onChange={set('zone_name')}>
                <option value="">{t('– select zone –')}</option>
                {zones.map((z) => <option key={z.id} value={z.name}>{z.name}</option>)}
              </select>
            </label>
          </div>
          <label className="checkbox">
            <input type="checkbox" checked={form.pbr_enabled} onChange={set('pbr_enabled')} />
            {t('PBR link to a Check Point firewall (policy-based redirect)')}
          </label>
          {form.pbr_enabled && (
            <div className="grid-3">
              <label>{t('Target firewall (Check Point)')}
                <select value={form.pbr_component_id} onChange={set('pbr_component_id')} required>
                  <option value="">{t('– select cluster –')}</option>
                  {checkpoints.map((c) => <option key={c.id} value={c.id}>{c.name} ({c.location})</option>)}
                </select>
              </label>
              <label>{t('PBR node IP')}<input value={form.pbr_node_ip} onChange={set('pbr_node_ip')}
                placeholder={t('e.g. 10.10.35.10')} required /></label>
              <label>{t('PBR node MAC')}<input value={form.pbr_node_mac} onChange={set('pbr_node_mac')}
                placeholder={t('e.g. 00:50:56:AB:CD:01')} /></label>
              <label>Service Graph<input value={form.pbr_service_graph} onChange={set('pbr_service_graph')}
                placeholder={t('e.g. SG-CHKP-FFM')} /></label>
              <label>Health Group<input value={form.pbr_health_group} onChange={set('pbr_health_group')} /></label>
            </div>
          )}
          <label>{t('Description')}<input value={form.description} onChange={set('description')} /></label>
          <div className="actions">
            <label className="checkbox">
              <input type="checkbox" checked={form.active} onChange={set('active')} /> {t('active')}
            </label>
            <button className="btn btn-primary" type="submit">{editId ? t('Save') : t('Create')}</button>
            {editId && <button className="btn btn-ghost" type="button" onClick={cancel}>{t('Cancel')}</button>}
          </div>
        </fieldset>
      </form>
    </section>
  )
}
