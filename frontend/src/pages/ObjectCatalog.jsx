import { useEffect, useState } from 'react'
import { api } from '../api'
import { useLang } from '../i18n'

const EMPTY_ADDR = { name: '', ip: '', description: '' }
const EMPTY_SVC = { name: '', protocol: 'TCP', port: '', description: '' }

function EpgSection() {
  const { t } = useLang()
  const [epgs, setEpgs] = useState([])
  const [mappings, setMappings] = useState([])
  const [epgForm, setEpgForm] = useState({ name: '', tenant: 'DEMO', app_profile: 'AP-DEMO', bridge_domain: '' })
  const [mapForm, setMapForm] = useState({ ip: '', alias: '', epg_id: '' })
  const [error, setError] = useState('')

  const load = () => {
    api.epgs().then(setEpgs).catch((e) => setError(e.message))
    api.epgMap().then(setMappings).catch(() => {})
  }
  useEffect(() => { load() }, [])

  const addEpg = async (e) => {
    e.preventDefault()
    setError('')
    try {
      await api.createEpg(epgForm)
      setEpgForm({ ...epgForm, name: '', bridge_domain: '' })
      load()
    } catch (err) { setError(err.message) }
  }

  const addMap = async (e) => {
    e.preventDefault()
    setError('')
    // Several addresses at once: comma-, semicolon- or space-separated
    const ips = mapForm.ip.split(/[\s,;]+/).filter(Boolean)
    try {
      for (const ip of ips) {
        // Only carry over the alias for a single address (an alias is address-specific)
        await api.upsertEpgMap({ ip, alias: ips.length === 1 ? mapForm.alias : '',
          epg_id: Number(mapForm.epg_id) })
      }
      setMapForm({ ip: '', alias: '', epg_id: '' })
      load()
    } catch (err) {
      setError(err.message)
      load()  // show the mappings that were already saved
    }
  }

  const removeEpg = async (epg) => {
    if (!window.confirm(t('Delete EPG "{name}"?').replace('{name}', epg.name))) return
    try { await api.deleteEpg(epg.id); load() } catch (err) { setError(err.message) }
  }
  const removeMap = async (m) => {
    try { await api.deleteEpgMap(m.id); load() } catch (err) { setError(err.message) }
  }

  return (
    <section className="card wide">
      <h2>{t('ACI EPGs & address mapping')}</h2>
      <p className="muted small">
        {t('ACI contracts connect EPGs, not IPs: the ACI export resolves source and destination addresses through this mapping (source → consumer, destination → provider, “any” → vzAny) and merges all rules of an EPG pair into one contract. Addresses without a mapping are exported as individual contracts and reported in the warnings.')}
      </p>
      {error && <div className="error">{error}</div>}
      <div className="detail-grid">
        <div>
          <h3>EPGs ({epgs.length})</h3>
          <div className="table-wrap">
            <table>
              <thead><tr><th>{t('Name')}</th><th>Tenant</th><th>App Profile</th><th>Bridge Domain</th><th></th></tr></thead>
              <tbody>
                {epgs.map((e) => (
                  <tr key={e.id}>
                    <td><strong>{e.name}</strong></td>
                    <td>{e.tenant}</td><td>{e.app_profile}</td><td>{e.bridge_domain}</td>
                    <td className="row-actions">
                      <button className="btn btn-ghost" onClick={() => removeEpg(e)}>{t('Delete')}</button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <form onSubmit={addEpg} className="object-form">
            <div className="grid-3">
              <label>{t('Name')}<input value={epgForm.name} required placeholder={t('e.g. epg-prod-app')}
                onChange={(e) => setEpgForm({ ...epgForm, name: e.target.value })} /></label>
              <label>Tenant<input value={epgForm.tenant}
                onChange={(e) => setEpgForm({ ...epgForm, tenant: e.target.value })} /></label>
              <label>App Profile<input value={epgForm.app_profile}
                onChange={(e) => setEpgForm({ ...epgForm, app_profile: e.target.value })} /></label>
              <label>Bridge Domain<input value={epgForm.bridge_domain} placeholder={t('e.g. BD-PROD-APP')}
                onChange={(e) => setEpgForm({ ...epgForm, bridge_domain: e.target.value })} /></label>
            </div>
            <div className="actions"><button className="btn btn-primary" type="submit">{t('Create EPG')}</button></div>
          </form>
        </div>
        <div>
          <h3>{t('Address → EPG')} ({mappings.length})</h3>
          <div className="table-wrap">
            <table>
              <thead><tr><th>{t('IP/network')}</th><th>Alias</th><th>EPG</th><th></th></tr></thead>
              <tbody>
                {[...mappings].sort((a, b) =>
                  a.epg_name.localeCompare(b.epg_name) || a.ip.localeCompare(b.ip)).map((m) => (
                  <tr key={m.id}>
                    <td><code>{m.ip}</code></td>
                    <td>{m.alias}</td>
                    <td><span className="badge platform-aci">{m.epg_name}</span></td>
                    <td className="row-actions">
                      <button className="btn btn-ghost" onClick={() => removeMap(m)}>✕</button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <form onSubmit={addMap} className="object-form">
            <div className="grid-3">
              <label>{t('IP/network(s)')}<input value={mapForm.ip} required
                placeholder={t('e.g. 10.10.30.0/24, 10.10.30.5 – several separated by commas')}
                onChange={(e) => setMapForm({ ...mapForm, ip: e.target.value })} /></label>
              <label>Alias<input value={mapForm.alias}
                onChange={(e) => setMapForm({ ...mapForm, alias: e.target.value })} /></label>
              <label>EPG
                <select value={mapForm.epg_id} required
                  onChange={(e) => setMapForm({ ...mapForm, epg_id: e.target.value })}>
                  <option value="">{t('– select –')}</option>
                  {epgs.map((e) => <option key={e.id} value={e.id}>{e.name}</option>)}
                </select>
              </label>
            </div>
            <div className="actions"><button className="btn btn-primary" type="submit">{t('Save mapping')}</button></div>
          </form>
        </div>
      </div>
    </section>
  )
}

export default function ObjectCatalog() {
  const { t } = useLang()
  const [addresses, setAddresses] = useState([])
  const [services, setServices] = useState([])
  const [addrForm, setAddrForm] = useState(EMPTY_ADDR)
  const [addrEditId, setAddrEditId] = useState(null)
  const [svcForm, setSvcForm] = useState(EMPTY_SVC)
  const [error, setError] = useState('')
  const [notice, setNotice] = useState('')

  const load = () => {
    api.addressObjects().then(setAddresses).catch((e) => setError(e.message))
    api.serviceObjects().then(setServices).catch(() => {})
  }
  useEffect(() => { load() }, [])

  const submitAddr = async (e) => {
    e.preventDefault()
    setError('')
    setNotice('')
    try {
      if (addrEditId) {
        const res = await api.updateAddressObject(addrEditId, addrForm)
        if (res.description?.includes(t('rule(s) updated'))) {
          setNotice(`${t('IP change applied')} – ${res.description.match(/\[(.*)\]/)?.[1] || ''}.`)
        }
      } else {
        await api.createAddressObject(addrForm)
      }
      setAddrForm(EMPTY_ADDR)
      setAddrEditId(null)
      load()
    } catch (err) {
      setError(err.message)
    }
  }

  const submitSvc = async (e) => {
    e.preventDefault()
    setError('')
    try {
      await api.createServiceObject(svcForm)
      setSvcForm(EMPTY_SVC)
      load()
    } catch (err) {
      setError(err.message)
    }
  }

  const removeAddr = async (o) => {
    if (!window.confirm(t('Delete address object "{name}"?').replace('{name}', o.name))) return
    try { await api.deleteAddressObject(o.id); load() } catch (err) { setError(err.message) }
  }
  const removeSvc = async (o) => {
    if (!window.confirm(t('Delete service object "{name}"?').replace('{name}', o.name))) return
    try { await api.deleteServiceObject(o.id); load() } catch (err) { setError(err.message) }
  }

  return (
    <div>
      <div className="page-head">
        <h1>{t('Object catalog')}</h1>
        <span className="muted">
          {t('Reusable address and service objects – when the IP of an address object changes, every rule using that alias follows automatically')}
        </span>
      </div>
      {error && <div className="error">{error}</div>}
      {notice && <div className="okbox">{notice}</div>}

      <div className="detail-grid">
        <section className="card">
          <h2>{t('Address objects')} ({addresses.length})</h2>
          <div className="table-wrap">
            <table>
              <thead><tr><th>{t('Name (alias)')}</th><th>{t('IP/network')}</th><th>{t('Description')}</th><th></th></tr></thead>
              <tbody>
                {addresses.map((o) => (
                  <tr key={o.id}>
                    <td><strong>{o.name}</strong></td>
                    <td><code>{o.ip}</code></td>
                    <td>{o.description}</td>
                    <td className="row-actions">
                      <button className="btn btn-ghost"
                        onClick={() => { setAddrEditId(o.id); setAddrForm({ name: o.name, ip: o.ip, description: o.description }) }}>
                        {t('Edit')}
                      </button>
                      <button className="btn btn-ghost" onClick={() => removeAddr(o)}>{t('Delete')}</button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <form onSubmit={submitAddr} className="object-form">
            <div className="grid-3">
              <label>{t('Name/alias')}<input value={addrForm.name}
                onChange={(e) => setAddrForm({ ...addrForm, name: e.target.value })}
                placeholder={t('e.g. web01.demo.local')} required /></label>
              <label>{t('IP/network')}<input value={addrForm.ip}
                onChange={(e) => setAddrForm({ ...addrForm, ip: e.target.value })}
                placeholder={t('e.g. 10.10.10.5')} required /></label>
              <label>{t('Description')}<input value={addrForm.description}
                onChange={(e) => setAddrForm({ ...addrForm, description: e.target.value })} /></label>
            </div>
            <div className="actions">
              <button className="btn btn-primary" type="submit">{addrEditId ? t('Save (IP is propagated)') : t('Create')}</button>
              {addrEditId && <button type="button" className="btn btn-ghost"
                onClick={() => { setAddrEditId(null); setAddrForm(EMPTY_ADDR) }}>{t('Cancel')}</button>}
            </div>
          </form>
        </section>

        <section className="card">
          <h2>{t('Service objects')} ({services.length})</h2>
          <div className="table-wrap">
            <table>
              <thead><tr><th>{t('Name')}</th><th>{t('Protocol')}</th><th>Port</th><th>{t('Description')}</th><th></th></tr></thead>
              <tbody>
                {services.map((o) => (
                  <tr key={o.id}>
                    <td><strong>{o.name}</strong></td>
                    <td><code>{o.protocol}</code></td>
                    <td><code>{o.port || '–'}</code></td>
                    <td>{o.description}</td>
                    <td className="row-actions">
                      <button className="btn btn-ghost" onClick={() => removeSvc(o)}>{t('Delete')}</button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <form onSubmit={submitSvc} className="object-form">
            <div className="grid-3">
              <label>{t('Name')}<input value={svcForm.name}
                onChange={(e) => setSvcForm({ ...svcForm, name: e.target.value })}
                placeholder={t('e.g. HTTPS')} required /></label>
              <label>{t('Protocol')}
                <select value={svcForm.protocol}
                  onChange={(e) => setSvcForm({ ...svcForm, protocol: e.target.value })}>
                  <option>TCP</option><option>UDP</option><option>TCP/UDP</option>
                  <option>ICMP</option><option>ANY</option>
                </select>
              </label>
              <label>Port<input value={svcForm.port}
                onChange={(e) => setSvcForm({ ...svcForm, port: e.target.value })}
                placeholder={t('e.g. 443')} /></label>
            </div>
            <div className="actions">
              <button className="btn btn-primary" type="submit">{t('Create')}</button>
            </div>
          </form>
        </section>

        <EpgSection />
      </div>
    </div>
  )
}
