import { useEffect, useState } from 'react'
import { api } from '../api'
import { useLang } from '../i18n'

const EMPTY_ADDR = { name: '', ip: '', description: '' }
const EMPTY_SVC = { name: '', protocol: 'TCP', port: '', description: '' }

function EpgSection() {
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
    try {
      await api.upsertEpgMap({ ...mapForm, epg_id: Number(mapForm.epg_id) })
      setMapForm({ ip: '', alias: '', epg_id: '' })
      load()
    } catch (err) { setError(err.message) }
  }

  const removeEpg = async (epg) => {
    if (!window.confirm(`EPG "${epg.name}" löschen?`)) return
    try { await api.deleteEpg(epg.id); load() } catch (err) { setError(err.message) }
  }
  const removeMap = async (m) => {
    try { await api.deleteEpgMap(m.id); load() } catch (err) { setError(err.message) }
  }

  return (
    <section className="card wide">
      <h2>ACI EPGs & Adress-Zuordnung</h2>
      <p className="muted small">
        ACI Contracts verbinden EPGs, nicht IPs: Der ACI-Export löst Quell-/Zieladressen über
        diese Zuordnung auf (Quelle → Consumer, Ziel → Provider, „any" → vzAny) und fasst alle
        Regeln eines EPG-Paars in einem Contract zusammen. Adressen ohne Zuordnung werden als
        Einzel-Contract exportiert und in den Warnungen ausgewiesen.
      </p>
      {error && <div className="error">{error}</div>}
      <div className="detail-grid">
        <div>
          <h3>EPGs ({epgs.length})</h3>
          <div className="table-wrap">
            <table>
              <thead><tr><th>Name</th><th>Tenant</th><th>App Profile</th><th>Bridge Domain</th><th></th></tr></thead>
              <tbody>
                {epgs.map((e) => (
                  <tr key={e.id}>
                    <td><strong>{e.name}</strong></td>
                    <td>{e.tenant}</td><td>{e.app_profile}</td><td>{e.bridge_domain}</td>
                    <td className="row-actions">
                      <button className="btn btn-ghost" onClick={() => removeEpg(e)}>Löschen</button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <form onSubmit={addEpg} className="object-form">
            <div className="grid-3">
              <label>Name<input value={epgForm.name} required placeholder="z.B. epg-prod-app"
                onChange={(e) => setEpgForm({ ...epgForm, name: e.target.value })} /></label>
              <label>Tenant<input value={epgForm.tenant}
                onChange={(e) => setEpgForm({ ...epgForm, tenant: e.target.value })} /></label>
              <label>App Profile<input value={epgForm.app_profile}
                onChange={(e) => setEpgForm({ ...epgForm, app_profile: e.target.value })} /></label>
              <label>Bridge Domain<input value={epgForm.bridge_domain} placeholder="z.B. BD-PROD-APP"
                onChange={(e) => setEpgForm({ ...epgForm, bridge_domain: e.target.value })} /></label>
            </div>
            <div className="actions"><button className="btn btn-primary" type="submit">EPG anlegen</button></div>
          </form>
        </div>
        <div>
          <h3>Adresse → EPG ({mappings.length})</h3>
          <div className="table-wrap">
            <table>
              <thead><tr><th>IP/Netz</th><th>Alias</th><th>EPG</th><th></th></tr></thead>
              <tbody>
                {mappings.map((m) => (
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
              <label>IP/Netz<input value={mapForm.ip} required placeholder="z.B. 10.10.30.0/24"
                onChange={(e) => setMapForm({ ...mapForm, ip: e.target.value })} /></label>
              <label>Alias<input value={mapForm.alias}
                onChange={(e) => setMapForm({ ...mapForm, alias: e.target.value })} /></label>
              <label>EPG
                <select value={mapForm.epg_id} required
                  onChange={(e) => setMapForm({ ...mapForm, epg_id: e.target.value })}>
                  <option value="">– wählen –</option>
                  {epgs.map((e) => <option key={e.id} value={e.id}>{e.name}</option>)}
                </select>
              </label>
            </div>
            <div className="actions"><button className="btn btn-primary" type="submit">Zuordnung speichern</button></div>
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
        if (res.description?.includes('Regel(n) aktualisiert')) {
          setNotice(`IP-Änderung übernommen – ${res.description.match(/\[(.*)\]/)?.[1] || ''}.`)
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
    if (!window.confirm(`Adress-Objekt "${o.name}" löschen?`)) return
    try { await api.deleteAddressObject(o.id); load() } catch (err) { setError(err.message) }
  }
  const removeSvc = async (o) => {
    if (!window.confirm(`Dienst-Objekt "${o.name}" löschen?`)) return
    try { await api.deleteServiceObject(o.id); load() } catch (err) { setError(err.message) }
  }

  return (
    <div>
      <div className="page-head">
        <h1>{t('Objektkatalog')}</h1>
        <span className="muted">
          Wiederverwendbare Adress- und Dienst-Objekte – ändert sich die IP eines
          Adress-Objekts, werden alle Regeln mit diesem Alias automatisch mitgezogen
        </span>
      </div>
      {error && <div className="error">{error}</div>}
      {notice && <div className="okbox">{notice}</div>}

      <div className="detail-grid">
        <section className="card">
          <h2>{t('Adress-Objekte')} ({addresses.length})</h2>
          <div className="table-wrap">
            <table>
              <thead><tr><th>Name (Alias)</th><th>IP/Netz</th><th>Beschreibung</th><th></th></tr></thead>
              <tbody>
                {addresses.map((o) => (
                  <tr key={o.id}>
                    <td><strong>{o.name}</strong></td>
                    <td><code>{o.ip}</code></td>
                    <td>{o.description}</td>
                    <td className="row-actions">
                      <button className="btn btn-ghost"
                        onClick={() => { setAddrEditId(o.id); setAddrForm({ name: o.name, ip: o.ip, description: o.description }) }}>
                        Bearbeiten
                      </button>
                      <button className="btn btn-ghost" onClick={() => removeAddr(o)}>Löschen</button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <form onSubmit={submitAddr} className="object-form">
            <div className="grid-3">
              <label>Name/Alias<input value={addrForm.name}
                onChange={(e) => setAddrForm({ ...addrForm, name: e.target.value })}
                placeholder="z.B. web01.demo.local" required /></label>
              <label>IP/Netz<input value={addrForm.ip}
                onChange={(e) => setAddrForm({ ...addrForm, ip: e.target.value })}
                placeholder="z.B. 10.10.10.5" required /></label>
              <label>Beschreibung<input value={addrForm.description}
                onChange={(e) => setAddrForm({ ...addrForm, description: e.target.value })} /></label>
            </div>
            <div className="actions">
              <button className="btn btn-primary" type="submit">{addrEditId ? 'Speichern (IP wird propagiert)' : 'Anlegen'}</button>
              {addrEditId && <button type="button" className="btn btn-ghost"
                onClick={() => { setAddrEditId(null); setAddrForm(EMPTY_ADDR) }}>Abbrechen</button>}
            </div>
          </form>
        </section>

        <section className="card">
          <h2>{t('Dienst-Objekte')} ({services.length})</h2>
          <div className="table-wrap">
            <table>
              <thead><tr><th>Name</th><th>Protokoll</th><th>Port</th><th>Beschreibung</th><th></th></tr></thead>
              <tbody>
                {services.map((o) => (
                  <tr key={o.id}>
                    <td><strong>{o.name}</strong></td>
                    <td><code>{o.protocol}</code></td>
                    <td><code>{o.port || '–'}</code></td>
                    <td>{o.description}</td>
                    <td className="row-actions">
                      <button className="btn btn-ghost" onClick={() => removeSvc(o)}>Löschen</button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <form onSubmit={submitSvc} className="object-form">
            <div className="grid-3">
              <label>Name<input value={svcForm.name}
                onChange={(e) => setSvcForm({ ...svcForm, name: e.target.value })}
                placeholder="z.B. HTTPS" required /></label>
              <label>Protokoll
                <select value={svcForm.protocol}
                  onChange={(e) => setSvcForm({ ...svcForm, protocol: e.target.value })}>
                  <option>TCP</option><option>UDP</option><option>TCP/UDP</option>
                  <option>ICMP</option><option>ANY</option>
                </select>
              </label>
              <label>Port<input value={svcForm.port}
                onChange={(e) => setSvcForm({ ...svcForm, port: e.target.value })}
                placeholder="z.B. 443" /></label>
            </div>
            <div className="actions">
              <button className="btn btn-primary" type="submit">Anlegen</button>
            </div>
          </form>
        </section>

        <EpgSection />
      </div>
    </div>
  )
}
