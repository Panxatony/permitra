import { useEffect, useState } from 'react'
import { Link, useNavigate, useParams } from 'react-router-dom'
import { useLang } from '../i18n'
import { api } from '../api'

const EMPTY = {
  rule_id: '',
  name: '',
  application: '',
  app_id: '',
  component_ids: [],
  source_zone: '',
  destination_zone: '',
  source: [{ ip: '', alias: '' }],
  destination: [{ ip: '', alias: '' }],
  services: [{ protocol: 'TCP', port: '' }],
  action: 'permit',
  description: '',
  justification: '',
  business_context: '',
  info: '',
  requestor: '',
  owner: '',
  change_id: '',
  valid_from: '',
  valid_until: '',
}

function ZoneSelect({ label, value, onChange, zones }) {
  // Bestehende Werte (Altdaten) beibehalten, auch wenn sie keine gepflegte Zone sind
  const known = zones.some((z) => z.name.toUpperCase() === (value || '').toUpperCase())
  return (
    <label>
      {label}
      <select value={value} onChange={onChange}>
        <option value="">{t('– Zone wählen –')}</option>
        {!known && value && <option value={value}>{value} (nicht gepflegt)</option>}
        {zones.map((z) => <option key={z.id} value={z.name}>{z.name}</option>)}
      </select>
    </label>
  )
}

export default function RuleForm() {
  const { id } = useParams()
  const isEdit = Boolean(id)
  const navigate = useNavigate()
  const { t } = useLang()
  const [form, setForm] = useState(EMPTY)
  const [zones, setZones] = useState([])
  const [components, setComponents] = useState([])
  const [zoneCheck, setZoneCheck] = useState(null)
  const [resolved, setResolved] = useState({ components: [], unknown: [] })
  const [reqSettings, setReqSettings] = useState({})
  useEffect(() => { api.settings().then(setReqSettings).catch(() => {}) }, [])
  const [assignments, setAssignments] = useState({}) // ip -> [componentIds] für neue Adressen
  const [changeNote, setChangeNote] = useState('')
  const [error, setError] = useState('')

  const [addressObjects, setAddressObjects] = useState([])
  const [serviceObjects, setServiceObjects] = useState([])

  useEffect(() => {
    api.zones().then(setZones).catch(() => setZones([]))
    api.components().then(setComponents).catch(() => setComponents([]))
    api.addressObjects().then(setAddressObjects).catch(() => setAddressObjects([]))
    api.serviceObjects().then(setServiceObjects).catch(() => setServiceObjects([]))
  }, [])

  // Nur syntaktisch gültige Einträge an die Auflösung schicken
  const validEntries = (entries) =>
    entries.filter((e) => {
      const ip = (e.ip || '').trim()
      return ip && (ip.toLowerCase() === 'any' || /^[0-9a-fA-F.:]+(\/\d{1,3})?$/.test(ip))
    }).map((e) => ({ ip: e.ip.trim(), alias: (e.alias || '').trim() }))

  // Komponenten automatisch aus Quelle/Ziel ermitteln (debounced)
  useEffect(() => {
    const src = validEntries(form.source)
    const dst = validEntries(form.destination)
    if (!src.length && !dst.length) {
      setResolved({ components: [], unknown: [] })
      return
    }
    const t = setTimeout(() => {
      api.resolveComponents({
        source: src, destination: dst,
        source_zone: form.source_zone, destination_zone: form.destination_zone,
      }).then((res) => {
        setResolved(res)
        // Zonen werden aus den Netzwerk-Zuordnungen abgeleitet
        setForm((f) => ({
          ...f,
          source_zone: res.source_zone || '',
          destination_zone: res.destination_zone || '',
        }))
      }).catch(() => setResolved({ components: [], unknown: [] }))
    }, 400)
    return () => clearTimeout(t)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [JSON.stringify(form.source), JSON.stringify(form.destination), form.source_zone, form.destination_zone])

  // Plattformen für die Zonen-Matrix-Prüfung: aus ermittelten + neu zugeordneten Komponenten
  const assignedIds = Object.values(assignments).flat()
  const effectivePlatforms = [...new Set([
    ...resolved.components.map((c) => c.type),
    ...components.filter((c) => assignedIds.includes(c.id)).map((c) => c.type),
  ])]

  // Live-Prüfung gegen die Zonen-Kommunikationsmatrix
  useEffect(() => {
    if (!form.source_zone || !form.destination_zone) {
      setZoneCheck(null)
      return
    }
    const t = setTimeout(() => {
      api.zoneCheck(form.source_zone, form.destination_zone, effectivePlatforms)
        .then(setZoneCheck)
        .catch(() => setZoneCheck(null))
    }, 300)
    return () => clearTimeout(t)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [form.source_zone, form.destination_zone, JSON.stringify(effectivePlatforms)])

  const toggleAssignment = (ip, componentId) => {
    const current = assignments[ip] || []
    const next = current.includes(componentId)
      ? current.filter((x) => x !== componentId)
      : [...current, componentId]
    setAssignments({ ...assignments, [ip]: next })
  }

  useEffect(() => {
    if (isEdit) {
      api.rule(id).then((r) =>
        setForm({
          ...r,
          component_ids: (r.components || []).map((c) => c.id),
          source: r.source?.length ? r.source : [{ ip: '', alias: '' }],
          destination: r.destination?.length ? r.destination : [{ ip: '', alias: '' }],
          valid_from: r.valid_from || '',
          valid_until: r.valid_until || '',
        }),
      )
    } else {
      api.nextId().then((d) => setForm((f) => ({ ...f, rule_id: d.rule_id })))
    }
  }, [id, isEdit])

  const set = (key) => (e) => setForm({ ...form, [key]: e.target.value })


  const setService = (i, key, value) => {
    const services = form.services.map((s, j) => (i === j ? { ...s, [key]: value } : s))
    setForm({ ...form, services })
  }
  const addService = () => setForm({ ...form, services: [...form.services, { protocol: 'TCP', port: '' }] })
  const removeService = (i) =>
    setForm({ ...form, services: form.services.filter((_, j) => j !== i) })

  // Adress-Einträge (Quelle/Ziel): immer IP/Netz + optionaler Alias
  const setEntry = (field, i, key, value) => {
    const entries = form[field].map((e, j) => (i === j ? { ...e, [key]: value } : e))
    setForm({ ...form, [field]: entries })
  }
  const addEntry = (field) =>
    setForm({ ...form, [field]: [...form[field], { ip: '', alias: '' }] })
  const removeEntry = (field, i) =>
    setForm({ ...form, [field]: form[field].filter((_, j) => j !== i) })

  // Als Funktion gerendert (kein eigener Komponenten-Typ), damit Inputs den Fokus behalten
  const renderAddressEditor = (field, label) => (
    <div className="address-editor">
      <span className="addr-label">{label}</span>
      {form[field].map((e, i) => (
        <div key={i} className="service-row">
          <input placeholder='IP oder Netz, z.B. 10.10.30.5 oder 10.10.20.0/24 oder "any"'
            value={e.ip} onChange={(ev) => setEntry(field, i, 'ip', ev.target.value)} />
          <input placeholder="Alias (Hostname / Netzwerkname, optional)"
            value={e.alias} onChange={(ev) => setEntry(field, i, 'alias', ev.target.value)} />
          {form[field].length > 1 && (
            <button type="button" className="btn btn-ghost" onClick={() => removeEntry(field, i)}>✕</button>
          )}
        </div>
      ))}
      <div className="catalog-pick">
        <button type="button" className="btn btn-ghost" onClick={() => addEntry(field)}>{t('+ Eintrag')}</button>
        {addressObjects.length > 0 && (
          <select value="" onChange={(ev) => {
            const obj = addressObjects.find((o) => String(o.id) === ev.target.value)
            if (!obj) return
            const entries = form[field].filter((e) => e.ip || e.alias)
            setForm({ ...form, [field]: [...entries, { ip: obj.ip, alias: obj.name }] })
          }}>
            <option value="">+ aus Objektkatalog…</option>
            {addressObjects.map((o) => <option key={o.id} value={o.id}>{o.name} ({o.ip})</option>)}
          </select>
        )}
      </div>
    </div>
  )

  // Adressen aus unbekannten Netzen: erst das Netzwerk anlegen und einer Zone
  // zuordnen – die Komponenten-Abfrage erscheint für sie noch nicht
  const unassigned = resolved.unassigned || []
  const unknownAssignable = resolved.unknown.filter((u) => !unassigned.includes(u.ip))

  const submit = async (e) => {
    e.preventDefault()
    setError('')
    if (unassigned.length) {
      setError(
        t('Folgende Netze sind keiner Sicherheitszone zugeordnet:') + ` ${unassigned.join(', ')}. `
        + t('Bitte zuerst auf der Seite „Netzwerke“ anlegen und einer Sicherheitszone zuordnen.'),
      )
      return
    }
    // Neue Adressen: Zuordnung muss einmalig festgelegt sein und wird gespeichert
    const missing = unknownAssignable.filter((u) => !(assignments[u.ip] || []).length)
    if (missing.length) {
      setError(
        `Bitte festlegen, auf welchen Komponenten Regeln für folgende neue Adressen `
        + `angelegt werden sollen: ${missing.map((u) => u.ip).join(', ')}`,
      )
      return
    }
    const payload = {
      ...form,
      component_ids: [],  // Komponenten werden serverseitig aus den Adressen ermittelt
      valid_from: form.valid_from || null,
      valid_until: form.valid_until || null,
    }
    try {
      for (const u of unknownAssignable) {
        await api.saveAddressMap({ ip: u.ip, alias: u.alias, component_ids: assignments[u.ip] })
      }
      if (isEdit) {
        await api.updateRule(id, { ...payload, change_note: changeNote })
        navigate(`/rules/${id}`)
      } else {
        const created = await api.createRule(payload)
        navigate(`/rules/${created.rule_id}`)
      }
    } catch (err) {
      setError(err.message)
    }
  }

  return (
    <form className="rule-form" onSubmit={submit}>
      <h1>{isEdit ? `${t('Bearbeiten')}: ${id}` : t('Neue Regel anlegen')}</h1>
      {error && <div className="error">{error}</div>}

      <fieldset>
        <legend>{t('Identifikation')}</legend>
        <div className="grid-3">
          <label>
            Rule-ID <span className="muted">{t('(wird automatisch vergeben)')}</span>
            <input value={form.rule_id} disabled readOnly />
          </label>
          <label>Name<input value={form.name} onChange={set('name')} placeholder="z.B. HTTPS-Webserver" /></label>
          <label>Application<input value={form.application} onChange={set('application')} placeholder="z.B. Control, ePA" /></label>
          <label>APP-ID<input value={form.app_id} onChange={set('app_id')} placeholder="z.B. APP-4711" /></label>
        </div>
        <div className="platform-select">
          <span>{t('Umsetzung auf Komponenten (automatisch aus Quelle/Ziel ermittelt):')}</span>
          {resolved.components.length
            ? resolved.components.map((c) => (
                <span key={c.id} className={`badge platform-${c.type}`}
                  title={{ juniper: 'Firewall-Regel (Juniper)', checkpoint: 'Firewall-Regel (Check Point)', aci: 'ACI Contract' }[c.type]}>
                  {c.name}
                </span>
              ))
            : <span className="muted">{t('– wird nach Eingabe von Quelle und Ziel ermittelt –')}</span>}
        </div>
      </fieldset>

      <fieldset>
        <legend>{t('Verkehrsbeziehung')}</legend>
        <div className="grid-2">
          <label>{t('Quell-Zone (automatisch aus den Netzen)')}
            <div className="derived-zone">{form.source_zone
              ? <span className="badge status-approved">{form.source_zone}</span>
              : <span className="muted">–</span>}</div>
          </label>
          <label>{t('Ziel-Zone (automatisch aus den Netzen)')}
            <div className="derived-zone">{form.destination_zone
              ? <span className="badge status-approved">{form.destination_zone}</span>
              : <span className="muted">–</span>}</div>
          </label>
        </div>
        {renderAddressEditor('source', t('Quelle (IP/Netz + optionaler Alias)'))}
        {renderAddressEditor('destination', t('Ziel (IP/Netz + optionaler Alias)'))}
        {unassigned.length > 0 && (
          <div className="warnbox">
            <strong>{t('Unbekanntes Netz:')}</strong>{' '}
            {unassigned.map((ip, i) => <span key={ip}>{i > 0 && ', '}<code>{ip}</code></span>)}{' '}
            {t('ist keinem bekannten Netzwerk zugeordnet. Bitte das Netzwerk zuerst auf der Seite')}{' '}
            <Link to="/networks">{t('Netzwerke')}</Link>{' '}
            {t('hinzufügen und einer Sicherheitszone zuordnen (Freigabe durch zwei Change Approver). Danach kann die Regel angelegt werden.')}
          </div>
        )}
        {unknownAssignable.length > 0 && (
          <div className="warnbox">
            <strong>Neue Adresse(n):</strong> Bitte einmalig festlegen, auf welchen Komponenten
            Regeln für diese Adressen angelegt werden sollen (die Zuordnung wird gespeichert
            und künftig automatisch angewendet):
            {unknownAssignable.map((u) => (
              <div key={u.ip} className="unknown-address">
                <code>{u.ip}</code>{u.alias ? <span className="muted"> {u.alias}</span> : null}
                <span className="assign-options">
                  {components.map((c) => (
                    <label key={c.id} className="checkbox">
                      <input type="checkbox"
                        checked={(assignments[u.ip] || []).includes(c.id)}
                        onChange={() => toggleAssignment(u.ip, c.id)} />
                      <span className={`badge platform-${c.type}`}>{c.name}</span>
                    </label>
                  ))}
                </span>
              </div>
            ))}
          </div>
        )}
        {(resolved.zone_issues || []).length > 0 && (
          <div className="warnbox">
            {resolved.zone_issues.map((m, i) => <div key={i}>{m}</div>)}
          </div>
        )}
        {zoneCheck && (
          <div className={zoneCheck.allowed ? (zoneCheck.messages.length ? 'warnbox' : 'okbox') : 'error'}>
            {zoneCheck.allowed
              ? zoneCheck.policy === 'allow_only'
                ? `✓ Zonen-Matrix: Regeln ${form.source_zone} → ${form.destination_zone} erlaubt (Firewall)`
                : zoneCheck.policy === 'intra'
                  ? '✓ Intra-Zonen-Verkehr (gleiche Zone, typischerweise ACI)'
                  : '· Zonen-Beziehung nicht in der Matrix gepflegt'
              : `✕ Zonen-Matrix verbietet Regeln ${form.source_zone} → ${form.destination_zone} (Block)`}
            {zoneCheck.messages.map((m, i) => <div key={i} className="small">{m}</div>)}
          </div>
        )}
        <div className="services-edit">
          <span>{t('Dienste:')}</span>
          {form.services.map((s, i) => (
            <div key={i} className="service-row">
              <select value={s.protocol} onChange={(e) => setService(i, 'protocol', e.target.value)}>
                <option>TCP</option><option>UDP</option><option>TCP/UDP</option>
                <option>ICMP</option><option>ANY</option>
              </select>
              <input placeholder='Port, z.B. 443 oder 8000-8080' value={s.port}
                onChange={(e) => setService(i, 'port', e.target.value)} />
              {form.services.length > 1 && (
                <button type="button" className="btn btn-ghost" onClick={() => removeService(i)}>✕</button>
              )}
            </div>
          ))}
          <div className="catalog-pick">
            <button type="button" className="btn btn-ghost" onClick={addService}>{t('+ Dienst')}</button>
            {serviceObjects.length > 0 && (
              <select value="" onChange={(ev) => {
                const obj = serviceObjects.find((o) => String(o.id) === ev.target.value)
                if (!obj) return
                // leere Default-Zeilen (TCP ohne Port) beim Übernehmen entfernen
                const kept = form.services.filter((s) => s.port || s.protocol.startsWith('ICMP'))
                setForm({ ...form, services: [...kept, { protocol: obj.protocol, port: obj.port }] })
              }}>
                <option value="">+ aus Objektkatalog…</option>
                {serviceObjects.map((o) => (
                  <option key={o.id} value={o.id}>{o.name} ({o.protocol}{o.port ? `/${o.port}` : ''})</option>
                ))}
              </select>
            )}
          </div>
        </div>
        <label className="inline">
          {t('Aktion:')}
          <select value={form.action} onChange={set('action')}>
            <option value="permit">permit</option>
            <option value="deny">deny</option>
          </select>
        </label>
      </fieldset>

      <fieldset>
        <legend>{t('Metadaten')}</legend>
        <label>{t('Anlass / Begründung')}{reqSettings.require_justification === 'yes' && ' *'}
          <textarea rows={2} value={form.justification} onChange={set('justification')}
            required={reqSettings.require_justification === 'yes'} /></label>
        <label>{t('Beschreibung')}<textarea rows={2} value={form.description} onChange={set('description')} /></label>
        <div className="grid-3">
          <label>Requestor{reqSettings.require_requestor === 'yes' && ' *'}
            <input value={form.requestor} onChange={set('requestor')}
              required={reqSettings.require_requestor === 'yes'} /></label>
          <label>Bearbeiter / Verantwortlich<input value={form.owner} onChange={set('owner')} /></label>
          <label>Change-ID<input value={form.change_id} onChange={set('change_id')} placeholder="z.B. CHN0000273" /></label>
          <label>Fachlicher Bezug<input value={form.business_context} onChange={set('business_context')} /></label>
          <label>{t('Gültig ab')}<input type="date" value={form.valid_from} onChange={set('valid_from')} /></label>
          <label>{t('Gültig bis')}{reqSettings.require_valid_until === 'yes' && ' *'}
            <input type="date" value={form.valid_until} onChange={set('valid_until')}
              required={reqSettings.require_valid_until === 'yes'} /></label>
        </div>
        <label>Info<textarea rows={2} value={form.info} onChange={set('info')} /></label>
        {isEdit && (
          <label>Änderungsnotiz (für die Versionshistorie)
            <input value={changeNote} onChange={(e) => setChangeNote(e.target.value)} placeholder="Was wurde geändert und warum?" />
          </label>
        )}
      </fieldset>

      <div className="actions">
        <button className="btn btn-primary" type="submit">{isEdit ? t('Änderungen speichern') : t('Regel anlegen')}</button>
        <button className="btn btn-ghost" type="button" onClick={() => navigate(-1)}>{t('Abbrechen')}</button>
      </div>
    </form>
  )
}
