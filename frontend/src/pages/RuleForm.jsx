import { useEffect, useState } from 'react'
import { Link, useLocation, useNavigate, useParams } from 'react-router-dom'
import { HelpLink } from '../components/shared'
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
  log_level: 'detailed',
  description: '',
  justification: '',
  business_context: '',
  info: '',
  change_id: '',
  valid_from: '',
  valid_until: '',
}

function ZoneSelect({ label, value, onChange, zones }) {
  // Keep existing values (legacy data) even when they are not a maintained zone
  const known = zones.some((z) => z.name.toUpperCase() === (value || '').toUpperCase())
  return (
    <label>
      {label}
      <select value={value} onChange={onChange}>
        <option value="">{t('– select zone –')}</option>
        {!known && value && <option value={value}>{value} (nicht gepflegt)</option>}
        {zones.map((z) => <option key={z.id} value={z.name}>{z.name}</option>)}
      </select>
    </label>
  )
}

export default function RuleForm() {
  const { id } = useParams()
  const isEdit = Boolean(id)
  /* The rule is already on the firewall; this form is the documentation being
     caught up afterwards. Same fields, same checks - what differs is that the
     reason is mandatory and the rule lands in review with a clock on it. */
  const isEmergency = !isEdit && new URLSearchParams(useLocation().search).has('emergency')
  const [emergencyReason, setEmergencyReason] = useState('')
  const navigate = useNavigate()
  const { t } = useLang()
  const [form, setForm] = useState(EMPTY)
  const [zones, setZones] = useState([])
  const [components, setComponents] = useState([])
  const [zoneCheck, setZoneCheck] = useState(null)
  const [resolved, setResolved] = useState({ components: [], unknown: [] })
  const [reqSettings, setReqSettings] = useState({})
  useEffect(() => { api.settings().then(setReqSettings).catch(() => {}) }, [])
  const [assignments, setAssignments] = useState({}) // ip -> [componentIds] for new addresses
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

  // Only send syntactically valid entries to the resolver
  const validEntries = (entries) =>
    entries.filter((e) => {
      const ip = (e.ip || '').trim()
      return ip && (ip.toLowerCase() === 'any' || /^[0-9a-fA-F.:]+(\/\d{1,3})?$/.test(ip))
    }).map((e) => ({ ip: e.ip.trim(), alias: (e.alias || '').trim() }))

  // Derive components automatically from source/destination (debounced)
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
        // Zones are derived from the network assignments
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

  // Platforms for the zone matrix check: from resolved + newly assigned components
  const assignedIds = Object.values(assignments).flat()
  const effectivePlatforms = [...new Set([
    ...resolved.components.map((c) => c.type),
    ...components.filter((c) => assignedIds.includes(c.id)).map((c) => c.type),
  ])]

  // Live check against the zone communication matrix
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

  // Address entries (source/destination): always IP/network + optional alias
  const setEntry = (field, i, key, value) => {
    const entries = form[field].map((e, j) => (i === j ? { ...e, [key]: value } : e))
    setForm({ ...form, [field]: entries })
  }
  const addEntry = (field) =>
    setForm({ ...form, [field]: [...form[field], { ip: '', alias: '' }] })
  const removeEntry = (field, i) =>
    setForm({ ...form, [field]: form[field].filter((_, j) => j !== i) })

  // Rendered as a function (not its own component type) so the inputs keep focus
  const renderAddressEditor = (field, label) => (
    <div className="address-editor">
      <span className="addr-label">{label}</span>
      {form[field].map((e, i) => (
        <div key={i} className="service-row">
          <input placeholder={t('IP or network, e.g. 10.10.30.5 or 10.10.20.0/24 or "any"')}
            value={e.ip} onChange={(ev) => setEntry(field, i, 'ip', ev.target.value)} />
          <input placeholder="Alias (Hostname / Netzwerkname, optional)"
            value={e.alias} onChange={(ev) => setEntry(field, i, 'alias', ev.target.value)} />
          {form[field].length > 1 && (
            <button type="button" className="btn btn-ghost" onClick={() => removeEntry(field, i)}>✕</button>
          )}
        </div>
      ))}
      <div className="catalog-pick">
        <button type="button" className="btn btn-ghost" onClick={() => addEntry(field)}>{t('+ Entry')}</button>
        {addressObjects.length > 0 && (
          <select value="" onChange={(ev) => {
            const obj = addressObjects.find((o) => String(o.id) === ev.target.value)
            if (!obj) return
            const entries = form[field].filter((e) => e.ip || e.alias)
            setForm({ ...form, [field]: [...entries, { ip: obj.ip, alias: obj.name }] })
          }}>
            <option value="">{t('+ from the object catalog…')}</option>
            {addressObjects.map((o) => <option key={o.id} value={o.id}>{o.name} ({o.ip})</option>)}
          </select>
        )}
      </div>
    </div>
  )

  // Addresses from unknown networks: the network has to be created and assigned
  // to a zone first - the component prompt does not appear for them yet
  const unassigned = resolved.unassigned || []
  const unknownAssignable = resolved.unknown.filter((u) => !unassigned.includes(u.ip))

  const submit = async (e) => {
    e.preventDefault()
    setError('')
    if (unassigned.length) {
      setError(
        t('The following networks are not assigned to a security zone:') + ` ${unassigned.join(', ')}. `
        + t('Please first add them on the "Networks" page and assign them to a security zone.'),
      )
      return
    }
    // New addresses: the assignment has to be set once and is then stored
    const missing = unknownAssignable.filter((u) => !(assignments[u.ip] || []).length)
    if (missing.length) {
      setError(t('Please decide which components rules should be created on for these new addresses: {addresses}')
        .replace('{addresses}', missing.map((u) => u.ip).join(', ')))
      return
    }
    const payload = {
      ...form,
      component_ids: [],  // components are resolved from the addresses on the server
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
        const created = isEmergency
          ? await api.declareEmergencyRule({ ...payload, emergency_reason: emergencyReason })
          : await api.createRule(payload)
        navigate(`/rules/${created.rule_id}`)
      }
    } catch (err) {
      setError(err.message)
    }
  }

  return (
    <form className="rule-form" onSubmit={submit}>
      <h1>
        {isEdit ? `${t('Edit')}: ${id}`
          : isEmergency ? <>{t('Document an emergency change')} <HelpLink topic="emergency" label={t('How the emergency path works')} /></> : t('Create new rule')}
      </h1>
      {error && <div className="error">{error}</div>}
      {isEmergency && (
        <div className="emergency-box">
          <p>
            <strong>{t('This rule is already on the device.')}</strong>{' '}
            {t('It goes into review with a clock on it: without an approval after the '
               + 'fact it is deactivated automatically and has to be removed again.')}
          </p>
          <label>
            {t('What happened?')} <span className="req">*</span>
            <textarea rows={3} required minLength={10} value={emergencyReason}
              onChange={(e) => setEmergencyReason(e.target.value)}
              placeholder={t('Incident, ticket, who was reachable – a year from now this is all there is')} />
          </label>
        </div>
      )}

      <fieldset>
        <legend>{t('Identification')}</legend>
        <div className="grid-3">
          <label>
            Rule-ID <span className="muted">{t('(assigned automatically)')}</span>
            <input value={form.rule_id} disabled readOnly />
          </label>
          <label>Name<input value={form.name} onChange={set('name')} placeholder="z.B. HTTPS-Webserver" /></label>
          <label>Application<input value={form.application} onChange={set('application')} placeholder="z.B. Control, ePA" /></label>
          <label>APP-ID<input value={form.app_id} onChange={set('app_id')} placeholder="z.B. APP-4711" /></label>
        </div>
        <div className="platform-select">
          <span>{t('Implemented on components (derived automatically from source/destination):')}</span>
          {resolved.components.length
            ? resolved.components.map((c) => (
                <span key={c.id} className={`badge platform-${c.type}`}
                  title={t({ juniper: 'Firewall rule (Juniper)', checkpoint: 'Firewall rule (Check Point)', aci: 'ACI Contract' }[c.type])}>
                  {c.name}
                </span>
              ))
            : <span className="muted">{t('– determined once source and destination are entered –')}</span>}
        </div>
      </fieldset>

      <fieldset>
        <legend>{t('Traffic relationship')}</legend>
        <div className="grid-2">
          <label>{t('Source zone (derived from networks)')}
            <div className="derived-zone">{form.source_zone
              ? <span className="badge status-approved">{form.source_zone}</span>
              : <span className="muted">–</span>}</div>
          </label>
          <label>{t('Destination zone (derived from networks)')}
            <div className="derived-zone">{form.destination_zone
              ? <span className="badge status-approved">{form.destination_zone}</span>
              : <span className="muted">–</span>}</div>
          </label>
        </div>
        {renderAddressEditor('source', t('Source (IP/network + optional alias)'))}
        {renderAddressEditor('destination', t('Destination (IP/network + optional alias)'))}
        {unassigned.length > 0 && (
          <div className="warnbox">
            <strong>{t('Unknown network:')}</strong>{' '}
            {unassigned.map((ip, i) => <span key={ip}>{i > 0 && ', '}<code>{ip}</code></span>)}{' '}
            {t('does not belong to any known network. Please first add the network on the')}{' '}
            <Link to="/networks">{t('Networks')}</Link>{' '}
            {t('page and assign it to a security zone (approval by two change approvers). The rule can be created afterwards.')}
          </div>
        )}
        {unknownAssignable.length > 0 && (
          <div className="warnbox">
            <strong>{t('New address(es):')}</strong>{' '}
            {t('Please decide once which components rules for these addresses should be created on (the mapping is stored and applied automatically from then on):')}
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
                ? `✓ ${t('Zone matrix: rules {from} → {to} allowed (firewall)')
                    .replace('{from}', form.source_zone).replace('{to}', form.destination_zone)}`
                : zoneCheck.policy === 'intra'
                  ? t('✓ Intra-zone traffic (same zone, typically ACI)')
                  : t('· Zone relationship not maintained in the matrix')
              : `✕ ${t('Zone matrix forbids rules {from} → {to} (Block)')
                    .replace('{from}', form.source_zone).replace('{to}', form.destination_zone)}`}
            {zoneCheck.messages.map((m, i) => <div key={i} className="small">{m}</div>)}
          </div>
        )}
        <div className="services-edit">
          <span>{t('Services:')}</span>
          {form.services.map((s, i) => (
            <div key={i} className="service-row">
              <select value={s.protocol} onChange={(e) => setService(i, 'protocol', e.target.value)}>
                <option>TCP</option><option>UDP</option><option>TCP/UDP</option>
                <option>ICMP</option><option>ANY</option>
              </select>
              <input placeholder={t('Port, e.g. 443 or 8000-8080')} value={s.port}
                onChange={(e) => setService(i, 'port', e.target.value)} />
              {form.services.length > 1 && (
                <button type="button" className="btn btn-ghost" onClick={() => removeService(i)}>✕</button>
              )}
            </div>
          ))}
          <div className="catalog-pick">
            <button type="button" className="btn btn-ghost" onClick={addService}>{t('+ Service')}</button>
            {serviceObjects.length > 0 && (
              <select value="" onChange={(ev) => {
                const obj = serviceObjects.find((o) => String(o.id) === ev.target.value)
                if (!obj) return
                // drop empty default rows (TCP without a port) when applying
                const kept = form.services.filter((s) => s.port || s.protocol.startsWith('ICMP'))
                setForm({ ...form, services: [...kept, { protocol: obj.protocol, port: obj.port }] })
              }}>
                <option value="">{t('+ from the object catalog…')}</option>
                {serviceObjects.map((o) => (
                  <option key={o.id} value={o.id}>{o.name} ({o.protocol}{o.port ? `/${o.port}` : ''})</option>
                ))}
              </select>
            )}
          </div>
        </div>
        <label className="inline">
          {t('Action:')}
          <select value={form.action} onChange={set('action')}>
            <option value="permit">permit</option>
            {/* Two refusals, and the difference is operational: drop discards
                silently and the caller waits out a timeout, reject answers and
                the caller gets an immediate error. The hint says which is
                which, because the words alone do not. */}
            <option value="deny">{t('deny (drop – silent, caller sees a timeout)')}</option>
            <option value="reject">{t('reject (answers – caller sees an error at once)')}</option>
          </select>
        </label>
        <label className="inline">
          {t('Logging:')}
          <select value={form.log_level} onChange={set('log_level')}>
            <option value="none">{t('none')}</option>
            <option value="standard">{t('standard (log each match)')}</option>
            <option value="detailed">{t('detailed (incl. session end)')}</option>
          </select>
        </label>
      </fieldset>

      <fieldset>
        <legend>{t('Metadata')}</legend>
        <label>{t('Reason / justification')}{reqSettings.require_justification === 'yes' && ' *'}
          <textarea rows={2} value={form.justification} onChange={set('justification')}
            required={reqSettings.require_justification === 'yes'} /></label>
        <label>{t('Description')}<textarea rows={2} value={form.description} onChange={set('description')} /></label>
        <div className="grid-3">
          {/* Requestor and owner are recorded, not entered: the requestor is
              the signed-in account that creates the rule, the owner is whoever
              last maintains the implementation status. A typed name can be
              misspelled and matches nobody in the reports; an account cannot. */}
          <label>{t('Change ID')}<input value={form.change_id} onChange={set('change_id')} placeholder={t('e.g. CHN0000273')} /></label>
          <label>{t('Business context')}<input value={form.business_context} onChange={set('business_context')} /></label>
          <label>{t('Valid from')}<input type="date" value={form.valid_from} onChange={set('valid_from')} /></label>
          <label>{t('Valid until')}{reqSettings.require_valid_until === 'yes' && ' *'}
            <input type="date" value={form.valid_until} onChange={set('valid_until')}
              required={reqSettings.require_valid_until === 'yes'} /></label>
        </div>
        <label>Info<textarea rows={2} value={form.info} onChange={set('info')} /></label>
        {isEdit && (
          <label>Änderungsnotiz (für die Versionshistorie)
            <input value={changeNote} onChange={(e) => setChangeNote(e.target.value)} placeholder={t('What was changed and why?')} />
          </label>
        )}
      </fieldset>

      <div className="actions">
        <button className="btn btn-primary" type="submit">{isEdit ? t('Save changes') : t('Create rule')}</button>
        <button className="btn btn-ghost" type="button" onClick={() => navigate(-1)}>{t('Cancel')}</button>
      </div>
    </form>
  )
}
