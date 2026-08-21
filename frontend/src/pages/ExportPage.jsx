import { useCallback, useEffect, useState } from 'react'
import { useSearchParams } from 'react-router-dom'
import { api, getToken } from '../api'
import { Highlighted } from '../components/shared'
import { useLang } from '../i18n'

const FORMATS = [
  { key: 'juniper', label: 'Juniper SRX (CLI)', hint: 'set-Kommandos inkl. Address-Book und Applications' },
  { key: 'checkpoint-cli', label: 'Check Point (mgmt_cli)', hint: 'Shell-Skript für den Management-Server' },
  { key: 'checkpoint-api', label: 'Check Point (Management API)', hint: 'JSON-Payloads für die Web-API' },
  { key: 'aci-json', label: 'ACI (APIC JSON)', hint: 'fvTenant-Baum mit vzFilter und vzBrCP' },
  { key: 'aci-yaml', label: 'ACI (YAML)', hint: 'Kompakt, z.B. für Ansible' },
  { key: 'csv', label: 'CSV (Kommunikationsmatrix)', hint: 'Excel-kompatibel, Spalten wie das bisherige Sheet' },
  { key: 'json', label: 'JSON (vollständig)', hint: 'Alle Felder für Integrationen' },
]

// Capirca-/Aerleon-Anbindung: weitere Plattformen über den Policy-Generator
const AERLEON_FORMATS = [
  { key: 'aerleon-cisco', target: 'cisco', label: 'Cisco IOS (via Capirca)', hint: 'Extended ACL, generiert mit Aerleon' },
  { key: 'aerleon-ciscoasa', target: 'ciscoasa', label: 'Cisco ASA (via Capirca)', hint: 'ASA-ACLs, generiert mit Aerleon' },
  { key: 'aerleon-srx', target: 'srx', label: 'Juniper SRX zonenbasiert (via Capirca)', hint: 'Security Policies je Zonen-Paar' },
  { key: 'aerleon-paloalto', target: 'paloalto', label: 'Palo Alto (via Capirca)', hint: 'Panorama-XML je Zonen-Paar' },
  { key: 'aerleon-iptables', target: 'iptables', label: 'Linux iptables (via Capirca)', hint: 'FORWARD-Chain für Gateways' },
  { key: 'aerleon-policy', target: 'policy', label: 'Capirca/Aerleon Policy (YAML)', hint: 'Objekte + Policy für bestehende Capirca-Pipelines' },
]

const HOST_FORMATS = [
  { key: 'host-debian', os: 'debian', label: 'Host-FW: Debian (nftables)', hint: 'nftables.conf für den Ziel-Server', file: 'nftables.conf' },
  { key: 'host-redhat', os: 'redhat', label: 'Host-FW: RedHat (firewalld)', hint: 'firewall-cmd Rich Rules', file: 'firewalld-rules.sh' },
  { key: 'host-sles', os: 'sles', label: 'Host-FW: SLES (iptables)', hint: 'iptables-Skript (SLES 15: firewalld nutzen)', file: 'iptables-rules.sh' },
]

export default function ExportPage() {
  const { t } = useLang()
  const [searchParams] = useSearchParams()
  const [fmt, setFmt] = useState('juniper')
  const [ids, setIds] = useState(searchParams.get('ids') || '')
  const [onlyApproved, setOnlyApproved] = useState(!searchParams.get('ids'))
  const [components, setComponents] = useState([])
  const [componentId, setComponentId] = useState('')
  const [targetIp, setTargetIp] = useState('')

  const hostFormat = HOST_FORMATS.find((f) => f.key === fmt)
  const aerleonFormat = AERLEON_FORMATS.find((f) => f.key === fmt)

  useEffect(() => {
    api.components().then(setComponents).catch(() => setComponents([]))
  }, [])
  const [preview, setPreview] = useState('')
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)

  const load = useCallback(async (f = fmt) => {
    setLoading(true)
    setError('')
    setPreview('')
    try {
      const host = HOST_FORMATS.find((h) => h.key === f)
      const aerleon = AERLEON_FORMATS.find((a) => a.key === f)
      let text
      if (host) {
        if (!targetIp.trim()) {
          setError('Bitte eine Ziel-IP für den Host-Firewall-Export angeben.')
          return
        }
        text = await api.exportPreview(`host/${host.os}`, { ip: targetIp.trim() })
      } else if (aerleon) {
        text = await api.exportPreview(`aerleon/${aerleon.target}`,
          { only_approved: onlyApproved, component_id: componentId })
      } else {
        text = await api.exportPreview(f, { ids, only_approved: onlyApproved, component_id: componentId })
      }
      setPreview(typeof text === 'string' ? text : JSON.stringify(text, null, 2))
    } catch (err) {
      setError(err.message)
    } finally {
      setLoading(false)
    }
  }, [fmt, ids, onlyApproved, componentId, targetIp])

  useEffect(() => { load() }, [load])

  const download = () => {
    const params = new URLSearchParams({ download: 'true' })
    let path = fmt
    if (hostFormat) {
      params.set('ip', targetIp.trim())
      path = `host/${hostFormat.os}`
    } else if (aerleonFormat) {
      params.set('only_approved', onlyApproved)
      if (componentId) params.set('component_id', componentId)
      path = `aerleon/${aerleonFormat.target}`
    } else {
      params.set('only_approved', onlyApproved)
      if (ids) params.set('ids', ids)
      if (componentId) params.set('component_id', componentId)
    }
    fetch(`/api/export/${path}?${params}`, { headers: { Authorization: `Bearer ${getToken()}` } })
      .then((res) => res.blob())
      .then((blob) => {
        const a = document.createElement('a')
        a.href = URL.createObjectURL(blob)
        a.download = hostFormat
          ? `${targetIp.trim().replaceAll('/', '_')}-${hostFormat.file}`
          : aerleonFormat
            ? `permitra-${aerleonFormat.target}${aerleonFormat.target === 'policy' ? '.yaml' : '.acl'}`
            : FORMATS.find((f) => f.key === fmt)?.key + (fmt === 'csv' ? '.csv' : fmt.includes('json') ? '.json' : fmt.includes('yaml') ? '.yaml' : fmt === 'checkpoint-cli' ? '.sh' : '.conf')
        a.click()
      })
  }

  const copy = () => navigator.clipboard.writeText(preview)

  return (
    <div>
      <div className="page-head">
        <h1>{t('Konfigurations-Export')}</h1>
      </div>
      <div className="export-layout">
        <aside className="export-sidebar">
          {FORMATS.map((f) => (
            <button key={f.key}
              className={`format-btn ${f.key === fmt ? 'active' : ''}`}
              onClick={() => setFmt(f.key)}>
              <strong>{f.label}</strong>
              <span className="muted small">{f.hint}</span>
            </button>
          ))}
          <div className="export-divider muted small">{t('Weitere Plattformen via Capirca/Aerleon:')}</div>
          {AERLEON_FORMATS.map((f) => (
            <button key={f.key}
              className={`format-btn ${f.key === fmt ? 'active' : ''}`}
              onClick={() => setFmt(f.key)}>
              <strong>{f.label}</strong>
              <span className="muted small">{f.hint}</span>
            </button>
          ))}
          <div className="export-divider muted small">{t('Host-Firewall für einen Ziel-Server:')}</div>
          {HOST_FORMATS.map((f) => (
            <button key={f.key}
              className={`format-btn ${f.key === fmt ? 'active' : ''}`}
              onClick={() => setFmt(f.key)}>
              <strong>{f.label}</strong>
              <span className="muted small">{f.hint}</span>
            </button>
          ))}
          <div className="export-options">
            {hostFormat && (
              <label>{t('Ziel-IP des Servers')}
                <input value={targetIp} onChange={(e) => setTargetIp(e.target.value)}
                  placeholder="z.B. 10.10.80.10" />
              </label>
            )}
            <label>{t('Komponente (nur deren Regeln)')}
              <select value={componentId} onChange={(e) => setComponentId(e.target.value)}>
                <option value="">{t('– alle Komponenten –')}</option>
                {components.map((c) => <option key={c.id} value={c.id}>{c.name}</option>)}
              </select>
            </label>
            <label>{t('Nur bestimmte Regeln (IDs, kommagetrennt)')}
              <input value={ids} onChange={(e) => setIds(e.target.value)} placeholder="SR0855, SR0846" />
            </label>
            <label className="checkbox">
              <input type="checkbox" checked={onlyApproved} onChange={(e) => setOnlyApproved(e.target.checked)} />
              {t('Nur freigegebene Regeln')}
            </label>
            <button className="btn btn-primary" onClick={() => load()}>{t('Vorschau aktualisieren')}</button>
          </div>
        </aside>
        <section className="export-preview">
          <div className="preview-actions">
            <button className="btn" onClick={copy} disabled={!preview}>{t('In Zwischenablage')}</button>
            <button className="btn btn-primary" onClick={download} disabled={!preview}>{t('Herunterladen')}</button>
          </div>
          {error && <div className="error">{error}</div>}
          {loading ? <p className="muted">Erzeuge Vorschau…</p>
            : preview && <Highlighted text={preview} fmt={(hostFormat || aerleonFormat) ? 'checkpoint-cli' : fmt} />}
        </section>
      </div>
    </div>
  )
}
