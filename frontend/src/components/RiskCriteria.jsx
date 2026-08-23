import { useEffect, useState } from 'react'
import { api } from '../api'
import { useLang } from '../i18n'

/* The yardstick behind every risk hint.

   An approver sees the hint before deciding, so the criteria have to be
   lookup-able - and an absent hint must not be read as "harmless" when it may
   only mean "not on the list". The component therefore shows all criteria to
   everyone; `editable` additionally makes the service list maintainable, which
   is an administrative act and recorded in the audit log by the backend. */
export default function RiskCriteria({ editable = false }) {
  const { t } = useLang()
  const [criteria, setCriteria] = useState(null)
  const [form, setForm] = useState({ port: '', label: '' })
  const [error, setError] = useState('')

  const load = () => api.riskCriteria().then(setCriteria).catch((e) => setError(e.message))
  useEffect(() => { load() }, [])

  const change = async (fn) => {
    setError('')
    try {
      await fn()
      await load()
      return true
    } catch (err) {
      setError(err.message)
      return false
    }
  }

  if (!criteria) {
    return <p className="muted">{error || `${t('Loading')}…`}</p>
  }

  return (
    <>
      {error && <div className="error">{error}</div>}
      <div className="table-wrap">
        <table>
          <thead>
            <tr><th>{t('Criterion')}</th><th>{t('Severity')}</th><th>{t('Applies when')}</th></tr>
          </thead>
          <tbody>
            {criteria.patterns.map((p) => (
              <tr key={p.code}>
                <td><code>{p.code}</code></td>
                <td><span className={`badge risk-${p.severity}`}>{t(p.severity)}</span></td>
                <td>
                  {p.detail}
                  {p.threshold && <span className="muted small"> ({t('threshold')} {p.threshold})</span>}
                  {p.note && <div className="muted small">{p.note}</div>}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <p className="muted small" style={{ marginTop: '.6rem' }}>
        {t('The destination zone raises the severity by its protection level:')}{' '}
        {Object.entries(criteria.protection_level_weight)
          .map(([level, steps]) => `${t(level)} +${steps}`).join(' · ')}
        . {t('A source zone at P-A-P level')}{' '}
        {criteria.exposed_pap_levels.map((l) => t(l)).join(', ')}{' '}
        {t('counts as exposed and raises a risky service to high.')}
      </p>

      <h4 style={{ marginTop: '1.2rem' }}>{t('Risky services')}</h4>
      <p className="muted small">
        {criteria.risky_ports_are_default
          ? t('Default list – not yet adapted for this installation.')
          : t('Adapted for this installation; every change is in the audit log.')}
      </p>
      <div className="table-wrap">
        <table>
          <thead>
            <tr><th>Port</th><th>{t('Name')}</th>{editable && <th></th>}</tr>
          </thead>
          <tbody>
            {criteria.risky_ports.map((p) => (
              <tr key={p.port}>
                <td><code>{p.port}</code></td>
                <td>{p.label}</td>
                {editable && (
                  <td className="row-actions">
                    {/* Edit what is stored, not what is displayed: saving the
                        translated text back would turn a shipped default into
                        own wording and freeze it in one language. */}
                    <button className="btn btn-ghost" type="button"
                      onClick={() => setForm({ port: p.port, label: p.source_label ?? p.label })}>
                      {t('Update')}
                    </button>
                    <button className="btn btn-ghost" type="button"
                      onClick={() => window.confirm(
                        t('Remove port {port} from the list? Rules using it are then no longer flagged.')
                          .replace('{port}', p.port)) && change(() => api.deleteRiskyPort(p.port))}>
                      {t('Remove')}
                    </button>
                  </td>
                )}
              </tr>
            ))}
            {!criteria.risky_ports.length && (
              <tr><td colSpan={editable ? 3 : 2} className="muted">
                {t('No services listed – no rule is flagged for its service.')}
              </td></tr>
            )}
          </tbody>
        </table>
      </div>
      {editable && (
        <form className="filterbar" style={{ marginTop: '.6rem' }} onSubmit={async (e) => {
          e.preventDefault()
          if (!form.port.trim() || !form.label.trim()) return
          if (await change(() => api.setRiskyPort(form.port.trim(), form.label.trim()))) {
            setForm({ port: '', label: '' })
          }
        }}>
          <input value={form.port} inputMode="numeric" style={{ maxWidth: '7rem' }} placeholder="Port"
            onChange={(e) => setForm({ ...form, port: e.target.value })} />
          <input value={form.label} placeholder={t('Name, e.g. "SSH (administration)"')}
            onChange={(e) => setForm({ ...form, label: e.target.value })} />
          <button className="btn btn-primary" type="submit">{t('Save service')}</button>
        </form>
      )}
    </>
  )
}
