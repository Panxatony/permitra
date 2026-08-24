import { useState } from 'react'
import { api } from '../api'
import { dateLocale, useLang } from '../i18n'
import { HelpLink, StatusBadge } from './shared'

/* The target/actual comparison, on the Reports page: it is a report, not a
   property of a component - the person asking "is everything on the devices
   justified?" is running an assessment, not maintaining infrastructure. */
export default function DriftPanel({ components }) {
  const { lang, t } = useLang()
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
      <h2>{t('Target/actual comparison (drift)')} <HelpLink topic="drift" label={t('What the findings mean')} /></h2>
      <p className="muted small">
        {t('Paste the device’s actual configuration (e.g. “show configuration | display set” or a management API export) – the comparison runs over the rule IDs (SR####) that Permitra carries in every export. A direct device query can be added later as an adapter.')}
      </p>
      {error && <div className="error">{error}</div>}
      {notice && <div className="okbox">{notice}</div>}
      <label className="inline">{t('Component')}:
        <select value={selected} onChange={select}>
          <option value="">{t('– select –')}</option>
          {components.map((c) => <option key={c.id} value={c.id}>{c.name}</option>)}
        </select>
      </label>

      {selected && report && (
        report.has_config ? (
          <div className="drift-report">
            {/* The coverage figure first: "did my rules arrive" is the smaller
                question, "is everything here justified" is the point. */}
            {report.coverage?.recognised ? (
              <div className="coverage">
                <div className="coverage-bar">
                  <span style={{ width: `${report.coverage.percent}%` }} />
                </div>
                <span className="coverage-text">
                  <strong>{report.coverage.percent}%</strong>{' '}
                  {t('of the rules on this device are covered by an approved security rule')}
                  {' '}({report.coverage.justified}/{report.coverage.total})
                </span>
              </div>
            ) : (
              <p className="muted small">
                {t('This configuration format cannot be read yet, so the coverage is unknown – only the rule IDs found in it were compared.')}
              </p>
            )}
            <div className={report.in_sync ? 'okbox' : 'warnbox'}>
              {report.in_sync
                ? `✓ ${t('{component} is in sync ({expected} approved rules, {actual} on the device).')
                  .replace('{component}', report.component)
                  .replace('{expected}', report.expected_rule_count)
                  .replace('{actual}', report.actual_rule_count)}`
                : `⚠ ${t('Deviations on {component} – state as of {when} ({who})')
                  .replace('{component}', report.component)
                  .replace('{when}', new Date(report.fetched_at).toLocaleString(dateLocale(lang)))
                  .replace('{who}', report.uploaded_by)}`}
            </div>
            {!report.in_sync && (
              <div className="detail-grid">
                <div>
                  <h3>{t('Missing on the device')} ({report.missing.length})</h3>
                  <ul>{report.missing.map((r) => <li key={r.rule_id}><strong>{r.rule_id}</strong> {r.justification || r.name}</li>)}</ul>
                </div>
                <div>
                  <h3>{t('On the device but no longer approved')} ({report.stale.length})</h3>
                  <ul>{report.stale.map((r) => <li key={r.rule_id}><strong>{r.rule_id}</strong> <StatusBadge status={r.status} /></li>)}</ul>
                </div>
                <div>
                  <h3>{t('Unknown rule IDs / shadow rules')} ({report.unknown.length})</h3>
                  <ul>{report.unknown.map((rid) => <li key={rid}><code>{rid}</code></li>)}</ul>
                </div>
                <div>
                  <h3>{t('Not justified by any rule')} ({report.coverage?.unjustified?.length || 0})</h3>
                  <p className="muted small">
                    {t('On the device, but carrying no rule ID – nobody requested or approved these.')}
                  </p>
                  <ul>{(report.coverage?.unjustified || []).map((u) => (
                    <li key={u.identifier}>
                      <code>{u.identifier}</code>{' '}
                      <span className="muted small">{t('line')} {u.line}</span>
                    </li>
                  ))}</ul>
                </div>
              </div>
            )}
          </div>
        ) : (
          <p className="muted">{t('No actual configuration has been stored for this component yet.')}</p>
        )
      )}

      {selected && (
        <form onSubmit={upload} className="drift-upload">
          <textarea rows={6} value={config} onChange={(e) => setConfig(e.target.value)}
            placeholder={t('Paste the actual configuration here…\nset security policies from-zone ... policy SR0101 ...')} />
          <button className="btn btn-primary" type="submit" disabled={!config.trim()}>
            {t('Save actual configuration & compare')}
          </button>
        </form>
      )}
    </section>
  )
}
