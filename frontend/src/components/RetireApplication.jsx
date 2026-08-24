import { useEffect, useState } from 'react'
import { api } from '../api'
import { useLang } from '../i18n'
import { Modal } from './shared'

/* Retiring an application (#85): the application is switched off, so the holes
   it needed should go too. Rules outliving their application is one of the most
   common ways a ruleset rots.

   The dialogue is built around the preview, not around the button. A bulk
   action whose scope is only visible after it has run is one nobody dares press
   - so nothing happens until the list of affected rules has been on screen. */
export default function RetireApplication({ onDone }) {
  const { t } = useLang()
  const [open, setOpen] = useState(false)
  const [apps, setApps] = useState([])
  const [appId, setAppId] = useState('')
  const [reason, setReason] = useState('')
  const [preview, setPreview] = useState(null)
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)

  useEffect(() => {
    if (!open) return
    api.applicationSummary()
      .then((d) => setApps(d.items || []))
      .catch((e) => setError(e.message))
  }, [open])

  const close = () => {
    setOpen(false)
    setAppId(''); setReason(''); setPreview(null); setError(''); setBusy(false)
  }

  const run = async (dryRun) => {
    setError(''); setBusy(true)
    try {
      const result = await api.retireApplication(appId, reason, dryRun)
      if (dryRun) {
        setPreview(result)
      } else {
        close()
        onDone?.(result)
      }
    } catch (e) {
      setError(e.message)
    } finally {
      setBusy(false)
    }
  }

  // The reason becomes the removal reason on every rule, so it is required
  // before anything is previewed - not caught later on submit.
  const ready = appId && reason.trim()

  return (
    <>
      <button className="btn btn-ghost" onClick={() => setOpen(true)}>
        {t('Retire application')}
      </button>
      {open && (
        <Modal title={t('Retire application')} onClose={close}>
          <p className="muted small">
            {t('Proposes every rule in force for this application for removal. Nothing is removed here: each rule goes back into review and is decided one at a time – and whoever starts this cannot approve those removals themselves.')}
          </p>
          {error && <div className="error">{error}</div>}

          <label>{t('Application')}
            <select value={appId} onChange={(e) => { setAppId(e.target.value); setPreview(null) }}>
              <option value="">{t('Please choose…')}</option>
              {apps.map((a) => (
                <option key={a.app_id} value={a.app_id}>
                  {a.app_id} ({a.in_force})
                </option>
              ))}
            </select>
          </label>
          {!apps.length && !error && (
            <p className="muted small">{t('No rule carries an application ID yet.')}</p>
          )}

          <label>{t('Reason')}
            <input value={reason} onChange={(e) => { setReason(e.target.value); setPreview(null) }}
              placeholder={t('e.g. replaced by SAP, decommissioned 2026-09-30')} />
          </label>

          {preview && (
            <div className="retire-preview">
              <p><strong>{t('{count} rule(s) would be proposed for removal')
                .replace('{count}', preview.total)}</strong></p>
              <div className="table-wrap">
                <table>
                  <thead>
                    <tr>
                      <th>{t('Rule ID')}</th><th>{t('Name')}</th>
                      <th>{t('Zones')}</th><th>{t('Requestor')}</th>
                    </tr>
                  </thead>
                  <tbody>
                    {preview.proposed.map((r) => (
                      <tr key={r.rule_id}>
                        <td><code>{r.rule_id}</code></td>
                        <td>{r.name}</td>
                        <td>{r.source_zone} → {r.destination_zone}</td>
                        <td>{r.requestor}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
              {preview.skipped?.length > 0 && (
                <p className="muted small">
                  {t('Not proposed (not in force):')}{' '}
                  {preview.skipped.map((s) => `${s.rule_id} (${t(s.status)})`).join(', ')}
                </p>
              )}
            </div>
          )}

          <div className="actions">
            <button className="btn" onClick={() => run(true)} disabled={!ready || busy}>
              {t('Preview')}
            </button>
            {/* Deliberately only reachable once the preview has been seen. */}
            <button className="btn btn-danger" onClick={() => run(false)}
              disabled={!preview || !preview.total || busy}>
              {t('Propose for removal')}
            </button>
            <button className="btn btn-ghost" onClick={close}>{t('Cancel')}</button>
          </div>
        </Modal>
      )}
    </>
  )
}
