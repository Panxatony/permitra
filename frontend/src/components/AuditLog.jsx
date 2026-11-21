import { useCallback, useEffect, useState } from 'react'
import { api } from '../api'
import { dateLocale, useLang } from '../i18n'

const LIMITS = [50, 200, 500, 2000]

/* The audit log with its chain check. One component for the two places it is
   read: the admin's settings page, where it is one card among several, and the
   auditor's own page, where it is the whole point - there with a period and a
   larger slice (`full`). Anchoring the chain head writes and is offered to the
   admin only (`canAnchor`); the backend refuses it to everybody else anyway.

   `refreshKey` lets the surrounding page ask for a reload after it changed
   something that produced an event. */
export default function AuditLog({ canAnchor = false, full = false, refreshKey = 0 }) {
  const { lang, t } = useLang()
  const [events, setEvents] = useState([])
  const [integrity, setIntegrity] = useState(null)
  const [siem, setSiem] = useState(null)
  const [limit, setLimit] = useState(50)
  const [since, setSince] = useState('')
  const [error, setError] = useState('')
  const [notice, setNotice] = useState('')

  const load = useCallback(() => {
    const params = { limit }
    if (since) params.since = since
    api.auditLog(params).then(setEvents).catch((e) => { setEvents([]); setError(e.message) })
    api.auditSiemStatus().then(setSiem).catch(() => setSiem(null))
  }, [limit, since])
  useEffect(() => { load() }, [load, refreshKey])

  const act = async (fn) => {
    setError('')
    setNotice('')
    try {
      const message = await fn()
      if (message) setNotice(message)
    } catch (err) {
      setError(err.message)
    }
  }

  const verify = () => act(async () => { setIntegrity(await api.auditVerify()) })
  const anchor = () => act(async () => {
    const r = await api.auditCheckpoint()
    setSiem(await api.auditSiemStatus())
    setIntegrity(await api.auditVerify())
    return r.event_count ? `${t('Chain end anchored at entry')} ${r.event_count}` : r.detail
  })

  return (
    <section className="card" style={{ marginTop: '1rem' }}>
      <h3>{t('Audit log')}{' '}
        {!full && <span className="muted small">{t('(last 50 events; full log via the /api/audit-log API for SIEM)')}</span>}
      </h3>
      {error && <div className="error">{error}</div>}
      {notice && <div className="infobox">{notice}</div>}
      <div className="row" style={{ display: 'flex', gap: '.6rem', alignItems: 'center', flexWrap: 'wrap', marginBottom: '.8rem' }}>
        {full && (
          <>
            <label className="inline">{t('From')}{' '}
              <input type="date" value={since} onChange={(e) => setSince(e.target.value)} />
            </label>
            <label className="inline">{t('Newest entries')}{' '}
              <select value={limit} onChange={(e) => setLimit(Number(e.target.value))}>
                {LIMITS.map((n) => <option key={n} value={n}>{n}</option>)}
              </select>
            </label>
          </>
        )}
        <button className="btn btn-ghost" onClick={verify}>{t('Verify integrity')}</button>
        {integrity && (integrity.ok
          ? <span className="pill" style={{ background: 'var(--green-bg)', color: 'var(--green)', borderColor: 'var(--green-border)' }}>
              ✓ {t('Chain intact')} ({integrity.checked} {t('entries')})
            </span>
          : <span className="pill" style={{ background: 'var(--red-bg)', color: 'var(--red)', borderColor: 'var(--red-border)' }}>
              ✗ {t('Chain broken')} – ID {integrity.broken_at_id}: {integrity.reason}
            </span>)}
        {canAnchor && <button className="btn btn-ghost" onClick={anchor}>{t('Anchor now')}</button>}
        {siem && (
          <span className="muted small">
            {t('SIEM delivery')}: {siem.enabled ? t('active') : t('not configured')}
            {' · '}{t('pending')}: {siem.pending} · {t('sent')}: {siem.sent}
            {siem.skipped ? ` · ${t('no sink')}: ${siem.skipped}` : ''}
            {siem.anchor
              ? ` · ${t('anchored at')}: ${siem.anchor.event_count}` +
                (siem.enabled
                  ? (siem.anchor.delivered ? ` (${t('sent to SIEM')})`
                                           : ` (${t('delivery pending')})`)
                  : '')
              : ` · ${t('not anchored yet')}`}
          </span>
        )}
      </div>
      <div className="table-wrap">
        <table>
          <thead>
            <tr><th>{t('Time')}</th><th>{t('Event')}</th><th>{t('Object')}</th><th>{t('By')}</th><th>{t('Source IP')}</th><th>{t('Details')}</th></tr>
          </thead>
          <tbody>
            {events.map((e, i) => (
              <tr key={i}>
                <td className="small">{e.timestamp ? new Date(e.timestamp).toLocaleString(dateLocale(lang)) : '–'}</td>
                <td><code>{e.event}</code></td>
                <td>{e.object}</td>
                <td>{e.actor || '–'}</td>
                <td className="small">{e.source_ip || '–'}</td>
                <td className="small">{e.detail || (e.status ? t(e.status) : '')}</td>
              </tr>
            ))}
            {!events.length && <tr><td colSpan={6} className="muted">{t('No entries.')}</td></tr>}
          </tbody>
        </table>
      </div>
      {full && events.length >= limit && (
        <p className="muted small">
          {t('More entries exist than shown – narrow the period or raise the number. The complete log is available through the API.')}
        </p>
      )}
    </section>
  )
}
