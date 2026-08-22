import { useCallback, useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { api, getUser } from '../api'
import { useLang } from '../i18n'

/* Fokussierte Startseite für Change Approver: alles, was auf Freigabe wartet –
   Regel-Reviews (eine Freigabe) und Zonen-/Netzwerk-Sammelanträge (zwei Freigaben). */
export default function Approvals() {
  const { t } = useLang()
  const user = getUser()
  const [reviews, setReviews] = useState([])
  const [batches, setBatches] = useState([])
  const [error, setError] = useState('')
  const [notice, setNotice] = useState('')

  const load = useCallback(async () => {
    try {
      const [rules, changes, matrix, settings] = await Promise.all([
        api.rules({ status: 'in_review', limit: 200 }),
        api.matrixChanges(),
        api.zoneMatrix().catch(() => ({ policies: [] })),
        api.settings().catch(() => ({})),
      ])
      const policyMap = {}
      matrix.policies.forEach((p) => { policyMap[`${p.from_zone}|${p.to_zone}`] = p.policy })
      const denyDefault = settings.zone_matrix_default === 'deny'
      setReviews(rules.items.map((r) => {
        const key = `${r.source_zone}|${r.destination_zone}`
        const policy = policyMap[key]
        const intra = (r.source_zone || '').toUpperCase() === (r.destination_zone || '').toUpperCase()
        return { ...r, zone_blocked: !intra && (policy === 'block_all' || (denyDefault && !policy)) }
      }))
      const pending = changes.filter((c) => c.status === 'pending')
      const byBatch = {}
      const grouped = []
      pending.forEach((c) => {
        const key = c.batch_id || `single-${c.id}`
        if (!byBatch[key]) {
          byBatch[key] = { key, items: [], requested_by: c.requested_by,
            requested_at: c.requested_at, first_approved_by: c.first_approved_by }
          grouped.push(byBatch[key])
        }
        byBatch[key].items.push(c)
      })
      setBatches(grouped)
    } catch (err) {
      setError(err.message)
    }
  }, [])
  useEffect(() => { load() }, [load])

  const act = async (fn, successMsg) => {
    setError('')
    setNotice('')
    try {
      const result = await fn()
      setNotice(result?.detail || successMsg)
      load()
    } catch (err) {
      setError(err.message)
    }
  }

  const decideRule = (rule, approve) => {
    let comment = ''
    if (!approve) {
      comment = window.prompt(t('Begründung für die Ablehnung:')) ?? ''
      if (comment === '') return
    }
    act(() => (approve ? api.approve(rule.rule_id, comment) : api.reject(rule.rule_id, comment)),
      approve ? `${rule.rule_id} ${t('freigegeben')}` : `${rule.rule_id} ${t('abgelehnt')}`)
  }

  const decideBatch = (batch, approve) => {
    const id = batch.items[0].id
    act(() => (approve ? api.approveMatrixChange(id) : api.rejectMatrixChange(id)),
      approve ? t('Freigabe erteilt') : t('Antrag abgelehnt'))
  }

  const itemLabel = (c) => {
    if (c.change_type === 'zone_create') return `${t('Neue Zone')}: ${c.from_zone} (${c.new_policy})`
    if (c.change_type === 'net_add') return `${t('Netz')} ${c.to_zone} → ${t('Zone')} ${c.from_zone}`
    if (c.change_type === 'net_delete') return `${t('Netz')} ${c.to_zone} ${t('aus Zone')} ${c.from_zone} ${t('entfernen')}`
    if (c.change_type === 'net_update') {
      const oldZone = c.extra?.old_zone, oldCidr = c.extra?.old_cidr
      const parts = []
      if (oldCidr && oldCidr !== c.to_zone) parts.push(`${oldCidr} → ${c.to_zone}`)
      if (oldZone && oldZone !== c.from_zone) parts.push(`${t('Zone')} ${oldZone} → ${c.from_zone}`)
      return `${t('Netz')} ${oldCidr || c.to_zone}: ${parts.join(', ') || c.from_zone}`
    }
    return `${c.from_zone} → ${c.to_zone}: `
      + `${c.old_policy ? (c.old_policy === 'allow_only' ? 'Allow' : 'Block') : t('neu')}`
      + ` → ${c.new_policy === 'allow_only' ? 'Allow' : 'Block'}`
  }

  const fmtAddr = (entries) => (entries || [])
    .map((e) => e.alias || e.ip).slice(0, 3).join(', ')
    + ((entries || []).length > 3 ? ` +${entries.length - 3}` : '')

  return (
    <div>
      <div className="page-head">
        <h1>{t('Freigaben')}</h1>
        <span className="muted">
          {t('Alles, was auf deine Entscheidung wartet – Regel-Reviews (eine Freigabe) und Zonen-/Netzwerk-Anträge (zwei Freigaben durch verschiedene Approver).')}
        </span>
      </div>

      {error && <div className="error">{error}</div>}
      {notice && <div className="infobox">{notice}</div>}

      <section className="card wide" style={{ marginBottom: '1rem' }}>
        <h2>{t('Offene Regel-Reviews')} ({reviews.length})</h2>
        {reviews.length === 0 && <p className="muted">{t('Keine Regeln im Review – alles erledigt.')}</p>}
        {reviews.length > 0 && (
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Rule-ID</th><th>{t('Name')}</th><th>{t('Zonen')}</th>
                  <th>{t('Quelle')}</th><th>{t('Ziel')}</th><th>{t('Beantragt von')}</th><th></th>
                </tr>
              </thead>
              <tbody>
                {reviews.map((r) => (
                  <tr key={r.rule_id}>
                    <td><Link to={`/rules/${r.rule_id}`} className="rule-link">{r.rule_id}</Link></td>
                    <td>{r.name}</td>
                    <td>
                      {r.source_zone} → {r.destination_zone}
                      {r.zone_blocked && (
                        <div><span className="badge status-rejected"
                          title={t('Die Zonen-Beziehung ist auf Block – Freigeben bestätigt die Löschung der Regel.')}>
                          ⚠ {t('Beziehung: Block → Löschung')}
                        </span></div>
                      )}
                    </td>
                    <td className="small">{fmtAddr(r.source)}</td>
                    <td className="small">{fmtAddr(r.destination)}</td>
                    <td>{r.created_by}</td>
                    <td className="row-actions">
                      <button className="btn btn-primary" onClick={() => decideRule(r, true)}>
                        {r.zone_blocked ? t('Löschung freigeben') : t('Freigeben')}
                      </button>
                      <button className="btn btn-ghost" onClick={() => decideRule(r, false)}>{t('Ablehnen')}</button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>

      <section className="card wide">
        <h2>{t('Offene Zonen- & Netzwerk-Anträge')} ({batches.length})</h2>
        {batches.length === 0 && <p className="muted">{t('Keine offenen Anträge.')}</p>}
        {batches.map((b) => (
          <div key={b.key} className="approval-box" style={{ marginBottom: '.8rem' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', gap: '1rem', flexWrap: 'wrap' }}>
              <div>
                <strong>{t('Antrag von')} {b.requested_by}</strong>{' '}
                <span className="muted small">
                  · {t('Freigaben')}: {b.first_approved_by ? `1/2 (${b.first_approved_by})` : '0/2'}
                </span>
                <ul style={{ margin: '.4rem 0 0 1.2rem' }}>
                  {b.items.map((c) => (
                    <li key={c.id}>
                      {itemLabel(c)}
                      {c.affected_count > 0 && (
                        <div className="warnbox" style={{ margin: '.35rem 0 .2rem', padding: '.4rem .6rem' }}>
                          ⚠ {t('Betrifft')} <strong>{c.affected_count}</strong> {t('aktive Regel(n) dieser Beziehung')}{' – '}
                          {t('freigegebene werden bei Freigabe in den Review zurückgesetzt:')}{' '}
                          {c.affected_rules.map((r, i) => (
                            <span key={r.rule_id}>
                              {i > 0 && ', '}
                              <Link to={`/rules/${r.rule_id}`} className="rule-link">{r.rule_id}</Link>
                              <span className="muted small"> ({t(
                                { approved: 'Freigegeben', in_review: 'Im Review', draft: 'Entwurf' }[r.status] || r.status)})</span>
                            </span>
                          ))}
                          {c.affected_count > c.affected_rules.length && ' …'}
                        </div>
                      )}
                    </li>
                  ))}
                </ul>
              </div>
              <div className="row-actions" style={{ alignSelf: 'center' }}>
                <button className="btn btn-primary" onClick={() => decideBatch(b, true)}
                  disabled={b.first_approved_by === user.username}>
                  {t('Freigeben')}
                </button>
                <button className="btn btn-ghost" onClick={() => decideBatch(b, false)}>{t('Ablehnen')}</button>
              </div>
            </div>
            {b.first_approved_by === user.username && (
              <p className="muted small" style={{ marginTop: '.4rem' }}>
                {t('Du hast bereits freigegeben – die zweite Freigabe muss ein anderer Change Approver erteilen.')}
              </p>
            )}
          </div>
        ))}
        <p className="muted small">
          {t('Details und Historie auf der Seite')} <Link to="/zones">{t('Sicherheitszonen')}</Link>.
        </p>
      </section>
    </div>
  )
}
