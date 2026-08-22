import { useCallback, useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { api, getUser } from '../api'
import { useLang } from '../i18n'

/* Focused home page for change approvers: everything awaiting approval -
   rule reviews (one approval) and zone/network batch requests (two approvals). */
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
      comment = window.prompt(t('Reason for rejection:')) ?? ''
      if (comment === '') return
    }
    act(() => (approve ? api.approve(rule.rule_id, comment) : api.reject(rule.rule_id, comment)),
      approve ? `${rule.rule_id} ${t('approved')}` : `${rule.rule_id} ${t('rejected')}`)
  }

  const decideBatch = (batch, approve) => {
    const id = batch.items[0].id
    act(() => (approve ? api.approveMatrixChange(id) : api.rejectMatrixChange(id)),
      approve ? t('Approval granted') : t('Request rejected'))
  }

  const itemLabel = (c) => {
    if (c.change_type === 'zone_create') return `${t('New zone')}: ${c.from_zone} (${c.new_policy})`
    if (c.change_type === 'zone_delete') return `${t('Delete zone')}: ${c.from_zone}`
    if (c.change_type === 'net_add') return `${t('Network')} ${c.to_zone} → ${t('Zone')} ${c.from_zone}`
    if (c.change_type === 'net_delete') return `${t('Network')} ${c.to_zone} ${t('from zone')} ${c.from_zone} ${t('remove')}`
    if (c.change_type === 'net_update') {
      const oldZone = c.extra?.old_zone, oldCidr = c.extra?.old_cidr
      const parts = []
      if (oldCidr && oldCidr !== c.to_zone) parts.push(`${oldCidr} → ${c.to_zone}`)
      if (oldZone && oldZone !== c.from_zone) parts.push(`${t('Zone')} ${oldZone} → ${c.from_zone}`)
      return `${t('Network')} ${oldCidr || c.to_zone}: ${parts.join(', ') || c.from_zone}`
    }
    return `${c.from_zone} → ${c.to_zone}: `
      + `${c.old_policy ? (c.old_policy === 'allow_only' ? 'Allow' : 'Block') : t('new')}`
      + ` → ${c.new_policy === 'allow_only' ? 'Allow' : 'Block'}`
  }

  const fmtAddr = (entries) => (entries || [])
    .map((e) => e.alias || e.ip).slice(0, 3).join(', ')
    + ((entries || []).length > 3 ? ` +${entries.length - 3}` : '')

  return (
    <div>
      <div className="page-head">
        <h1>{t('Approvals')}</h1>
        <span className="muted">
          {t('Everything awaiting your decision – rule reviews (one approval) and zone/network requests (two approvals by different approvers).')}
        </span>
      </div>

      {error && <div className="error">{error}</div>}
      {notice && <div className="infobox">{notice}</div>}

      <section className="card wide" style={{ marginBottom: '1rem' }}>
        <h2>{t('Open rule reviews')} ({reviews.length})</h2>
        {reviews.length === 0 && <p className="muted">{t('No rules in review – all done.')}</p>}
        {reviews.length > 0 && (
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Rule-ID</th><th>{t('Name')}</th><th>{t('Zones')}</th>
                  <th>{t('Source')}</th><th>{t('Destination')}</th><th>{t('Requested by')}</th><th></th>
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
                          title={t('The zone relationship is set to block – approving confirms removal of the rule.')}>
                          ⚠ {t('Relationship: block → removal')}
                        </span></div>
                      )}
                    </td>
                    <td className="small">{fmtAddr(r.source)}</td>
                    <td className="small">{fmtAddr(r.destination)}</td>
                    <td>{r.created_by}</td>
                    <td className="row-actions">
                      <button className="btn btn-primary" onClick={() => decideRule(r, true)}>
                        {r.zone_blocked ? t('Approve removal') : t('Approve')}
                      </button>
                      <button className="btn btn-ghost" onClick={() => decideRule(r, false)}>{t('Reject')}</button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>

      <section className="card wide">
        <h2>{t('Open zone & network requests')} ({batches.length})</h2>
        {batches.length === 0 && <p className="muted">{t('No open requests.')}</p>}
        {batches.map((b) => (
          <div key={b.key} className="approval-box" style={{ marginBottom: '.8rem' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', gap: '1rem', flexWrap: 'wrap' }}>
              <div>
                <strong>{t('Request by')} {b.requested_by}</strong>{' '}
                <span className="muted small">
                  · {t('Approvals')}: {b.first_approved_by ? `1/2 (${b.first_approved_by})` : '0/2'}
                </span>
                <ul style={{ margin: '.4rem 0 0 1.2rem' }}>
                  {b.items.map((c) => (
                    <li key={c.id}>
                      {itemLabel(c)}
                      {c.affected_count > 0 && c.change_type === 'net_update' && (
                        <div className="warnbox" style={{ margin: '.35rem 0 .2rem', padding: '.4rem .6rem' }}>
                          ⚠ {t('The move affects')} <strong>{c.affected_count}</strong>{' '}
                          {t('rule(s)')}
                          {c.removal_count > 0 && (
                            <>{' – '}<strong>{c.removal_count}</strong>{' '}
                              {t('of them become inadmissible and go to review for removal')}</>
                          )}
                          {':'}
                          <ul style={{ margin: '.3rem 0 0 1.1rem', padding: 0 }}>
                            {c.affected_rules.map((r) => (
                              <li key={r.rule_id} className="small">
                                <Link to={`/rules/${r.rule_id}`} className="rule-link">{r.rule_id}</Link>
                                {' '}<code>{r.from}</code> → <code>{r.to}</code>
                                {r.admissible
                                  ? <span className="muted"> ({t('stays admissible, zones will be updated')})</span>
                                  : <strong style={{ color: 'var(--red)' }}>
                                      {' '}({t('to be removed')}{r.reason ? `: ${r.reason}` : ''})
                                    </strong>}
                              </li>
                            ))}
                          </ul>
                          {c.affected_count > c.affected_rules.length && ' …'}
                        </div>
                      )}
                      {c.affected_count > 0 && c.change_type !== 'net_update' && (
                        <div className="warnbox" style={{ margin: '.35rem 0 .2rem', padding: '.4rem .6rem' }}>
                          ⚠ {t('Affects')} <strong>{c.affected_count}</strong> {t('active rule(s) of this relationship')}{' – '}
                          {t('approved ones will be reset to review when this is approved:')}{' '}
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
                  {t('Approve')}
                </button>
                <button className="btn btn-ghost" onClick={() => decideBatch(b, false)}>{t('Reject')}</button>
              </div>
            </div>
            {b.first_approved_by === user.username && (
              <p className="muted small" style={{ marginTop: '.4rem' }}>
                {t('You have already approved – the second approval must come from a different change approver.')}
              </p>
            )}
          </div>
        ))}
        <p className="muted small">
          {t('Details and history on the page')} <Link to="/zones">{t('Security zones')}</Link>.
        </p>
      </section>
    </div>
  )
}
