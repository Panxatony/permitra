import { useCallback, useEffect, useState } from 'react'
import { Link, useNavigate, useParams } from 'react-router-dom'
import { api, getUser } from '../api'
import RiskCriteria from '../components/RiskCriteria'
import { AddressList, ComponentBadges, Highlighted, ServiceList, StatusBadge, useZoneLabels } from '../components/shared'
import { useLang } from '../i18n'

const IMPL_OPTIONS = ['open', 'new', 'to change', 'to remove', 'implemented', 'deactivated']

export default function RuleDetail() {
  const { id } = useParams()
  const user = getUser()
  const navigate = useNavigate()
  const { t } = useLang()
  const zoneLabel = useZoneLabels()
  const [rule, setRule] = useState(null)
  const [impl, setImpl] = useState(null)
  const [conflicts, setConflicts] = useState([])
  const [risk, setRisk] = useState(null)
  const [comment, setComment] = useState('')
  const [reviewComment, setReviewComment] = useState('')
  const [error, setError] = useState('')

  const load = useCallback(async () => {
    try {
      setRule(await api.rule(id))
      api.conflicts(id).then(setConflicts).catch(() => setConflicts([]))
      api.risk(id).then(setRisk).catch(() => setRisk(null))
      api.implementation(id).then(setImpl).catch(() => setImpl(null))
    } catch (err) {
      setError(err.message)
    }
  }, [id])

  useEffect(() => { load() }, [load])

  if (error) return <div className="error">{error}</div>
  if (!rule) return <p className="muted">Lade…</p>

  const isArchitect = user.role === 'architect' || user.role === 'admin'
  const isOps = user.role === 'operations' || user.role === 'admin'
  const isApprover = user.role === 'change_approver' || user.role === 'admin'

  const act = (fn) => async () => {
    setError('')
    try {
      await fn()
      setReviewComment('')
      await load()
    } catch (err) {
      setError(err.message)
    }
  }

  const addComment = async (e) => {
    e.preventDefault()
    if (!comment.trim()) return
    await api.addComment(id, comment)
    setComment('')
    load()
  }

  return (
    <div className="rule-detail">
      <div className="page-head">
        <h1>{rule.rule_id} <span className="muted">{rule.name}</span></h1>
        <StatusBadge status={rule.status} />
      </div>

      {rule.removal_reason && (
        <div className="error">
          <strong>🗑️ {t('Proposed for removal')}</strong>
          <p style={{ margin: '.3rem 0 0' }}>{rule.removal_reason}</p>
          <p className="small" style={{ margin: '.4rem 0 0' }}>
            {t('An approved change made this rule inadmissible. Approving it here means approving its removal – the rule is deactivated and rolled back on the components. Alternatively, rework the rule until it is admissible again.')}
          </p>
        </div>
      )}

      {risk && risk.level !== 'none' && (
        <div className={risk.level === 'high' ? 'error' : 'warnbox'}>
          <strong>⚠️ {t('Risk')}: {risk.level.toUpperCase()}</strong>
          {' '}({t('Target protection level')}: {risk.target_protection_level})
          <ul>
            {risk.findings.map((f, i) => (
              <li key={i}><span className={`badge risk-${f.severity}`}>{f.severity}</span> {f.detail}</li>
            ))}
          </ul>
          {/* Whoever has to decide on this rule must be able to check the
              yardstick it was measured by - collapsed, so it does not compete
              with the finding itself. */}
          <details className="small">
            <summary style={{ cursor: 'pointer' }}>{t('By which criteria?')}</summary>
            <div className="inset-reference"><RiskCriteria /></div>
          </details>
        </div>
      )}
      {conflicts.length > 0 && (
        <div className="warnbox">
          ⚠️ {conflicts.length} mögliche Konflikte:
          <ul>
            {conflicts.slice(0, 6).map((c, i) => (
              <li key={i}>
                {c.kind.startsWith('zone') ? (
                  <><strong>{c.other_rule_id}</strong> – {c.detail} <Link to="/zones">(Zonen-Matrix)</Link></>
                ) : (
                  <><Link to={`/rules/${c.other_rule_id}`}>{c.other_rule_id}</Link> – {c.detail} ({c.kind})</>
                )}
              </li>
            ))}
            {conflicts.length > 6 && <li>… und {conflicts.length - 6} weitere</li>}
          </ul>
        </div>
      )}

      <div className="detail-grid">
        <section className="card">
          <h2>{t('Traffic relationship')}</h2>
          <dl>
            <dt>{t('Components')}</dt><dd><ComponentBadges components={rule.components} /></dd>
            <dt>{t('Source zone')}</dt><dd>{zoneLabel(rule.source_zone) || '–'}</dd>
            <dt>{t('Source')}</dt><dd className="addr"><AddressList entries={rule.source} /></dd>
            <dt>{t('Destination zone')}</dt><dd>{zoneLabel(rule.destination_zone) || '–'}</dd>
            <dt>{t('Destination')}</dt><dd className="addr"><AddressList entries={rule.destination} /></dd>
            <dt>{t('Services')}</dt><dd><ServiceList services={rule.services} /></dd>
            <dt>{t('Action')}</dt><dd><code>{rule.action}</code></dd>
          </dl>
        </section>

        <section className="card">
          <h2>{t('Metadata')}</h2>
          <dl>
            <dt>Application</dt><dd>{rule.application || '–'}</dd>
            <dt>APP-ID</dt><dd>{rule.app_id || '–'}</dd>
            <dt>{t('Reason')}</dt><dd>{rule.justification || '–'}</dd>
            <dt>{t('Description')}</dt><dd>{rule.description || '–'}</dd>
            <dt>Requestor</dt><dd>{rule.requestor || '–'}</dd>
            <dt>Bearbeiter</dt><dd>{rule.owner || '–'}</dd>
            <dt>Change-ID</dt><dd>{rule.change_id || '–'}</dd>
            <dt>Fachlicher Bezug</dt><dd>{rule.business_context || '–'}</dd>
            <dt>{t('Validity')}</dt>
            <dd>{rule.valid_from || '…'} – {rule.valid_until || t('unlimited')}</dd>
            <dt>Info</dt><dd>{rule.info || '–'}</dd>
            <dt>Version</dt><dd>v{rule.version} · angelegt von {rule.created_by}</dd>
          </dl>
        </section>

        <section className="card">
          <h2>{t('Workflow')}</h2>
          <div className="workflow-actions">
            {isArchitect && ['draft', 'rejected'].includes(rule.status) && (
              <>
                <button className="btn btn-primary" onClick={act(() => api.submit(id))}>{t('Submit for review')}</button>
                <button className="btn" onClick={() => navigate(`/rules/${id}/edit`)}>{t('Edit')}</button>
              </>
            )}
            {isArchitect && !['draft', 'rejected'].includes(rule.status) && (
              <button className="btn" onClick={() => navigate(`/rules/${id}/edit`)}>
                {t('Edit (resets review)')}
              </button>
            )}
            {isApprover && rule.status === 'in_review' && (() => {
              const zoneBlocked = conflicts.some((c) => c.kind === 'zone-blocked')
              return (
                <div className="review-box">
                  {zoneBlocked && (
                    <div className="warnbox">
                      ⚠ {t('The zone relationship is set to block – "approve" confirms removal: the rule is deactivated, each component is set to "to remove" and it appears for operations as open implementation work (decommissioning).')}
                    </div>
                  )}
                  <textarea rows={2} placeholder={t('Review comment (optional)')} value={reviewComment}
                    onChange={(e) => setReviewComment(e.target.value)} />
                  <div>
                    <button className="btn btn-approve" onClick={act(() => api.approve(id, reviewComment))}>
                      {zoneBlocked ? `✓ ${t('Approve removal')}` : t('✓ Approve')}
                    </button>
                    <button className="btn btn-reject" onClick={act(() => api.reject(id, reviewComment))}>{t('✕ Reject')}</button>
                  </div>
                </div>
              )
            })()}
            {rule.status === 'approved' && (isOps || isArchitect) && (
              <button className="btn btn-ghost" onClick={act(() => api.deactivate(id, reviewComment))}>{t('Deactivate rule')}</button>
            )}
            {rule.status === 'approved' && (
              <Link className="btn" to={`/export?ids=${rule.rule_id}`}>{t('Export configuration →')}</Link>
            )}
          </div>

          <h3>{t('Implementation status per component (operations)')}</h3>
          <div className="impl-status">
            {(rule.components || []).map((c) => (
              <label key={c.id} className="inline">
                <span className={`badge platform-${c.type}`}>{c.name}</span>
                <select
                  disabled={!isOps}
                  value={rule.impl_status?.[c.name] || 'open'}
                  onChange={(e) => act(() => api.setImplStatus(id, { [c.name]: e.target.value }))()}
                >
                  {IMPL_OPTIONS.map((o) => <option key={o} value={o}>{t(o)}</option>)}
                </select>
              </label>
            ))}
            {!(rule.components || []).length && <span className="muted">{t('No components assigned.')}</span>}
          </div>
        </section>

        <section className="card">
          <h2>{t('Comments')} ({rule.comments.length})</h2>
          <ul className="comments">
            {rule.comments.map((c) => (
              <li key={c.id}>
                <strong>{c.author}</strong>
                <span className="muted small"> · {new Date(c.created_at).toLocaleString('de-DE')}</span>
                <p>{c.text}</p>
              </li>
            ))}
          </ul>
          <form onSubmit={addComment} className="comment-form">
            <textarea rows={2} value={comment} onChange={(e) => setComment(e.target.value)}
              placeholder={t('Comment for the review…')} />
            <button className="btn" type="submit">{t('Comment')}</button>
          </form>
        </section>

        <section className="card wide">
          <h2>{t('Implementation on the components')}</h2>
          {!impl ? <p className="muted">{t('Loading…')}</p> : impl.implementations.map((entry) => (
            <div key={entry.component_id} className="impl-block">
              <div className="path-comp-head">
                <span className={`badge platform-${entry.type}`}>{entry.component}</span>
                <span className="badge">{entry.impl_status}</span>
                {entry.note && <span className="muted small">{entry.note}</span>}
              </div>
              {entry.aci && (
                <p className="small">
                  Consumer <strong>{entry.aci.consumer}</strong> → Provider{' '}
                  <strong>{entry.aci.provider}</strong> · Contract <code>{entry.aci.contract}</code>
                  {' '}· Filter {entry.aci.filters.map((f) => <code key={f} className="svc">{f}</code>)}
                  {entry.aci.service_graph && <> · Service Graph <code>{entry.aci.service_graph}</code></>}
                </p>
              )}
              {entry.warning && <div className="warnbox">{entry.warning}</div>}
              <Highlighted text={entry.preview} fmt={entry.format} />
            </div>
          ))}
        </section>

        <section className="card wide">
          <h2>{t('Version history')}</h2>
          <div className="table-wrap">
            <table>
              <thead>
                <tr><th>{t('Version')}</th><th>{t('Change')}</th><th>{t('By')}</th><th>{t('Time')}</th><th></th></tr>
              </thead>
              <tbody>
                {rule.versions.map((v) => (
                  <tr key={v.version}>
                    <td>v{v.version}</td>
                    <td>{v.change_note}</td>
                    <td>{v.changed_by}</td>
                    <td>{new Date(v.changed_at).toLocaleString('de-DE')}</td>
                    <td className="row-actions">
                      {isArchitect && v.version < rule.version && (
                        <button className="btn btn-ghost"
                          title={t('Restores this state as a new draft (normal review workflow)')}
                          onClick={() => {
                            if (!window.confirm(`${t('Reset rule to version')} v${v.version} ${t('? The state will be restored as a new draft.')}`)) return
                            act(() => api.restoreRule(id, v.version))()
                          }}>
                          ↩ {t('Restore')}
                        </button>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>
      </div>
    </div>
  )
}
