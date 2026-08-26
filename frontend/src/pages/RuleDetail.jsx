import { useCallback, useEffect, useState } from 'react'
import { Link, useNavigate, useParams } from 'react-router-dom'
import { api, getUser, hasRole } from '../api'
import RiskCriteria from '../components/RiskCriteria'
import { AddressList, ComponentBadges, HelpLink, Modal, ServiceList, StatusBadge, useZoneLabels } from '../components/shared'
import { dateLocale, useLang } from '../i18n'

const IMPL_OPTIONS = ['open', 'new', 'to change', 'to remove', 'implemented', 'deactivated']

/* Approved and active are the same thing to act on: the rule is in force. A
   deleted rule offers no actions at all - it is documentation, not a workflow
   step, and nothing may put it back into service. */
const IN_FORCE = ['approved', 'active']

export default function RuleDetail() {
  const { id } = useParams()
  const user = getUser()
  const navigate = useNavigate()
  const { lang, t } = useLang()
  const zoneLabel = useZoneLabels()
  const openHandover = () => {
    api.architects().then(setArchitects).catch(() => setArchitects([]))
  }
  const submitHandover = async () => {
    setError('')
    try {
      await api.proposeHandover(id, successor)
      setHandover(false); setSuccessor('')
      await load()
    } catch (e) { setError(e.message) }
  }
  const cancelHandover = async () => {
    try { await api.cancelHandover(id); await load() } catch (e) { setError(e.message) }
  }
  const [rule, setRule] = useState(null)
  const [conflicts, setConflicts] = useState([])
  const [handover, setHandover] = useState(false)
  const [architects, setArchitects] = useState([])
  const [successor, setSuccessor] = useState('')
  const canHandOver = rule && (user.username === rule.requestor || hasRole(user, 'admin'))
  const [risk, setRisk] = useState(null)
  const [comment, setComment] = useState('')
  const [reviewComment, setReviewComment] = useState('')
  const [error, setError] = useState('')

  const load = useCallback(async () => {
    try {
      setRule(await api.rule(id))
      api.conflicts(id).then(setConflicts).catch(() => setConflicts([]))
      api.risk(id).then(setRisk).catch(() => setRisk(null))
    } catch (err) {
      setError(err.message)
    }
  }, [id])

  useEffect(() => { load() }, [load])

  if (error) return <div className="error">{error}</div>
  if (!rule) return <p className="muted">{t('Loading')}…</p>

  const isArchitect = hasRole(user, 'architect')
  const isOps = hasRole(user, 'operations')
  const isApprover = hasRole(user, 'change_approver')

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

  const confirmHandover = async () => {
    try { await api.confirmHandover(id); await load() } catch (e) { setError(e.message) }
  }

  return (
    <div className="rule-detail">
      <div className="page-head">
        <h1>{rule.rule_id} <span className="muted">{rule.name}</span></h1>
        <StatusBadge status={rule.status} />
      </div>

      {rule.pending_requestor === user.username && (
        <div className="infobox">
          <strong>{t('This rule has been handed over to you')}</strong>
          <p style={{ margin: '.3rem 0 .6rem' }}>
            {t('Proposed by')} {rule.handover_proposed_by}. {t('The requestor changes only once you confirm - you become accountable for whether this rule is still needed.')}
          </p>
          <button className="btn btn-approve" onClick={confirmHandover}>{t('Confirm takeover')}</button>{' '}
          <button className="btn btn-ghost" onClick={cancelHandover}>{t('Decline')}</button>
        </div>
      )}

      {handover && (
        <Modal title={t('Hand over the requestor')} onClose={() => setHandover(false)}>
          <p className="muted small">
            {t('Pick the architect who takes this rule over. They must confirm before the requestor changes.')}
          </p>
          <select value={successor} onChange={(e) => setSuccessor(e.target.value)}>
            <option value="">{t('– select –')}</option>
            {architects.filter((a) => a.username !== rule.requestor).map((a) => (
              <option key={a.username} value={a.username}>
                {a.full_name ? `${a.full_name} (${a.username})` : a.username}
              </option>
            ))}
          </select>
          <div className="actions" style={{ marginTop: '.8rem' }}>
            <button className="btn btn-primary" disabled={!successor} onClick={submitHandover}>
              {t('Propose handover')}
            </button>
            <button className="btn btn-ghost" onClick={() => setHandover(false)}>{t('Cancel')}</button>
          </div>
        </Modal>
      )}

      {rule.emergency_declared_at && (
        <div className={rule.emergency_approval_due ? 'error' : 'infobox'}>
          <strong>
            {rule.emergency_approval_due
              ? t('Emergency change – approval after the fact is outstanding')
              : t('Was declared as an emergency change')}
          </strong>
          <p style={{ margin: '.3rem 0 0' }}>{rule.emergency_reason}</p>
          <p className="small" style={{ margin: '.4rem 0 0' }}>
            {t('Declared by')} {rule.emergency_declared_by},{' '}
            {new Date(rule.emergency_declared_at).toLocaleString(dateLocale(lang))}
            {rule.emergency_approval_due && (
              <> – {t('without an approval it is deactivated on')}{' '}
                {new Date(rule.emergency_approval_due).toLocaleString(dateLocale(lang))}</>
            )}
          </p>
        </div>
      )}

      {/* Stated on the rule, not only in the risk panel: this is the one rule
          here whose source and destination say "any", and a reader who does not
          know why is looking at what would otherwise be the worst rule in the
          catalogue. */}
      {rule.ping_baseline && (
        <div className="infobox">
          <strong>{t('Ping baseline')}</strong>
          <p style={{ margin: '.3rem 0 0' }}>
            {t('Every address in {from} may ping every address in {to} – ICMP echo only.')
              .replace('{from}', rule.source_zone || '?')
              .replace('{to}', rule.destination_zone || '?')}{' '}
            <HelpLink topic="ping-baseline" label={t('When that is allowed')} />
          </p>
        </div>
      )}

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
          {/* Level and severity are stored in English; they are values shown to
              a person, so they go through the dictionary like any other text. */}
          <strong>⚠️ {t('Risk')}: {t(risk.level).toUpperCase()}</strong>
          {' '}({t('Target protection level')}: {t(risk.target_protection_level)})
          <ul>
            {risk.findings.map((f, i) => (
              <li key={i}><span className={`badge risk-${f.severity}`}>{t(f.severity)}</span> {f.detail}</li>
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
          ⚠️ {conflicts.length} {t('possible conflicts')}:
          <ul>
            {conflicts.slice(0, 6).map((c, i) => (
              <li key={i}>
                {c.kind.startsWith('zone') ? (
                  <><strong>{c.other_rule_id}</strong> – {c.detail} <Link to="/zones">({t('Zone matrix')})</Link></>
                ) : (
                  <><Link to={`/rules/${c.other_rule_id}`}>{c.other_rule_id}</Link> – {c.detail} ({c.kind})</>
                )}
              </li>
            ))}
            {conflicts.length > 6 && <li>… {t('and {n} more').replace('{n}', conflicts.length - 6)}</li>}
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
            <dt>{t('Logging')}</dt>
            <dd><code>{rule.log_level || 'detailed'}</code></dd>
          </dl>
        </section>

        <section className="card">
          <h2>{t('Metadata')}</h2>
          <dl>
            <dt>Application</dt><dd>{rule.application || '–'}</dd>
            <dt>APP-ID</dt><dd>{rule.app_id || '–'}</dd>
            <dt>{t('Reason')}</dt><dd>{rule.justification || '–'}</dd>
            <dt>{t('Description')}</dt><dd>{rule.description || '–'}</dd>
            <dt>Requestor</dt>
            <dd>{rule.requestor || '–'}
              <span className="muted small"> ({t('created the rule')})</span>
              {canHandOver && !rule.pending_requestor && (
                <> · <button className="linklike" onClick={() => { openHandover(); setHandover(true) }}>{t('Hand over')}</button></>
              )}
              {rule.pending_requestor && (
                <div className="muted small">
                  {t('Handover to')} <strong>{rule.pending_requestor}</strong> {t('awaiting confirmation')}
                  {(user.username === rule.handover_proposed_by || hasRole(user, 'admin')) && (
                    <> · <button className="linklike" onClick={cancelHandover}>{t('Withdraw')}</button></>
                  )}
                </div>
              )}
            </dd>
            <dt>{t('Handler')}</dt>
            <dd>{rule.owner
              ? <>{rule.owner} <span className="muted small">({t('last maintained the rollout')})</span></>
              : <span className="muted">{t('not worked on the components yet')}</span>}</dd>
            <dt>{t('Change ID')}</dt><dd>{rule.change_id || '–'}</dd>
            <dt>{t('Business context')}</dt><dd>{rule.business_context || '–'}</dd>
            <dt>{t('Validity')}</dt>
            <dd>{rule.valid_from || '…'} – {rule.valid_until || t('unlimited')}</dd>
            <dt>Info</dt><dd>{rule.info || '–'}</dd>
            <dt>Version</dt><dd>v{rule.version} · {t('created by')} {rule.created_by}</dd>
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
            {isArchitect && !['draft', 'rejected', 'deleted'].includes(rule.status) && (
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
            {IN_FORCE.includes(rule.status) && (isOps || isArchitect) && (
              <button className="btn btn-ghost" onClick={act(() => api.deactivate(id, reviewComment))}>{t('Deactivate rule')}</button>
            )}
            {IN_FORCE.includes(rule.status) && (
              <Link className="btn" to={`/export?ids=${rule.rule_id}`}>{t('Export configuration →')}</Link>
            )}
            {rule.status === 'deleted' && (
              <p className="muted small">
                {t('This rule is deleted. It is kept as documentation and no longer takes effect – it is not exported, not analysed and not recertified.')}
              </p>
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
                <span className="muted small"> · {new Date(c.created_at).toLocaleString(dateLocale(lang))}</span>
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
                    <td>{new Date(v.changed_at).toLocaleString(dateLocale(lang))}</td>
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
