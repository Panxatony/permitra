import { useCallback, useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { api, getToken, getUser } from '../api'
import { ComponentBadges, HelpLink, ServiceList } from '../components/shared'
import { useLang } from '../i18n'

function plusMonths(n) {
  const d = new Date()
  d.setMonth(d.getMonth() + n)
  return d.toISOString().slice(0, 10)
}

function plusOneYear() {
  const d = new Date()
  d.setFullYear(d.getFullYear() + 1)
  return d.toISOString().slice(0, 10)
}

function RuleRows({ rules, onExtend, onDeactivate, canAct }) {
  const { t } = useLang()
  const [dates, setDates] = useState({})
  if (!rules.length) return <p className="muted">{t('No rules.')}</p>
  return (
    <div className="table-wrap">
      <table>
        <thead>
          <tr>
            <th>{t('Rule ID')}</th><th>{t('Justification')}</th><th>{t('Components')}</th><th>{t('Services')}</th>
            <th>{t('Valid until')}</th><th>{t('Owner')}</th><th>{t('Action')}</th>
          </tr>
        </thead>
        <tbody>
          {rules.map((r) => (
            <tr key={r.rule_id}>
              <td><Link to={`/rules/${r.rule_id}`} className="rule-link">{r.rule_id}</Link></td>
              <td className="justif">{r.justification || r.name}</td>
              <td><ComponentBadges components={r.components} /></td>
              <td><ServiceList services={r.services} /></td>
              <td><code>{r.valid_until}</code></td>
              <td>{r.owner || r.requestor}</td>
              <td className="row-actions">
                {canAct && (
                  <>
                    <input type="date" value={dates[r.rule_id] || plusOneYear()}
                      onChange={(e) => setDates({ ...dates, [r.rule_id]: e.target.value })} />
                    <button className="btn btn-approve"
                      onClick={() => onExtend(r.rule_id, dates[r.rule_id] || plusOneYear())}>
                      {t('Extend')}
                    </button>
                    <button className="btn btn-ghost" onClick={() => onDeactivate(r.rule_id)}>
                      {t('Deactivate')}
                    </button>
                  </>
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

/* One campaign: progress, the per-requestor worklist, and the three decisions.

   The decision buttons are deliberately three, not two. "Still needed but
   wrong" sends the rule back into review - without that path a reviewer facing
   an almost-right rule can only wave it through or kill it, and both produce
   the ruleset the review was supposed to prevent. */
function Campaign({ c, onChanged, canDecide, canManage, me }) {
  const { t } = useLang()
  const [detail, setDetail] = useState(null)
  const [open, setOpen] = useState(false)
  const [comments, setComments] = useState({})
  const [error, setError] = useState('')
  const [mineOnly, setMineOnly] = useState(false)

  const load = () => api.recertCampaign(c.id).then(setDetail).catch((e) => setError(e.message))

  const toggle = () => {
    if (!open && !detail) load()
    setOpen(!open)
  }

  const decide = async (item, decision) => {
    setError('')
    try {
      await api.recertDecide(c.id, item.item_id, decision,
        { comment: comments[item.item_id] || '' })
      load()
      onChanged()
    } catch (err) {
      setError(err.message)
    }
  }

  const downloadReport = () => {
    fetch(`/api/recertification/campaigns/${c.id}/report?format=csv`,
      { headers: { Authorization: `Bearer ${getToken()}` } })
      .then((res) => { if (!res.ok) throw new Error(res.statusText); return res.blob() })
      .then((blob) => {
        const a = document.createElement('a')
        a.href = URL.createObjectURL(blob)
        a.download = `recertification-${c.id}.csv`
        a.click()
        URL.revokeObjectURL(a.href)
      })
      .catch((err) => setError(err.message))
  }

  const closeCampaign = async () => {
    if (!window.confirm(t('Close the campaign? Open items stay open, on the record.'))) return
    try {
      await api.closeRecertCampaign(c.id)
      load()
      onChanged()
    } catch (err) {
      setError(err.message)
    }
  }

  const done = c.total - c.open
  const items = (detail?.items || []).filter((i) =>
    !mineOnly || (i.requestor || '').toLowerCase() === me.toLowerCase())

  return (
    <div className={`card recert-campaign ${c.overdue ? 'recert-overdue' : ''}`}>
      <div className="recert-head" onClick={toggle} role="button" tabIndex={0}
        onKeyDown={(e) => e.key === 'Enter' && toggle()}>
        <div>
          <strong>{c.name}</strong>{' '}
          <span className="muted small">
            {c.scope} · {t('due')} {c.due_date}
            {c.closed_at && <> · {t('closed by')} {c.closed_by}</>}
            {c.overdue && <span className="emergency-overdue"> · {t('overdue')}</span>}
          </span>
        </div>
        <div className="recert-progress" title={`${done}/${c.total}`}>
          <span className="barrow-track"><span className="barrow-fill fill-approved"
            style={{ width: `${c.total ? (done / c.total) * 100 : 0}%` }} /></span>
          <span className="small">{done}/{c.total}</span>
        </div>
      </div>

      {c.requestors_unknown.length > 0 && (
        <p className="coverage-gap">
          <strong>{t('Requestor matches no active user')}:</strong>{' '}
          {c.requestors_unknown.join(', ')} — {t('their open rules cannot be recertified by anybody')}
        </p>
      )}

      {open && (
        <>
          {error && <div className="error">{error}</div>}
          <div className="filterbar">
            <label className="inline">
              <input type="checkbox" checked={mineOnly}
                onChange={(e) => setMineOnly(e.target.checked)} />{' '}
              {t('Only my rules')}
            </label>
            <button className="btn btn-ghost" onClick={downloadReport}>
              {t('Report (CSV)')}
            </button>
            {canManage && !c.closed_at && (
              <button className="btn btn-ghost" onClick={closeCampaign}>{t('Close campaign')}</button>
            )}
          </div>
          {detail && (
            <div className="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>{t('Rule')}</th><th>{t('Requestor')}</th><th>{t('Valid until')}</th>
                    <th>{t('Decision')}</th><th>{t('Comment')}</th>
                  </tr>
                </thead>
                <tbody>
                  {items.map((i) => (
                    <tr key={i.item_id}>
                      <td><Link to={`/rules/${i.rule_id}`} className="rule-link">{i.rule_id}</Link>
                        <span className="muted small"> {i.name}</span></td>
                      <td>{i.requestor}{i.requestor_unknown &&
                        <span className="emergency-overdue" title={t('Requestor matches no active user')}> ⚠</span>}</td>
                      <td><code>{i.valid_until || '–'}</code></td>
                      <td>
                        {i.decision
                          ? <span>{t(i.decision)} <span className="muted small">
                              ({i.decided_by}, {new Date(i.decided_at).toLocaleDateString()})</span></span>
                          : canDecide && !c.closed_at && (
                            <span className="row-actions">
                              <button className="btn btn-approve small"
                                onClick={() => decide(i, 'confirm')}>{t('Still required')}</button>
                              <button className="btn btn-ghost small"
                                onClick={() => decide(i, 'rework')}>{t('Needed, but wrong')}</button>
                              <button className="btn btn-ghost small"
                                onClick={() => decide(i, 'retire')}>{t('No longer needed')}</button>
                            </span>
                          )}
                      </td>
                      <td>
                        {i.decision ? <span className="small">{i.comment}</span> : canDecide && !c.closed_at && (
                          <input value={comments[i.item_id] || ''} placeholder={t('Reason')}
                            onChange={(e) => setComments({ ...comments, [i.item_id]: e.target.value })} />
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </>
      )}
    </div>
  )
}

export default function Recertification() {
  const { t } = useLang()
  const user = getUser()
  const canAct = ['architect', 'operations', 'admin'].includes(user.role)
  const [days, setDays] = useState(30)
  const [data, setData] = useState(null)
  const [error, setError] = useState('')
  const [notice, setNotice] = useState('')
  const [campaigns, setCampaigns] = useState([])
  const [newCampaign, setNewCampaign] = useState({ name: '', due_date: plusMonths(3), scope: 'all' })
  const canManage = ['admin', 'change_approver'].includes(user.role)

  const loadCampaigns = useCallback(() => {
    api.recertCampaigns().then(setCampaigns).catch(() => {})
  }, [])
  useEffect(() => { loadCampaigns() }, [loadCampaigns])

  const createCampaign = async (e) => {
    e.preventDefault()
    setError('')
    try {
      await api.createRecertCampaign(newCampaign)
      setNewCampaign({ name: '', due_date: plusMonths(3), scope: 'all' })
      loadCampaigns()
    } catch (err) {
      setError(err.message)
    }
  }

  const load = useCallback((d = days) => {
    api.expiring(d).then(setData).catch((e) => setError(e.message))
  }, [days])

  useEffect(() => { load() }, [load])

  const extend = async (ruleId, validUntil) => {
    setError('')
    setNotice('')
    try {
      await api.extendRule(ruleId, validUntil)
      setNotice(t('{rule} recertified until {date}.')
        .replace('{rule}', ruleId).replace('{date}', validUntil))
      load()
    } catch (err) {
      setError(err.message)
    }
  }

  const deactivate = async (ruleId) => {
    if (!window.confirm(t('Deactivate rule {rule}?').replace('{rule}', ruleId))) return
    setError('')
    try {
      await api.deactivate(ruleId, t('Deactivated as part of the recertification'))
      setNotice(t('{rule} deactivated.').replace('{rule}', ruleId))
      load()
    } catch (err) {
      setError(err.message)
    }
  }

  return (
    <div>
      <div className="page-head">
        <h1>{t('Recertification')}</h1>
        <span className="muted">
          {t('Expired rules are deactivated automatically by the system every day – extend them here beforehand, or deactivate them deliberately')}
        </span>
      </div>

      <form className="filterbar" onSubmit={(e) => { e.preventDefault(); load() }}>
        <label className="inline">{t('Lead time')}:
          <select value={days} onChange={(e) => { setDays(Number(e.target.value)) }}>
            <option value={14}>14 {t('days')}</option>
            <option value={30}>30 {t('days')}</option>
            <option value={90}>90 {t('days')}</option>
            <option value={365}>1 {t('year')}</option>
          </select>
        </label>
        <button className="btn btn-primary" type="submit">{t('Refresh')}</button>
      </form>

      {error && <div className="error">{error}</div>}
      {notice && <div className="okbox">{notice}</div>}

      <section>
        <h2>{t('Campaigns')} <HelpLink topic="recert" label={t('How campaigns work')} /></h2>
        <p className="muted small">
          {t('Extending a date is a decision about a calendar. A campaign asks the actual question, rule by rule: still needed, still correct, still owned – and its report shows who answered and what is outstanding.')}
        </p>
        {canManage && (
          <form className="filterbar" onSubmit={createCampaign}>
            <input value={newCampaign.name} required minLength={3}
              placeholder={t('Name, e.g. "Annual review 2026"')}
              onChange={(e) => setNewCampaign({ ...newCampaign, name: e.target.value })} />
            <input value={newCampaign.scope}
              title={t("'all', 'zone:<name>' or 'component:<id>'")}
              onChange={(e) => setNewCampaign({ ...newCampaign, scope: e.target.value })} />
            <input type="date" value={newCampaign.due_date} required
              onChange={(e) => setNewCampaign({ ...newCampaign, due_date: e.target.value })} />
            <button className="btn btn-primary" type="submit">{t('Start campaign')}</button>
          </form>
        )}
        {campaigns.map((c) => (
          <Campaign key={c.id} c={c} me={user.username}
            canDecide={canAct || user.role === 'change_approver'} canManage={canManage}
            onChanged={loadCampaigns} />
        ))}
        {!campaigns.length && <p className="muted">{t('No campaigns yet.')}</p>}
      </section>

      {data && (
        <div className="search-results">
          <section>
            <h2>{t('⚠ Expired')} ({data.expired.length})</h2>
            <RuleRows rules={data.expired} onExtend={extend} onDeactivate={deactivate} canAct={canAct} />
          </section>
          <section>
            <h2>{t('Expiring within')} {data.days} {t('days')} ({data.expiring.length})</h2>
            <RuleRows rules={data.expiring} onExtend={extend} onDeactivate={deactivate} canAct={canAct} />
          </section>
          {data.invalid?.length > 0 && (
            <section>
              <h2>{t('⚠ Unreadable expiry date')} ({data.invalid.length})</h2>
              <p className="muted small">
                {t('These rules are skipped by the expiry check and therefore never expire automatically. Please correct the valid-until date.')}
              </p>
              <RuleRows rules={data.invalid} onExtend={extend} onDeactivate={deactivate} canAct={canAct} />
            </section>
          )}
        </div>
      )}
    </div>
  )
}
