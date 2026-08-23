import { useCallback, useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { api, getUser } from '../api'
import { ComponentBadges, ServiceList } from '../components/shared'
import { useLang } from '../i18n'

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

export default function Recertification() {
  const { t } = useLang()
  const user = getUser()
  const canAct = ['architect', 'operations', 'admin'].includes(user.role)
  const [days, setDays] = useState(30)
  const [data, setData] = useState(null)
  const [error, setError] = useState('')
  const [notice, setNotice] = useState('')

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
