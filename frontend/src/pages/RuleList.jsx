import { useEffect, useState } from 'react'
import { Link, useSearchParams } from 'react-router-dom'
import { api, getToken, getUser, hasRole } from '../api'
import { AddressList, ComponentBadges, ServiceList, STATUS_LABELS, StatusBadge, useZoneLabels } from '../components/shared'
import NewRuleButton from '../components/NewRuleButton'
import RetireApplication from '../components/RetireApplication'
import { useLang } from '../i18n'

const EMPTY_FILTERS = { q: '', source: '', destination: '', port: '', protocol: '', status: '', component: '', impl: '', risk: '', app_id: '' }

export default function RuleList() {
  const PAGE_SIZE = 50
  const { t } = useLang()
  const zoneLabel = useZoneLabels()
  const [searchParams] = useSearchParams()
  const [rules, setRules] = useState([])
  const [total, setTotal] = useState(0)
  const [page, setPage] = useState(0)
  const [components, setComponents] = useState([])
  const [filters, setFilters] = useState({
    ...EMPTY_FILTERS,
    status: searchParams.get('status') || '',
    impl: searchParams.get('impl') || '',
    risk: searchParams.get('risk') || '',
  })
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')

  const load = async (f = filters, p = page) => {
    setLoading(true)
    setError('')
    try {
      const data = await api.rules({ ...f, limit: PAGE_SIZE, offset: p * PAGE_SIZE })
      setRules(data.items)
      setTotal(data.total)
    } catch (err) {
      setError(err.message)
    } finally {
      setLoading(false)
    }
  }

  const goto = (p) => {
    setPage(p)
    load(filters, p)
  }

  // The filter follows the URL: navigating to /rules (without parameters)
  // resets the status filter, /rules?status=… (e.g. from the dashboard) sets it.
  useEffect(() => {
    const next = {
      ...EMPTY_FILTERS,
      status: searchParams.get('status') || '',
      impl: searchParams.get('impl') || '',
      risk: searchParams.get('risk') || '',
    }
    setFilters(next)
    setPage(0)
    load(next, 0)
    api.components().then(setComponents).catch(() => setComponents([]))
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [searchParams])

  const downloadReport = (appId) => {
    fetch(`/api/export/csv?app_id=${encodeURIComponent(appId)}&only_approved=false&download=true`,
      { headers: { Authorization: `Bearer ${getToken()}` } })
      .then((res) => res.blob())
      .then((blob) => {
        const a = document.createElement('a')
        a.href = URL.createObjectURL(blob)
        a.download = `permitra-report-${appId}.csv`
        a.click()
      })
  }

  const set = (key) => (e) => setFilters({ ...filters, [key]: e.target.value })
  const submit = (e) => {
    e.preventDefault()
    setPage(0)
    load(filters, 0)
  }
  const reset = () => {
    setFilters(EMPTY_FILTERS)
    setPage(0)
    load(EMPTY_FILTERS, 0)
  }

  return (
    <div>
      <div className="page-head">
        <h1>{t('Security rules')}</h1>
        <span className="muted">{total} {t('Rules')}</span>
        {/* Retiring an application is a decision about the application, so it
            sits with the architect - the per-rule approval downstream is what
            keeps it from being a mass deactivation. */}
        <NewRuleButton />
        {hasRole(getUser(), 'architect') && <RetireApplication onDone={() => load()} />}
      </div>

      <form className="filterbar" onSubmit={submit}>
        <input placeholder={t('Search (ID, name, reason, change…)')} value={filters.q} onChange={set('q')} />
        <input placeholder={t('Source / source zone')} value={filters.source} onChange={set('source')} />
        <input placeholder={t('Destination / destination zone')} value={filters.destination} onChange={set('destination')} />
        <input placeholder={t('Port')} value={filters.port} onChange={set('port')} className="narrow" />
        <select value={filters.protocol} onChange={set('protocol')} className="narrow">
          <option value="">{t('Protocol')}</option>
          <option>TCP</option>
          <option>UDP</option>
          <option>ICMP</option>
        </select>
        <select value={filters.status} onChange={set('status')}>
          <option value="">{t('Status')}</option>
          {Object.entries(STATUS_LABELS).map(([k, v]) => <option key={k} value={k}>{t(v)}</option>)}
        </select>
        <select value={filters.impl} onChange={set('impl')}>
          <option value="">{t('Implementation')}</option>
          <option value="pending">{t('To implement (open / to change)')}</option>
        </select>
        <select value={filters.risk} onChange={set('risk')}>
          <option value="">{t('Risk')}</option>
          <option value="flagged">{t('With risk warning')}</option>
        </select>
        <select value={filters.component} onChange={set('component')}>
          <option value="">{t('Component')}</option>
          {components.map((c) => <option key={c.id} value={c.name}>{c.name}</option>)}
        </select>
        <input className="narrow" value={filters.app_id} onChange={set('app_id')} placeholder="APP-ID" />
        <button className="btn btn-primary" type="submit">{t('Filter')}</button>
        <button className="btn btn-ghost" type="button" onClick={reset}>{t('Reset')}</button>
        {filters.app_id.trim() && (
          <a className="btn btn-ghost"
            href={`/api/export/csv?app_id=${encodeURIComponent(filters.app_id.trim())}&only_approved=false&download=true`}
            title={t('CSV report of all rules for this APP-ID')}
            onClick={(e) => { e.preventDefault(); downloadReport(filters.app_id.trim()) }}>
            ⬇ {t('APP-ID report (CSV)')}
          </a>
        )}
      </form>

      {error && <div className="error">{error}</div>}
      {loading ? (
        <p className="muted">{t('Loading…')}</p>
      ) : (
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>{t('Rule ID')}</th>
                <th>{t('Components')}</th>
                <th>{t('Source zone')}</th>
                <th>{t('Source')}</th>
                <th>{t('Destination zone')}</th>
                <th>{t('Destination')}</th>
                <th>{t('Services')}</th>
                <th>{t('Reason')}</th>
                <th>{t('Status')}</th>
              </tr>
            </thead>
            <tbody>
              {rules.map((r) => (
                <tr key={r.rule_id} className={r.status === 'deleted' ? 'row-deleted' : ''}>
                  <td>
                    <Link to={`/rules/${r.rule_id}`} className="rule-link">{r.rule_id}</Link>
                    {r.removal_reason && (
                      <span className="badge risk-high" style={{ marginLeft: '.35rem' }}
                        title={r.removal_reason}>🗑️ {t('to be removed')}</span>
                    )}
                  </td>
                  <td><ComponentBadges components={r.components} /></td>
                  <td>{zoneLabel(r.source_zone)}</td>
                  <td className="addr"><AddressList entries={r.source} max={2} /></td>
                  <td>{zoneLabel(r.destination_zone)}</td>
                  <td className="addr"><AddressList entries={r.destination} max={2} /></td>
                  <td><ServiceList services={r.services} /></td>
                  <td className="justif">{r.justification}</td>
                  <td><StatusBadge status={r.status} /></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {total > PAGE_SIZE && (
        <div className="pager">
          <button className="btn btn-ghost" disabled={page === 0} onClick={() => goto(page - 1)}>{t('← Previous')}</button>
          <span className="muted">{t('Page')} {page + 1} {t('of')} {Math.ceil(total / PAGE_SIZE)}</span>
          <button className="btn btn-ghost" disabled={(page + 1) * PAGE_SIZE >= total}
            onClick={() => goto(page + 1)}>{t('Next →')}</button>
        </div>
      )}
    </div>
  )
}
