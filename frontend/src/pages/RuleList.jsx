import { useEffect, useState } from 'react'
import { Link, useSearchParams } from 'react-router-dom'
import { api, getToken } from '../api'
import { AddressList, ComponentBadges, ServiceList, STATUS_LABELS, StatusBadge, useZoneLabels } from '../components/shared'
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

  // Filter folgt der URL: Navigation auf /rules (ohne Parameter) setzt den
  // Status-Filter zurück, /rules?status=… (z.B. vom Dashboard) setzt ihn.
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
        <h1>{t('Sicherheitsregeln')}</h1>
        <span className="muted">{total} {t('Regeln')}</span>
      </div>

      <form className="filterbar" onSubmit={submit}>
        <input placeholder={t('Suche (ID, Name, Anlass, Change…)')} value={filters.q} onChange={set('q')} />
        <input placeholder={t('Quelle / Quell-Zone')} value={filters.source} onChange={set('source')} />
        <input placeholder={t('Ziel / Ziel-Zone')} value={filters.destination} onChange={set('destination')} />
        <input placeholder={t('Port')} value={filters.port} onChange={set('port')} className="narrow" />
        <select value={filters.protocol} onChange={set('protocol')} className="narrow">
          <option value="">{t('Protokoll')}</option>
          <option>TCP</option>
          <option>UDP</option>
          <option>ICMP</option>
        </select>
        <select value={filters.status} onChange={set('status')}>
          <option value="">{t('Status')}</option>
          {Object.entries(STATUS_LABELS).map(([k, v]) => <option key={k} value={k}>{t(v)}</option>)}
        </select>
        <select value={filters.impl} onChange={set('impl')}>
          <option value="">{t('Umsetzung')}</option>
          <option value="pending">{t('Umzusetzen (offen / zu ändern)')}</option>
        </select>
        <select value={filters.risk} onChange={set('risk')}>
          <option value="">{t('Risiko')}</option>
          <option value="flagged">{t('Mit Risiko-Hinweis')}</option>
        </select>
        <select value={filters.component} onChange={set('component')}>
          <option value="">{t('Komponente')}</option>
          {components.map((c) => <option key={c.id} value={c.name}>{c.name}</option>)}
        </select>
        <input className="narrow" value={filters.app_id} onChange={set('app_id')} placeholder="APP-ID" />
        <button className="btn btn-primary" type="submit">{t('Filtern')}</button>
        <button className="btn btn-ghost" type="button" onClick={reset}>{t('Zurücksetzen')}</button>
        {filters.app_id.trim() && (
          <a className="btn btn-ghost"
            href={`/api/export/csv?app_id=${encodeURIComponent(filters.app_id.trim())}&only_approved=false&download=true`}
            title={t('CSV-Report aller Regeln dieser APP-ID')}
            onClick={(e) => { e.preventDefault(); downloadReport(filters.app_id.trim()) }}>
            ⬇ {t('APP-ID-Report (CSV)')}
          </a>
        )}
      </form>

      {error && <div className="error">{error}</div>}
      {loading ? (
        <p className="muted">{t('Lade…')}</p>
      ) : (
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>{t('Rule-ID')}</th>
                <th>{t('Komponenten')}</th>
                <th>{t('Quell-Zone')}</th>
                <th>{t('Quelle')}</th>
                <th>{t('Ziel-Zone')}</th>
                <th>{t('Ziel')}</th>
                <th>{t('Dienste')}</th>
                <th>{t('Anlass')}</th>
                <th>{t('Status')}</th>
              </tr>
            </thead>
            <tbody>
              {rules.map((r) => (
                <tr key={r.rule_id}>
                  <td><Link to={`/rules/${r.rule_id}`} className="rule-link">{r.rule_id}</Link></td>
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
          <button className="btn btn-ghost" disabled={page === 0} onClick={() => goto(page - 1)}>{t('← Zurück')}</button>
          <span className="muted">{t('Seite')} {page + 1} {t('von')} {Math.ceil(total / PAGE_SIZE)}</span>
          <button className="btn btn-ghost" disabled={(page + 1) * PAGE_SIZE >= total}
            onClick={() => goto(page + 1)}>{t('Weiter →')}</button>
        </div>
      )}
    </div>
  )
}
