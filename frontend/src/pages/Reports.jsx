import { useEffect, useState } from 'react'
import { api } from '../api'
import DriftPanel from '../components/DriftPanel'
import { useLang } from '../i18n'

/* Reports: the questions someone asks across the whole ruleset, as opposed to
   the pages where the ruleset is worked on. The drift comparison moved here
   from the components page for that reason - whoever runs it is assessing,
   not maintaining infrastructure. */

function RequestorTable() {
  const { t } = useLang()
  const [data, setData] = useState(null)
  const [error, setError] = useState('')

  useEffect(() => {
    api.requestorReport().then(setData).catch((e) => setError(e.message))
  }, [])

  if (error) return <div className="error">{error}</div>
  if (!data) return <p className="muted">{t('Loading…')}</p>

  const named = data.requestors.filter((r) => r.requestor)
  return (
    <section className="card wide">
      <h2>{t('Rules per requestor')}</h2>
      <p className="muted small">
        {t('Who asked for what is on the firewalls – and whether that person still exists. A requestor matching no active user cannot be asked whether their rules are still needed.')}
      </p>
      <div className="table-wrap">
        <table>
          <thead>
            <tr>
              <th>{t('Requestor')}</th>
              <th>{t('Rules')}</th>
              <th>{t('In force')}</th>
            </tr>
          </thead>
          <tbody>
            {named.map((r) => (
              <tr key={r.requestor}>
                <td>
                  {r.requestor}
                  {r.unknown && (
                    <span className="emergency-overdue"
                      title={t('Matches no active user')}> ⚠ {t('no active user')}</span>
                  )}
                </td>
                <td>{r.total}</td>
                <td>{r.in_force}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {data.without_requestor > 0 && (
        <p className="coverage-gap">
          <strong>{data.without_requestor}</strong>{' '}
          {t('rule(s) carry no requestor at all – nobody can be asked about them.')}
        </p>
      )}
    </section>
  )
}

export default function Reports() {
  const { t } = useLang()
  const [components, setComponents] = useState([])

  useEffect(() => {
    api.components().then(setComponents).catch(() => setComponents([]))
  }, [])

  return (
    <div>
      <div className="page-head">
        <h1>{t('Reports')}</h1>
        <span className="muted">
          {t('Assessments across the whole ruleset – nothing here changes a rule')}
        </span>
      </div>
      <div className="search-results">
        <DriftPanel components={components} />
        <RequestorTable />
      </div>
    </div>
  )
}
