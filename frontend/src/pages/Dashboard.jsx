import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { api } from '../api'
import { STATUS_LABELS } from '../components/shared'
import { dateLocale, useLang } from '../i18n'

/* Workflow order, with `active` ahead of `approved`: the interesting number is
   how many rules are approved but not yet on the devices, and that only reads
   as a gap when the two sit next to each other. */
const STATUS_ORDER = ['active', 'approved', 'in_review', 'draft', 'rejected', 'deactivated', 'deleted']

function Tile({ value, label, to, tone }) {
  const inner = (
    <div className={`tile ${tone || ''}`}>
      <div className="tile-value">{value}</div>
      <div className="tile-label">{label}</div>
    </div>
  )
  return to ? <Link to={to} className="tile-link">{inner}</Link> : inner
}

function BarList({ rows, max }) {
  return (
    <div className="barlist">
      {rows.map((r) => (
        <div key={r.key} className="barrow" title={`${r.label}: ${r.value}`}>
          <span className="barrow-label">{r.link ? <Link to={r.link}>{r.label}</Link> : r.label}</span>
          <span className="barrow-track">
            <span className={`barrow-fill ${r.cls || ''}`}
              style={{ width: max ? `${Math.max(2, (r.value / max) * 100)}%` : '2%' }} />
          </span>
          <span className="barrow-value">{r.value}</span>
        </div>
      ))}
    </div>
  )
}

/* The coverage figure, with what it does not cover.

   The percentage is never rendered on its own: an aggregate improves by looking
   away, so how much of the estate it actually measured sits directly under it,
   and the components it could not measure are listed rather than dropped. A
   figure computed from a configuration nobody has re-uploaded in months says so
   too. */
function Coverage({ c, t, lang }) {
  const nothing = c.measured === 0
  const trend = c.unjustified_change

  return (
    <section className="card wide coverage-card">
      <h2>{t('Backed by an approved rule')}</h2>
      <div className="coverage-head">
        <div className="coverage-figure">
          <div className={`coverage-percent ${nothing ? 'muted' : ''}`}>
            {nothing ? '–' : `${c.percent} %`}
          </div>
          <div className="coverage-scope">
            {nothing
              ? t('No device configuration has been uploaded yet')
              : `${t('measured on')} ${c.measured}/${c.components_total} ${t('components')}`}
          </div>
        </div>

        {!nothing && (
          <div className="coverage-facts">
            <p>
              <strong>{c.unjustified}</strong>{' '}
              {c.unjustified === 1
                ? t('rule on the devices is backed by no approved security rule')
                : t('rules on the devices are backed by no approved security rule')}
              {' '}({c.justified}/{c.total} {t('backed')}).
            </p>
            {trend !== null && trend !== 0 && (
              <p className={trend > 0 ? 'coverage-worse' : 'coverage-better'}>
                {trend > 0 ? `+${trend}` : trend}{' '}
                {t('since the previous measurement')}
                <span className="muted small"> ({c.compared}/{c.measured} {t('comparable')})</span>
              </p>
            )}
            {trend === null && (
              <p className="muted small">
                {t('Measured once so far – a trend needs a second upload')}
              </p>
            )}
            {c.stale && (
              <p className="coverage-worse">
                {t('Oldest configuration is')} {c.oldest_measurement_age_days} {t('days old')}
              </p>
            )}
          </div>
        )}
      </div>

      {c.not_measured.length > 0 && (
        <p className="coverage-gap">
          <strong>{t('Not measured')}:</strong>{' '}
          {c.not_measured.map((n) => `${n.component} (${t(n.reason)})`).join(', ')} –{' '}
          <Link to="/components">{t('upload a configuration')}</Link>
        </p>
      )}

      {c.per_component.length > 0 && (
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>{t('Component')}</th><th>{t('Backed')}</th><th>{t('Unbacked')}</th>
                <th>{t('Share')}</th><th>{t('Change')}</th><th>{t('Measured')}</th>
              </tr>
            </thead>
            <tbody>
              {c.per_component.map((p) => (
                <tr key={p.component_id}>
                  <td><Link to="/components">{p.component}</Link></td>
                  <td>{p.justified}/{p.total}</td>
                  <td className={p.unjustified ? 'coverage-worse' : ''}>{p.unjustified}</td>
                  <td>{p.percent} %</td>
                  <td className={p.change > 0 ? 'coverage-worse' : p.change < 0 ? 'coverage-better' : ''}>
                    {p.change === null ? '–' : p.change > 0 ? `+${p.change}` : p.change}
                  </td>
                  <td className="small">
                    {p.fetched_at ? new Date(p.fetched_at).toLocaleDateString(dateLocale(lang)) : '–'}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  )
}

export default function Dashboard() {
  const { lang, t } = useLang()
  const [data, setData] = useState(null)
  const [error, setError] = useState('')

  useEffect(() => {
    api.dashboard().then(setData).catch((e) => setError(e.message))
  }, [])

  if (error) return <div className="error">{error}</div>
  if (!data) return <p className="muted">{t('Loading…')}</p>

  const statusMax = Math.max(...STATUS_ORDER.map((s) => data.by_status[s] || 0), 1)
  const compMax = Math.max(...data.components.map((c) => c.rules), 1)

  return (
    <div>
      <div className="page-head"><h1>Dashboard</h1></div>

      <div className="infobox">
        {lang === 'de' ? (
          <span>
            <strong>ℹ️ Was Permitra ist:</strong> Permitra ist ein <strong>Planungs- und
            Dokumentationstool</strong> für Sicherheitsregeln — hier werden Freigaben beantragt,
            geprüft, genehmigt und nachvollziehbar dokumentiert (Quelle der Wahrheit für das
            „Soll"). Die <strong>Umsetzung</strong> erfolgt weiterhin in den Management-Tools der
            Hersteller (Check Point SmartConsole, Juniper CLI/Security Director, Cisco APIC):
            Permitra erzeugt dafür die passenden Konfigurationen zum Übernehmen, schreibt aber
            <strong> nicht selbst auf die Geräte</strong>.
          </span>
        ) : (
          <span>
            <strong>ℹ️ What Permitra is:</strong> Permitra is a <strong>planning and
            documentation tool</strong> for security rules — requests are raised, reviewed,
            approved and documented traceably here (the source of truth for the intended
            state). <strong>Implementation</strong> still happens in the vendors' management
            tools (Check Point SmartConsole, Juniper CLI/Security Director, Cisco APIC):
            Permitra generates the matching configurations to apply, but
            <strong> never writes to the devices itself</strong>.
          </span>
        )}
      </div>

      {data.emergency && data.emergency.pending > 0 && (
        <section className={`emergency-banner ${data.emergency.overdue ? 'overdue' : ''}`}>
          <h2>
            {data.emergency.pending}{' '}
            {data.emergency.pending === 1
              ? t('emergency change is waiting for approval after the fact')
              : t('emergency changes are waiting for approval after the fact')}
            {data.emergency.overdue > 0 && (
              <span className="emergency-overdue"> – {data.emergency.overdue} {t('overdue')}</span>
            )}
          </h2>
          <ul>
            {data.emergency.items.map((e) => (
              <li key={e.rule_id} className={e.overdue ? 'emergency-overdue' : ''}>
                <Link to={`/rules/${e.rule_id}`} className="rule-link">{e.rule_id}</Link>{' '}
                {e.name} – <em>{e.reason}</em>{' '}
                <span className="muted small">
                  ({t('declared by')} {e.declared_by}, {t('due')}{' '}
                  {new Date(e.due).toLocaleString(dateLocale(lang))})
                </span>
              </li>
            ))}
          </ul>
        </section>
      )}

      <div className="tiles">
        <Tile value={data.rules_total} label={t('Total rules')} to="/rules" />
        <Tile value={data.open_reviews} label={t('Open reviews')} to="/rules?status=in_review"
          tone={data.open_reviews ? 'tone-warn' : ''} />
        <Tile value={data.to_implement} label={t('To implement')} to="/rules?impl=pending"
          tone={data.to_implement ? 'tone-warn' : 'tone-good'} />
        <Tile value={data.expired} label={t('Expired')} to="/recertification"
          tone={data.expired ? 'tone-bad' : 'tone-good'} />
        <Tile value={data.expiring_30d} label={t('Expiring within 30 days')} to="/recertification"
          tone={data.expiring_30d ? 'tone-warn' : ''} />
        <Tile value={data.zones} label={t('Zones')} to="/zones" />
        <Tile value={data.aci_gateways} label={t('ACI gateways')} to="/components" />
      </div>

      <div className="detail-grid">
        {data.coverage && <Coverage c={data.coverage} t={t} lang={lang} />}

        <section className="card">
          <h2>{t('Rules by status')}</h2>
          <BarList
            max={statusMax}
            rows={STATUS_ORDER.map((s) => ({
              key: s,
              label: t(STATUS_LABELS[s]),
              value: data.by_status[s] || 0,
              cls: `fill-${s}`,
            }))}
          />
        </section>

        <section className="card">
          <h2>{t('Rules per component')}</h2>
          <BarList
            max={compMax}
            rows={data.components.map((c) => ({
              key: c.id,
              label: c.name,
              value: c.rules,
              link: '/components',
            }))}
          />
        </section>

        <section className="card wide">
          <h2>{t('Recent changes')}</h2>
          <div className="table-wrap">
            <table>
              <thead>
                <tr><th>{t('Rule')}</th><th>{t('Change')}</th><th>{t('By')}</th><th>{t('Time')}</th></tr>
              </thead>
              <tbody>
                {data.recent_changes.map((c, i) => (
                  <tr key={i}>
                    <td><Link to={`/rules/${c.rule_id}`} className="rule-link">{c.rule_id}</Link>
                      <span className="muted small"> v{c.version}</span></td>
                    <td>{c.change_note}</td>
                    <td>{c.changed_by}</td>
                    <td>{c.changed_at ? new Date(c.changed_at).toLocaleString(dateLocale(lang)) : ''}</td>
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
