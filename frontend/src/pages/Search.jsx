import { useState } from 'react'
import { Link } from 'react-router-dom'
import { api } from '../api'
import { ServiceList, StatusBadge, formatEntry, useZoneLabels } from '../components/shared'
import { useLang } from '../i18n'

const TYPE_LABELS = { juniper: 'Juniper SRX', checkpoint: 'Check Point', aci: 'Cisco ACI' }

function highlight(entries, matched) {
  return (entries || []).map((e, i) => {
    const text = formatEntry(e)
    return <div key={i} className={matched.includes(text) ? 'hit' : ''}>{text}</div>
  })
}

function ServiceChips({ services }) {
  if (!services?.length) return <span className="muted">–</span>
  return services.map((s, i) => (
    <code key={i} className="svc">{s.protocol}{s.port ? `/${s.port}` : ''}</code>
  ))
}

function ResultTable({ rows, showMatch, t, zoneLabel }) {
  if (!rows.length) return <p className="muted">{t('Keine Treffer.')}</p>
  return (
    <div className="table-wrap">
      <table>
        <thead>
          <tr>
            <th>{t('Rule-ID')}</th><th>{t('Komponenten')}</th><th>{t('Quell-Zone')}</th><th>{t('Quelle')}</th>
            <th>{t('Ziel-Zone')}</th><th>{t('Ziel')}</th><th>{t('Dienste')}</th><th>{t('Aktion')}</th><th>{t('Status')}</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((r) => (
            <tr key={r.rule_id} className={r.match === 'any' ? 'row-any' : ''}>
              <td>
                <Link to={`/rules/${r.rule_id}`} className="rule-link">{r.rule_id}</Link>
                {showMatch && r.match === 'any' && <div className="badge match-any">{t('nur über „any“')}</div>}
              </td>
              <td>{(r.components || []).map((name) => <span key={name} className="badge platform-unknown comp-badge">{name}</span>)}</td>
              <td>{zoneLabel(r.source_zone)}</td>
              <td className="addr">{highlight(r.source, r.matched_source || r.matched_entries || [])}</td>
              <td>{zoneLabel(r.destination_zone)}</td>
              <td className="addr">{highlight(r.destination, r.matched_destination || r.matched_entries || [])}</td>
              <td><ServiceList services={r.services} /></td>
              <td><code>{r.action}</code></td>
              <td><StatusBadge status={r.status} /></td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

/* Pfad-Diagramm: Quelle -> Hops (Komponenten) -> Ziel mit Urteil */
function PathFlow({ result, t }) {
  if (!result) return null
  return (
    <>
      {result.unknown_addresses.length > 0 && (
        <div className="warnbox">
          Für {result.unknown_addresses.join(' und ')} ist keine Komponenten-Zuordnung
          gepflegt – der Pfad kann unvollständig sein.
        </div>
      )}

      <div className={result.possible ? 'okbox path-verdict' : 'error path-verdict'}>
        {result.possible ? (
          <>
            ✓ Kommunikation <strong>{result.src} → {result.dst}</strong> ist möglich für:{' '}
            {result.allowed_services.map((s, i) => (
              <code key={i} className="svc">{s.protocol}{s.port ? `/${s.port}` : ''}</code>
            ))}
            {result.intra_zone && <span className="muted"> (Intra-Zone, via ACI)</span>}
          </>
        ) : (
          <>
            ✕ Kommunikation <strong>{result.src} → {result.dst}</strong> ist nicht möglich
            {result.components.some((c) => !c.covered)
              ? ` – auf ${result.components.filter((c) => !c.covered).map((c) => c.name).join(', ')} fehlt eine freigegebene Regel`
              : result.components.length
                ? ' – kein gemeinsamer Dienst über alle Komponenten freigegeben'
                : ' – keine zu passierenden Komponenten ermittelbar'}
          </>
        )}
      </div>

      <div className="path-flow">
        <div className="path-node">
          <div className="path-node-title">{t('Quelle')}</div>
          <code>{result.src}</code>
        </div>
        {result.components.map((c) => (
          <div key={c.id} className="path-step">
            <div className="path-arrow">→</div>
            <div className={`path-comp ${c.covered ? 'comp-ok' : 'comp-missing'}`}>
              <div className="path-comp-head">
                <span className={`badge platform-${c.type}`}>{TYPE_LABELS[c.type]}</span>
                <strong>{c.name}</strong>
                {c.location && <span className="muted small">{c.location}</span>}
              </div>
              <div className="path-comp-meta">
                <span className="badge side-badge">
                  {{ quelle: 'quellseitig', beide: 'beidseitig', ziel: 'zielseitig' }[c.side] || ''}
                </span>
                {c.via_pbr && (
                  <span className="badge pbr-badge" title={`PBR-Umleitung über ${c.gateway}`}>
                    via PBR ({c.gateway})
                  </span>
                )}
              </div>
              {c.rules.length ? (
                <ul className="path-rules">
                  {c.rules.map((r) => (
                    <li key={r.rule_id}>
                      <Link to={`/rules/${r.rule_id}`} className="rule-link">{r.rule_id}</Link>{' '}
                      <ServiceChips services={r.services} />{' '}
                      <StatusBadge status={r.status} />
                      {r.action === 'deny' && <span className="badge status-rejected">deny</span>}
                      {r.via_any && <span className="badge match-any">via any</span>}
                    </li>
                  ))}
                </ul>
              ) : (
                <div className="path-missing">Keine passende Regel auf dieser Komponente</div>
              )}
            </div>
          </div>
        ))}
        <div className="path-step">
          <div className="path-arrow">→</div>
          <div className="path-node">
            <div className="path-node-title">{t('Ziel')}</div>
            <code>{result.dst}</code>
          </div>
        </div>
      </div>
    </>
  )
}

export default function Search() {
  const { t } = useLang()
  const zoneLabel = useZoneLabels()
  const [src, setSrc] = useState('')
  const [dst, setDst] = useState('')
  const [result, setResult] = useState(null)       // Adress-Suche (ein Feld)
  const [pathResult, setPathResult] = useState(null)  // Pfad-Diagramm (beide Felder)
  const [pathRules, setPathRules] = useState(null)    // Regeln zwischen Quelle und Ziel
  const [mode, setMode] = useState(null)
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)

  const isIpish = (v) => /^[0-9a-fA-F.:]+(\/\d{1,3})?$/.test(v) || v.toLowerCase() === 'any'

  const submit = async (e) => {
    e.preventDefault()
    const s = src.trim(), d = dst.trim()
    if (!s && !d) return
    setLoading(true)
    setError('')
    setResult(null)
    setPathResult(null)
    setPathRules(null)
    try {
      if (s && d) {
        setMode('path')
        // Regel-Tabelle immer; Pfad-Diagramm nur für konkrete IPs/Netze
        const wantFlow = isIpish(s) && isIpish(d)
        const [rules, flow] = await Promise.all([
          api.pathSearch(s, d),
          wantFlow
            ? api.pathAnalysis(new URLSearchParams({ src: s, dst: d })).catch(() => null)
            : Promise.resolve(null),
        ])
        setPathRules(rules)
        setPathResult(flow)
      } else {
        setMode('ip')
        setResult(await api.ipSearch(s || d))
      }
    } catch (err) {
      setError(err.message)
    } finally {
      setLoading(false)
    }
  }

  return (
    <div>
      <div className="page-head">
        <h1>{t('Analyse')}</h1>
        <span className="muted">
          {t('Nur Quelle ODER Ziel: alle ein-/ausgehenden Regeln der Adresse. Beides: Pfad-Prüfung über die Komponenten plus alle passenden Regeln.')}
        </span>
      </div>

      <form className="filterbar pair-form" onSubmit={submit}>
        <input value={src} onChange={(e) => setSrc(e.target.value)}
          placeholder={t('Quelle: IP, Netz (10.10.105.0/24) oder Hostname')} />
        <span className="muted">→</span>
        <input value={dst} onChange={(e) => setDst(e.target.value)}
          placeholder={t('Ziel: IP, Netz oder Hostname (optional)')} />
        <button className="btn btn-primary" type="submit">{t('Analysieren')}</button>
      </form>

      {error && <div className="error">{error}</div>}
      {loading && <p className="muted">{t('Lade…')}</p>}

      {mode === 'path' && (
        <>
          <PathFlow result={pathResult} t={t} />
          {pathRules && (
            <section>
              <h2>{t('Regeln')} {pathRules.src} → {pathRules.dst} ({pathRules.results.length})</h2>
              <ResultTable rows={pathRules.results} showMatch t={t} zoneLabel={zoneLabel} />
            </section>
          )}
        </>
      )}

      {mode === 'ip' && result && (
        <div className="search-results">
          <section>
            <h2>{t('⬆ Ausgehend – als Quelle')} ({result.outgoing.length})</h2>
            <ResultTable rows={result.outgoing} showMatch={result.is_network} t={t} zoneLabel={zoneLabel} />
          </section>
          <section>
            <h2>{t('⬇ Eingehend – als Ziel')} ({result.incoming.length})</h2>
            <ResultTable rows={result.incoming} showMatch={result.is_network} t={t} zoneLabel={zoneLabel} />
          </section>
        </div>
      )}
    </div>
  )
}
