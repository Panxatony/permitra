import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { api, getUser } from '../api'
import { useLang } from '../i18n'

/* The first-run checklist (#67): what a fresh instance still needs, in the
   order the steps depend on each other, each saying WHY before the next one
   works. It renders on the dashboard and the admin page until the essentials
   exist, then disappears - except the approver warning, which is permanent:
   the matrix workflow needs two different approvers, and approvers leave
   after setup too.

   Deliberately a guide, not a gate. Every step links to the normal page;
   nothing is blocked, nothing is duplicated as wizard forms. */

const STEP_TEXT = {
  language: {
    title: ['Sprache der Instanz festlegen', 'Set the instance language'],
    why: ['Zuerst, weil jede weitere Seite in ihr erscheint. Gilt für alle Benutzer – so verwenden Screenshots, Schulung und Support dieselben Begriffe.',
          'First, because every later screen renders in it. Applies to every user – so screenshots, training and support share one wording.'],
  },
  zones: {
    title: ['Sicherheitszonen anlegen', 'Create the security zones'],
    why: ['Ohne Zonen funktioniert nichts: jede Regel leitet ihre Zonen aus den Netzen ab.',
          'Nothing works without zones: every rule derives its zones from the networks.'],
  },
  networks: {
    title: ['Netze den Zonen zuordnen', 'Assign networks to zones'],
    why: ['Eine leere Netz-Registry weist jede Adresse ab – „keiner Zone zugeordnet" ist der erste Fehler, den ein neuer Nutzer sonst sieht.',
          'An empty network registry rejects every address – "not assigned to any zone" is the first error a new user sees otherwise.'],
  },
  components: {
    title: ['Sicherheitskomponenten erfassen', 'Register the security components'],
    why: ['Die Firewalls und Fabrics, auf denen Regeln umgesetzt werden.',
          'The firewalls and fabrics rules are implemented on.'],
  },
  matrix: {
    title: ['Zonen-Matrix pflegen oder Default-Deny wählen', 'Maintain the matrix or choose default-deny'],
    why: ['Welche Zonenpaare Regeln erlauben – oder die bewusste Entscheidung, Ungepflegtes abzulehnen (BSI-Empfehlung).',
          'Which zone pairs permit rules – or the deliberate decision to refuse unmaintained ones (BSI recommendation).'],
  },
  accounts: {
    title: ['Konten für die Rollen anlegen', 'Create accounts for the roles'],
    why: ['Mindestens ein Architekt, ein Betrieb – und zwei Change Approver, denn das Vier-Augen-Prinzip braucht zwei verschiedene. Damit ist der Admin-Teil abgeschlossen: alles Weitere machen die Architekten.',
          'At least one architect, one operations – and two change approvers, because four eyes means two different people. This closes the admin part: everything from here on is the architects\u0027 work.'],
  },
  first_rule: {
    title: ['Die erste Regel anlegen', 'Create the first rule'],
    why: ['Die Probe aufs Exempel: sie durchläuft Zonen-Ableitung und Adress-Zuordnung (das Formular fragt je neuer Adresse einmal nach den Komponenten).',
          'The proof: it exercises zone derivation and the address mapping (the form asks once per new address which components it belongs to).'],
  },
}

export default function SetupChecklist() {
  const { lang, t } = useLang()
  const user = getUser()
  const [data, setData] = useState(null)

  useEffect(() => {
    api.setupStatus().then(setData).catch(() => {})
  }, [])

  if (!data) return null
  const de = lang === 'de'
  const fewApprovers = data.warnings.some((w) => w.code === 'too-few-approvers')
  const noBaseUrl = data.warnings.some((w) => w.code === 'base-url-not-set')

  if (data.complete && !fewApprovers && !noBaseUrl) return null

  return (
    <>
      {noBaseUrl && (
        <section className="emergency-banner">
          <h2>{t('PERMITRA_BASE_URL is not set')}</h2>
          <p className="small" style={{ margin: 0 }}>
            {t('Activation and password-reset links are built from it and currently point at localhost – a colleague cannot open the link they were sent. Set it in .env to the address users reach this instance under, then restart the stack.')}
          </p>
        </section>
      )}
      {fewApprovers && (
        <section className="emergency-banner overdue">
          <h2>
            {data.approvers_active === 0
              ? t('No active change approver exists')
              : t('Only one active change approver exists')}
          </h2>
          <p className="small" style={{ margin: 0 }}>
            {t('Matrix, zone and network changes need approval by two different change approvers – with fewer, those requests can never complete, and the second approval simply never comes.')}
            {user.role === 'admin' && <> <Link to="/admin">{t('Create accounts')}</Link></>}
          </p>
        </section>
      )}

      {!data.complete && (
        <section className="card wide setup-card">
          <h2>
            {t('Initial configuration')}{' '}
            <span className="muted small">
              {data.steps.filter((s) => s.done).length}/{data.steps.length}
            </span>
          </h2>
          <p className="muted small">
            {t('Two phases: the admin sets language and accounts, then the architect accounts do the domain work. Nothing here blocks anything – the list disappears once the essentials exist.')}
          </p>
          <ol className="setup-steps">
            {data.steps.map((s, i) => {
              const text = STEP_TEXT[s.id]
              const newPhase = i === 0 || data.steps[i - 1].phase !== s.phase
              return (
                <li key={s.id} className={s.done ? 'setup-done' : ''}>
                  {newPhase && (
                    <div className="setup-phase">
                      {s.phase === 'admin'
                        ? t('The admin prepares the instance')
                        : t('Then the architects take over')}
                    </div>
                  )}
                  <div className="setup-row">
                    <span className="setup-mark">{s.done ? '✓' : '○'}</span>
                    <span>
                      {/* A link only for the role whose move it is. The admin
                          following an architect step's link landed on the zones
                          page - a page whose every action now 403s for them.
                          Showing the step without the link keeps the handover
                          visible and the trap closed. */}
                      {s.role === user.role
                        ? <Link to={s.route}>{text.title[de ? 0 : 1]}</Link>
                        : <>
                            {text.title[de ? 0 : 1]}{' '}
                            <span className="muted small">
                              ({s.role === 'admin' ? t('the admin does this') : t('the architects do this')})
                            </span>
                          </>}
                      {s.count > 0 && <span className="muted small"> ({s.count})</span>}
                      {!s.done && (
                        <span className="muted small setup-why"> — {text.why[de ? 0 : 1]}</span>
                      )}
                    </span>
                  </div>
                </li>
              )
            })}
          </ol>
        </section>
      )}
    </>
  )
}
