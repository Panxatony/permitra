import { useEffect, useState } from 'react'
import { useLocation, useNavigate } from 'react-router-dom'
import { Modal } from '../components/shared'
import { useLang } from '../i18n'

/* The help lives in the application, not only in the repository: the person
   with the question is standing in front of a form, not in front of GitHub.
   Content is kept here as one bilingual structure rather than in the i18n
   dictionary - these are pages of prose keyed by topic, not labels keyed by
   English text, and the instance language decides which half renders.

   The page is an overview of topics; the text itself opens as an overlay. One
   wall of nine sections answers none of them well - a reader with a question
   has one, not nine. Pages link here with anchors (/help#recert), which open
   the matching overlay directly, so the "?" next to a feature lands on the
   explanation rather than on a table of contents. */

// **bold** and `code`, nothing more. A markdown renderer would invite content
// this file is the wrong home for.
function fmt(text) {
  const parts = text.split(/(\*\*[^*]+\*\*|`[^`]+`)/g)
  return parts.map((p, i) => {
    if (p.startsWith('**')) return <strong key={i}>{p.slice(2, -2)}</strong>
    if (p.startsWith('`')) return <code key={i}>{p.slice(1, -1)}</code>
    return p
  })
}

const SECTIONS = [
  {
    id: 'workflow',
    de: {
      title: 'Der Weg einer Regel',
      body: [
        'Eine Regel durchläuft `Entwurf → Im Review → Freigegeben → Aktiv`. **Freigegeben** heißt: jemand anderes hat entschieden, dass es die Regel geben darf. **Aktiv** heißt: der Betrieb hat bestätigt, dass sie auf allen zugeordneten Komponenten tatsächlich umgesetzt ist — der Status springt automatisch, sobald die letzte Komponente auf „umgesetzt" steht, und fällt zurück auf „freigegeben", wenn eine es nicht mehr ist. Der Unterschied macht sichtbar, was sonst unsichtbar wäre: freigegeben, aber nie ausgerollt.',
        'Eine inhaltliche Änderung an einer freigegebenen Regel setzt sie zurück auf **Entwurf** — die alte Freigabe galt der alten Regel. Bereits umgesetzte Komponenten stehen nach erneuter Freigabe auf „zu ändern", damit der Betrieb den Unterschied nachzieht.',
        '**Gelöscht wird nie.** Eine nicht mehr benötigte Regel bekommt den Status „gelöscht", bleibt in der Übersicht sichtbar (durchgestrichen) und behält Historie und Kommentare als Nachweis. Was endet, ist ihre Wirkung: kein Export, keine Pfad-Analyse, kein Soll-Ist-Abgleich.',
      ],
    },
    en: {
      title: 'The life of a rule',
      body: [
        'A rule moves through `draft → in review → approved → active`. **Approved** means somebody else decided the rule may exist. **Active** means operations confirmed it actually exists on every assigned component — the status switches automatically when the last component reports "implemented", and falls back to "approved" when one no longer does. The distinction makes visible what would otherwise be invisible: approved but never rolled out.',
        'A content change to an approved rule resets it to **draft** — the old approval belonged to the old rule. Components already implemented switch to "to change" after re-approval, so operations applies the difference.',
        '**Nothing is ever deleted.** A rule no longer needed takes the status "deleted", stays visible in the overview (struck through) and keeps its history and comments as evidence. What ends is its effect: no export, no path analysis, no drift comparison.',
      ],
    },
  },
  {
    id: 'recert',
    de: {
      title: 'Rezertifizierung: Kampagnen',
      body: [
        'Ein Ablaufdatum zu verlängern ist eine Entscheidung über einen Kalender. Eine **Kampagne** stellt die eigentliche Frage, Regel für Regel: wird sie noch gebraucht, stimmt ihr Zuschnitt, gibt es ihren Verantwortlichen noch? Genau das verlangt eine Prüfung nach BSI NET.3.2 — und genau das kann ein Datumsfeld nicht beantworten.',
        'So läuft eine Kampagne ab:',
        { ol: [
          'Ein **Admin oder Change Approver startet** sie: Name, Stichtag und Umfang — `all` (alle Regeln in Kraft), `zone:Z040` (alle Regeln aus oder in die Zone) oder `component:3` (alle Regeln dieser Komponente). Die Liste wird beim Start eingefroren; später angelegte Regeln gehören zur nächsten Kampagne.',
          'Jede Regel steht mit ihrem **Verantwortlichen** auf der Liste. Der Filter „Nur meine Regeln" zeigt jedem seinen Anteil. Verantwortliche, die keinem aktiven Benutzer entsprechen, werden markiert — diese Regeln bearbeitet sonst niemand, und oft ist das der erste Hinweis, dass ein Owner die Organisation verlassen hat.',
          'Pro Regel fällt **eine von drei Entscheidungen**: **„Weiterhin nötig"** bestätigt die Regel (auf Wunsch mit neuem Ablaufdatum, sonst läuft sie trotz Bestätigung ab). **„Nötig, aber fehlerhaft"** schickt sie mit Pflicht-Begründung zurück ins Review — der Mittelweg, damit niemand eine fast richtige Regel durchwinken oder stilllegen muss. **„Nicht mehr nötig"** deaktiviert sie und setzt die Komponenten auf „zu löschen".',
          'Jede Entscheidung wird **namentlich festgehalten** und kann nicht überschrieben werden — wer es versucht, erfährt, wer zuerst entschieden hat. Auf der Regel selbst steht danach, wer sie zuletzt bewusst bestätigt hat und wann.',
          'Zum Stichtag zeigt der **Bericht (CSV)**, wer was entschieden hat und was offen ist. Offene Einträge bleiben beim Schließen offen — eine unentschiedene Regel ist ein Befund, kein Schönheitsfehler. Der Bericht ist das, was ein Prüfer tatsächlich sehen will.',
        ] },
        'Die Abschnitte „Abgelaufen" und „Läuft ab" darunter sind davon unabhängig: das ist die tägliche Ablaufkontrolle, die weiterläuft wie bisher.',
      ],
    },
    en: {
      title: 'Recertification: campaigns',
      body: [
        'Extending an expiry date is a decision about a calendar. A **campaign** asks the actual question, rule by rule: is it still needed, is its scope still right, does its owner still exist? That is what a BSI NET.3.2 review demands — and what a date field cannot answer.',
        'How a campaign runs:',
        { ol: [
          'An **admin or change approver starts** it: name, cut-off date and scope — `all` (every rule in force), `zone:Z040` (every rule out of or into the zone) or `component:3` (every rule on that component). The list is frozen at start; rules created later belong to the next campaign.',
          'Every rule sits on the list with its **owner**. The "Only my rules" filter shows each person their share. Owners matching no active user are flagged — nobody will work on those rules otherwise, and often this is the first sign an owner has left the organisation.',
          'Per rule, **one of three decisions**: **"Still required"** confirms it (optionally with a new expiry — otherwise it expires despite the confirmation). **"Needed, but wrong"** sends it back into review with a mandatory reason — the middle path, so nobody has to wave through or kill an almost-right rule. **"No longer needed"** deactivates it and sets its components to "to remove".',
          'Every decision is **recorded by name** and cannot be overwritten — whoever tries is told who decided first. The rule itself then shows who last deliberately confirmed it, and when.',
          'At the cut-off, the **report (CSV)** shows who decided what and what is outstanding. Open items stay open when the campaign is closed — an undecided rule is a finding, not a blemish. The report is what an auditor actually asks for.',
        ] },
        'The "Expired" and "Expiring" sections below are independent of this: that is the daily expiry control, which keeps running as before.',
      ],
    },
  },
  {
    id: 'emergency',
    de: {
      title: 'Notfall-Änderung',
      body: [
        'Um drei Uhr nachts, Anwendung steht, kein Change Approver erreichbar: die Regel wird auf der Firewall geöffnet — das verhindert kein Werkzeug. Was Permitra verhindert, ist, dass sie **unaufgezeichnet** bleibt. Über „Notfall-Änderung" wird die bereits gesetzte Regel nachträglich dokumentiert, mit Pflicht-Begründung: Störung, Ticket, wer erreichbar war.',
        'Die Regel geht ins Review und trägt eine **Uhr**: ohne nachträgliche Freigabe innerhalb des Zeitfensters (Standard 24 Stunden) deaktiviert sie sich selbst, und der Betrieb wird angewiesen, sie zurückzubauen. Bis dahin steht sie deutlich sichtbar auf dem Dashboard.',
        'Der Weg ist bewusst eng statt bequem: keine Abkürzung an der Freigabe vorbei, sondern ein eigener Audit-Eintrag — damit zählbar bleibt, wie oft das vorkommt. Zweimal im Jahr ist ein funktionierender Prozess; wöchentlich ist ein Befund.',
      ],
    },
    en: {
      title: 'Emergency change',
      body: [
        'Three in the morning, the application is down, no change approver reachable: the rule gets opened on the firewall — no tool prevents that. What Permitra prevents is that it stays **unrecorded**. "Emergency change" documents the rule already in place, with a mandatory reason: incident, ticket, who was reachable.',
        'The rule goes into review carrying a **clock**: without an approval after the fact within the window (default 24 hours) it deactivates itself, and operations is told to remove it. Until then it sits prominently on the dashboard.',
        'The path is deliberately narrow rather than convenient: not a shortcut around approval, and its own audit event — so it stays countable how often this happens. Twice a year is a working process; weekly is a finding.',
      ],
    },
  },
  {
    id: 'zones',
    de: {
      title: 'Zonen, Netzwerke und die Matrix',
      body: [
        'Quell- und Zielzone einer Regel werden **nicht eingegeben, sondern abgeleitet**: jedes Netz gehört zu genau einer Sicherheitszone (Seite „Netzwerke"), und die Adressen der Regel bestimmen ihre Zonen. Wird eine Adresse abgelehnt („keiner Zone zugeordnet"), fehlt die Netz-Zuordnung — sie wird einmal auf der Netzwerke-Seite gepflegt und gilt dann für alle künftigen Regeln.',
        'Die **Kommunikationsmatrix** legt je Zonenpaar fest, ob Regeln überhaupt zulässig sind. Steht die Beziehung auf Block (oder ist ungepflegt, bei aktivem Default-Deny), wird die Regel mit einer Meldung abgewiesen — die Matrix ändert man nicht nebenbei, sondern per Antrag mit **zwei Freigaben durch verschiedene Change Approver**.',
        'Ein Zonenübergang läuft **immer über eine Firewall** (BSI-Prinzip): eine zonenübergreifende Regel, deren Komponenten alle ACI sind, wird abgelehnt. ACI-Contracts sind das Werkzeug innerhalb einer Zone.',
        'Wird ein Netz in eine andere Zone verschoben, werden **alle betroffenen Regeln neu bewertet**: Zonen neu abgeleitet, Matrix neu geprüft. Regeln, die dadurch unzulässig werden, gehen als Löschvorschlag ins Review — die Freigabe ist dann die Freigabe ihres Rückbaus.',
      ],
    },
    en: {
      title: 'Zones, networks and the matrix',
      body: [
        'A rule\'s source and destination zones are **derived, not entered**: every network belongs to exactly one security zone (Networks page), and the rule\'s addresses determine its zones. If an address is rejected ("not assigned to any zone"), the network mapping is missing — maintain it once on the Networks page and it applies to every future rule.',
        'The **communication matrix** governs, per zone pair, whether rules are admissible at all. If the relation is Block (or unmaintained, with default-deny active), the rule is refused with a message — the matrix is not changed in passing but by request with **two approvals by different change approvers**.',
        'A zone transition **always crosses a firewall** (BSI principle): a cross-zone rule whose components are all ACI is refused. ACI contracts are the tool within a zone.',
        'When a network moves to another zone, **every affected rule is re-assessed**: zones re-derived, matrix re-checked. Rules that become inadmissible go into review as removal proposals — approving one approves its removal.',
      ],
    },
  },
  {
    id: 'drift',
    de: {
      title: 'Soll-Ist-Abgleich und Deckungsgrad',
      body: [
        'Der Abgleich vergleicht die dokumentierten Regeln mit einer hochgeladenen Gerätekonfiguration (Seite „Berichte") und beantwortet **beide Richtungen**. Erstens: sind meine Regeln angekommen? `missing` = freigegeben, aber nicht auf dem Gerät; `stale` = auf dem Gerät, aber nicht mehr freigegeben; `unknown` = eine SR-ID, die Permitra nicht kennt.',
        'Zweitens die Frage, für die Permitra existiert: **ist jede Regel auf dem Gerät durch eine freigegebene Sicherheitsregel begründet?** Regeln ohne SR-ID — von Hand geöffnet, aus der Zeit vor Permitra — erscheinen als `unbegründet`, mit Name und Zeilennummer. Daraus entsteht der **Deckungsgrad** auf dem Dashboard.',
        'Die Zahl ist ehrlich, oder sie ist nichts: sie erscheint nie ohne die Angabe, auf wie vielen Komponenten gemessen wurde. Komponenten ohne Konfiguration oder mit unlesbarem Format werden **benannt statt weggemittelt** — „kann ich nicht lesen" wird nie zu „alles in Ordnung". Eine laufende Notfall-Änderung gilt nicht als `stale`: sie liegt absichtlich auf dem Gerät, solange ihr Zeitfenster offen ist.',
      ],
    },
    en: {
      title: 'Drift comparison and coverage',
      body: [
        'The comparison checks the documented rules against an uploaded device configuration (Reports page) and answers **both directions**. First: did my rules arrive? `missing` = approved but not on the device; `stale` = on the device but no longer approved; `unknown` = an SR ID Permitra does not know.',
        'Second, the question Permitra exists for: **is every rule on the device backed by an approved security rule?** Rules without an SR ID — opened by hand, predating Permitra — appear as `unjustified`, with name and line number. This produces the **coverage figure** on the dashboard.',
        'The figure is honest or it is nothing: it never appears without stating how many components it was measured on. Components without a configuration, or in an unreadable format, are **named rather than averaged away** — "cannot read it" never becomes "all clear". A pending emergency change does not count as `stale`: it sits on the device on purpose while its window is open.',
      ],
    },
  },
  {
    id: 'risk',
    de: {
      title: 'Risikohinweise',
      body: [
        'Regeln werden gegen sichtbare Kriterien geprüft: any-zu-any, `any` als Quelle, sehr breite Netze, riskante Dienste (Portliste vom Admin pflegbar, Bereiche wie `20-25` werden aufgelöst), `any`-Dienst über Zonengrenzen — und eine Regel **ohne Protokollierung in eine Zone mit hohem Schutzbedarf**.',
        'Der Schweregrad steigt mit dem Schutzbedarf der Zielzone und bei exponierter Quelle. Hinweise blockieren nichts: sie stehen beim Review sichtbar dabei, damit die Entscheidung sie einbezieht. „Nach welchen Kriterien?" auf der Regelseite zeigt den vollständigen Maßstab — ein fehlender Hinweis heißt „nicht auf der Liste", nicht „harmlos".',
      ],
    },
    en: {
      title: 'Risk findings',
      body: [
        'Rules are checked against visible criteria: any-to-any, `any` as source, very broad networks, risky services (port list maintainable by admins; ranges like `20-25` are expanded), an `any` service across zones — and a rule **logging nothing into a zone with high protection requirements**.',
        'Severity rises with the destination zone\'s protection level and with an exposed source. Findings block nothing: they stand beside the review so the decision takes them into account. "By which criteria?" on the rule page shows the full yardstick — an absent finding means "not on the list", not "harmless".',
      ],
    },
  },
  {
    id: 'logging',
    de: {
      title: 'Protokollierung, deny und reject',
      body: [
        'Jede Regel legt fest, was sie protokolliert: **keine**, **standard** (jeder Treffer) oder **detailliert** (inklusive Sitzungsende — bei Juniper `session-init session-close`, bei Check Point „Detailed Log"). Der Abgleich mit der Zonen-Schutzstufe läuft über die Risikohinweise.',
        'Bei Verweigerung gibt es zwei Arten: **deny (drop)** verwirft still — der Aufrufer läuft in einen Timeout. **reject** antwortet mit ICMP unreachable oder TCP RST — der Aufrufer bekommt sofort einen Fehler. Faustregel: nach außen Stille, nach innen eine Antwort; ein Drop im eigenen Netz macht aus einem Konfigurationsfehler ein 30-Sekunden-Hängen und ein Ticket. Plattformen ohne reject (z. B. Cisco Extended ACL) erzeugen deny — das ist die Grenze des Geräts, kein verlorener Wert.',
      ],
    },
    en: {
      title: 'Logging, deny and reject',
      body: [
        'Every rule states what it logs: **none**, **standard** (each match) or **detailed** (including session end — Juniper `session-init session-close`, Check Point "Detailed Log"). The check against the zone\'s protection level runs through the risk findings.',
        'There are two refusals: **deny (drop)** discards silently — the caller runs into a timeout. **reject** answers with ICMP unreachable or a TCP RST — the caller gets an immediate error. Rule of thumb: silence outward, an answer inward; a drop inside your own network turns a misconfiguration into a thirty-second hang and a ticket. Platforms without reject (e.g. Cisco extended ACLs) render deny — that is the device\'s limit, not a lost setting.',
      ],
    },
  },
  {
    id: 'exports',
    de: {
      title: 'Exporte',
      body: [
        'Permitra **schreibt nie selbst auf Geräte**. Es erzeugt die Konfiguration zum Übernehmen: Juniper set-Kommandos, Check Point mgmt_cli und Management-API, EPG-basierte ACI-Contracts, Host-Firewalls, Capirca/Aerleon-Ziele, CSV/JSON.',
        'In einen Export kommen nur Regeln **in Kraft** (freigegeben oder aktiv) — auch wenn explizite IDs angegeben werden: `ids=` wählt aus, *welche* Regeln gemeint sind, nicht ob ihr Status noch zählt. Eine Vorschau nicht freigegebener Regeln braucht `only_approved=false` und wird im Audit-Log als solche vermerkt. Jeder Export schreibt einen Audit-Eintrag.',
      ],
    },
    en: {
      title: 'Exports',
      body: [
        'Permitra **never writes to devices itself**. It produces the configuration to apply: Juniper set commands, Check Point mgmt_cli and Management API, EPG-based ACI contracts, host firewalls, Capirca/Aerleon targets, CSV/JSON.',
        'Only rules **in force** (approved or active) enter an export — even with explicit IDs: `ids=` narrows *which* rules are meant, not whether their status still counts. Previewing unapproved rules needs `only_approved=false` and is marked as such in the audit log. Every export writes an audit entry.',
      ],
    },
  },
  {
    id: 'roles',
    de: {
      title: 'Rollen und Vier-Augen-Prinzip',
      body: [
        '**Architekten** legen Regeln an und reichen sie ein. **Change Approver** entscheiden: eine Freigabe je Regel-Review, **zwei verschiedene Approver** je Zonen-, Netz- oder Matrixantrag. Wer eine Regel eingereicht oder erstellt hat, kann sie nicht selbst freigeben — auch Admins nicht. **Betrieb** pflegt den Umsetzungsstatus je Komponente, exportiert und lädt Gerätekonfigurationen für den Abgleich. **Admins** verwalten Benutzer und Einstellungen.',
        'Das Audit-Log hält jede Anmeldung, jede Verwaltungsaktion und jeden Datenzugriff fest, verkettet mit SHA-256-Hashes und auf Wunsch an ein SIEM zugestellt. Einträge erscheinen in der Sprache der Instanz — auch rückwirkend nach einem Sprachwechsel.',
      ],
    },
    en: {
      title: 'Roles and the four-eyes principle',
      body: [
        '**Architects** create rules and submit them. **Change approvers** decide: one approval per rule review, **two different approvers** per zone, network or matrix request. Whoever submitted or created a rule cannot approve it — admins included. **Operations** maintains the implementation status per component, exports, and uploads device configurations for the drift comparison. **Admins** manage users and settings.',
        'The audit log records every sign-in, administrative action and data access, chained with SHA-256 hashes and delivered to a SIEM if configured. Entries render in the instance\'s language — retroactively, after a language switch.',
      ],
    },
  },
]

/* The first sentence of a section is its teaser on the card - written to
   carry the idea on its own, so nothing here needs a separate summary. */
function teaser(section) {
  const first = section.body.find((b) => typeof b === 'string') || ''
  const cut = first.indexOf('. ')
  return cut > 0 ? first.slice(0, cut + 1) : first
}

export default function Help() {
  const { lang, t } = useLang()
  const { hash } = useLocation()
  const navigate = useNavigate()
  const [openId, setOpenId] = useState(null)

  // A deep link (/help#recert) opens its overlay directly - the "?" beside a
  // feature must land on the explanation, not on a table of contents.
  useEffect(() => {
    const id = hash.slice(1)
    setOpenId(SECTIONS.some((s) => s.id === id) ? id : null)
  }, [hash])

  const open = (id) => navigate(`/help#${id}`)
  const close = () => navigate('/help')
  const current = SECTIONS.find((s) => s.id === openId)
  const content = current && (lang === 'de' ? current.de : current.en)

  return (
    <div className="help-page">
      <div className="page-head">
        <h1>{t('Help')}</h1>
        <span className="muted">
          {t('What the interface cannot say in one line – in-depth documentation lives in the repository')}
        </span>
      </div>

      <div className="help-grid">
        {SECTIONS.map((s) => {
          const c = lang === 'de' ? s.de : s.en
          return (
            <button key={s.id} type="button" className="card help-card"
              onClick={() => open(s.id)}>
              <h2>{c.title}</h2>
              <p className="muted">{fmt(teaser(c))}</p>
            </button>
          )
        })}
      </div>

      {content && (
        <Modal title={content.title} onClose={close}>
          <div className="help-section">
            {content.body.map((item, i) =>
              typeof item === 'string'
                ? <p key={i}>{fmt(item)}</p>
                : <ol key={i}>{item.ol.map((li, j) => <li key={j}>{fmt(li)}</li>)}</ol>
            )}
          </div>
        </Modal>
      )}

      <p className="muted small">
        {t('These topics are also on the website, linkable and printable:')}{' '}
        <a href="https://permitra.de/hilfe.html" target="_blank" rel="noopener noreferrer">
          permitra.de/hilfe
        </a>
      </p>
    </div>
  )
}
