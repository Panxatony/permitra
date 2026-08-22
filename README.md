# 🛡️ Permitra

Zentrale Webanwendung zur Verwaltung von Sicherheitsregeln für **Juniper SRX**, **Check Point** und **Cisco ACI Contracts** – als Ablösung der Excel-basierten Kommunikationsmatrix (AP0400).

## Architektur

```
┌──────────────┐      REST/JSON      ┌───────────────┐      SQL      ┌────────────┐
│  React SPA   │ ──────────────────► │  FastAPI      │ ────────────► │ PostgreSQL │
│  (Vite)      │  JWT (rollenbasiert)│  Backend      │  SQLAlchemy   │ (SQLite    │
│  Tabelle,    │                     │  Validierung, │               │  für Dev)  │
│  Review-UI,  │                     │  Workflow,    │               └────────────┘
│  Export-     │                     │  Konflikt-    │
│  Vorschau    │                     │  Erkennung    │
└──────────────┘                     └──────┬────────┘
                                            │ Exporter
                        ┌───────────────────┼──────────────────────┐
                        ▼                   ▼                      ▼
                 Juniper SRX          Check Point              Cisco ACI
                 (set-Kommandos)      (mgmt_cli-Skript,        (APIC-JSON,
                                       Management-API-JSON)     YAML)
```

**Rollen:**

| Rolle | Rechte |
|---|---|
| `architect` (Architekt) | Regeln anlegen/bearbeiten, zum Review einreichen, kommentieren |
| `operations` (Betrieb) | Umsetzungsstatus je Komponente pflegen, exportieren, Drift-Abgleich |
| `change_approver` (Change Approver) | Freigaben: Regel-Reviews (eine Freigabe) und Zonen-/Matrix-Anträge (zwei Freigaben durch verschiedene Approver) |
| `admin` | Alles, zusätzlich Benutzer- und Regel-Löschverwaltung |

**Regel-Workflow:** `Entwurf → Im Review → Freigegeben/Abgelehnt → (Deaktiviert)`.
Inhaltliche Änderungen an freigegebenen Regeln setzen den Status auf `Entwurf` zurück.
Getrennt davon pflegt der Betrieb den **Umsetzungsstatus je Plattform** (`offen/neu/umgesetzt/deaktiviert` – entspricht den Spalten „Status Juniper“/„Status ACI“ im Excel).

**Datenmodell**: Rule-ID im `SR#####`-Format (5-stellig, bis 99999 Regeln) mit Auto-Vergabe, Application, Quell-/Ziel-Zonen
(Dropdown aus der Zonenverwaltung), mehrere Dienste (Protokoll/Port) pro Regel, Anlass,
Requestor, Bearbeiter, Change-ID, Fachlicher Bezug, Gültigkeitszeitraum, Versionshistorie
mit Snapshots, Kommentare.

- **Adressen sind strukturiert**: Quelle/Ziel bestehen aus Einträgen, die **immer eine
  IP oder ein Netz (CIDR, IPv4/IPv6)** sind – plus optionalem **Alias** pro Eintrag
  (Hostname bei einer Einzel-IP, Netzwerkname bei einem Netz). Sonderwert `any`.
  Die Exporter verwenden den Alias als Objektnamen (Juniper Address-Book, Check Point
  Hosts/Netze); die Adress-Suche findet Einträge über IP-Überlappung **und** Alias.
- **Regeln mappen auf konkrete Komponenten** (nicht abstrakt auf Plattformen): Jede Regel
  referenziert die Sicherheitskomponenten (Firewall-Cluster bzw. ACI-Fabric), auf denen
  eine Firewall-Regel bzw. ein ACI Contract angelegt werden muss. Die Plattform ergibt
  sich aus dem Komponenten-Typ (steuert Exportformate und Zonen-Matrix-Prüfung), der
  Umsetzungsstatus wird je Komponente gepflegt, und der Export lässt sich auf eine
  Komponente einschränken (`/api/export/{fmt}?component_id=`).
- **Komponenten werden automatisch aus Quelle/Ziel ermittelt** über die persistente
  Adress-Zuordnung (`address_component_map`, API `/api/address-map`,
  `/api/rules/resolve-components`): exakter Treffer oder spezifischstes enthaltendes
  Netz; Intra-Zonen-Regeln lösen auf ACI-Komponenten auf, zonenübergreifende auf die
  Firewall-Cluster. Enthält eine Regel eine **neue Adresse**, fordert das Formular
  **einmalig** dazu auf festzulegen, auf welchen Komponenten Regeln für diese Adresse
  angelegt werden – die Zuordnung wird gespeichert und künftig automatisch angewendet.
  Ohne Zuordnung lehnt die API das Anlegen mit einer klaren Meldung ab.

## Dashboard, Rezertifizierung, Drift & Objektkatalog

- **Dashboard** (Startseite): Kennzahlen-Kacheln (Regeln, offene Reviews, abgelaufen /
  läuft in 30 Tagen ab), Regeln nach Status und je Komponente, letzte Änderungen.
- **Gültigkeits-Überwachung**: Ein täglicher Job deaktiviert freigegebene Regeln
  automatisch nach Ablauf von `valid_until` (mit Versions- und Kommentareintrag).
  Die Seite „Rezertifizierung" (`GET /api/rules/expiring?days=`) zeigt abgelaufene und
  demnächst ablaufende Regeln; „Verlängern" (`POST /api/rules/{id}/extend`) setzt ein
  neues Gültig-bis-Datum, **ohne** den Freigabe-Status zurückzusetzen.
- **Soll-Ist-Abgleich (Drift)** auf der Komponenten-Seite: Ist-Konfiguration des Geräts
  hinterlegen (`PUT /api/components/{id}/actual-config`; ein direkter Geräte-Abruf kann
  als Adapter andocken) → `GET /api/components/{id}/drift` meldet **fehlende** (freigegeben,
  nicht umgesetzt), **veraltete** (umgesetzt, nicht mehr freigegeben) und **unbekannte**
  Regel-IDs (Schatten-Regeln). Abgleich über die SR-IDs, die alle Exporte mitführen.
- **Objektkatalog** (`/api/objects/...`): wiederverwendbare Adress-Objekte (Alias → IP/Netz)
  und Dienst-Objekte (z.B. HTTPS = TCP/443), im Regelformular per Auswahl übernehmbar.
  Ändert sich die IP eines Adress-Objekts, werden **alle Regeln mit diesem Alias
  automatisch aktualisiert** (versioniert).
- **Migrationen & Backup**: Schema-Änderungen laufen über **Alembic** (Migrationen in
  `backend/alembic/`, automatisch beim App-Start; Vor-Alembic-Bestände werden auf die
  Baseline gestempelt). Tägliche Sicherung: `scripts/backup.sh` (pg_dump, 14 Generationen).
- **Pagination**: `GET /api/rules` liefert `{total, items}` mit `limit`/`offset`;
  die Regelliste blättert in 50er-Schritten.

## ACI Contracts (EPG-basiert)

Der ACI-Export modelliert Contracts idiomatisch statt „ein Contract pro Regel":

- **EPG-Katalog** (`/api/epgs`, Pflege auf der Objekte-Seite): EPGs mit Tenant,
  Application Profile und Bridge Domain, plus **Adresse→EPG-Zuordnung** (exakter Treffer
  oder spezifischstes enthaltendes Netz; `any` → **vzAny**).
- **Aggregierung**: Quelle → Consumer, Ziel → Provider; alle Regeln eines
  (Consumer-EPG, Provider-EPG)-Paars werden zu **einem Contract**
  (`con-<consumer>-to-<provider>`, scope `context`) mit einem Subject je Filter —
  das vermeidet Contract-/TCAM-Explosion in der Fabric.
- **Filter-Wiederverwendung**: Dienste werden gegen den Dienst-Objektkatalog aufgelöst
  (`flt-https` statt Duplikat je Regel) und über alle Contracts dedupliziert.
- **Service Graph/PBR**: Trägt die Bridge Domain des Provider-EPG ein Anycast Gateway
  mit PBR, referenziert das Subject dessen Service-Graph-Template (`vzRsSubjGraphAtt`).
- **EPG-Bindings**: Der APIC-JSON-Export enthält `fvAp`/`fvAEPg` mit
  `fvRsProv`/`fvRsCons`-Referenzen; SR-IDs stehen in den Subject-Beschreibungen
  (Rückverfolgbarkeit/Drift). Regeln ohne EPG-Zuordnung fallen auf Einzel-Contracts
  zurück und werden in den Warnungen ausgewiesen (sichtbar im YAML-Export).

## Host-Firewall-Export

Auf der Export-Seite (Abschnitt „Host-Firewall für einen Ziel-Server") erzeugt Permitra
für eine **Ziel-IP** die lokalen Firewall-Regeln des Servers
(`GET /api/export/host/{debian|redhat|sles}?ip=`): Grundlage sind alle freigegebenen
permit-Regeln, deren Ziel die IP abdeckt (exakt, per Netz-Containment oder via `any` –
gekennzeichnet). Formate: **Debian** = nftables-Regelwerk (default drop, loopback,
established/related, ICMP), **RedHat** = firewalld-Skript mit Rich Rules + `--reload`,
**SLES** = iptables-Skript (Hinweis: SLES 15 nutzt firewalld → RedHat-Export). Jede
Regelzeile trägt die SR-ID als Kommentar; IPv6-Quellen werden korrekt behandelt
(`ip6 saddr` / `family="ipv6"` / `ip6tables`).

## Pfad-Analyse (visuelle Ansicht)

Menüpunkt „Pfad-Analyse" (`GET /api/rules/path-analysis?src=&dst=`): Zeigt für ein
Quell-/Ziel-IP-Paar als Fluss-Diagramm (Quelle → Komponenten → Ziel), **ob die
Kommunikation möglich ist** und **für welche Protokolle/Ports** (Schnittmenge der
freigegebenen permit-Regeln über alle zu passierenden Komponenten). Je Komponente
werden die Regeln angezeigt, die den Verkehr dort ermöglichen (verlinkt, mit Status,
deny- und „via any"-Kennzeichnung); Komponenten ohne passende freigegebene Regel
werden rot markiert und in der Bewertung benannt.

**Mehr-Hop-Topologie**: Die Hops sind geordnet (quellseitige Komponenten → beidseitige →
zielseitige, abgeleitet aus der Adress-Zuordnung). Liegt eine Adresse im Netz eines ACI
Anycast Gateways mit **PBR**, erscheint der Check Point Cluster als zusätzlicher Hop
(„via PBR", mit Gateway-Name) und wird im Urteil mitgeprüft.

## Schnellstart (lokal, ohne Docker)

```bash
# 1. Backend
python3 -m venv .venv
.venv/bin/pip install -r backend/requirements.txt openpyxl
cd backend
../.venv/bin/python -m uvicorn app.main:app --port 8000   # API auf :8000, legt SQLite + Demo-User an

# 2. Demo-Daten erzeugen (11 Zonen, Matrix, ~100 Regeln) – empfohlen zum Testen
cd backend
../.venv/bin/python seed_demo.py --wipe

#    Alternativ: echte Excel-Daten importieren
../.venv/bin/python import_excel.py ../data/AP0400Sicherheitsregeln.xlsx   # Regeln
../.venv/bin/python import_zones.py ../data/AP0400_Zonenmatrix.xlsx        # Zonen + Matrix

# 3. Frontend
cd frontend
npm install
npm run dev                                               # UI auf http://localhost:5173
```

**Demo-Logins:** `architekt/architekt123`, `betrieb/betrieb123`, `admin/admin123`
API-Dokumentation (Swagger): http://localhost:8000/docs

## Schnellstart (Docker Compose)

```bash
docker compose up --build
# UI: http://localhost:8080  (PostgreSQL, Backend und Frontend inklusive)

# Demo-Daten in den laufenden Stack (11 Zonen, Matrix, ~100 Regeln):
docker compose exec backend python seed_demo.py --wipe

# Alternativ: Excel-Import in den laufenden Stack
docker compose exec backend python import_excel.py /data/AP0400Sicherheitsregeln.xlsx
docker compose exec backend python import_zones.py /data/AP0400_Zonenmatrix.xlsx
```

### Demo-Datensatz (`backend/seed_demo.py`)

Deterministisch (fester Seed), komplett fiktiv (Netze aus `10.10.0.0/16`, Hosts `*.demo.local`):
11 Zonen (INET, DMZ-WEB, VPN, PROD-APP, PROD-DB, TEST, DEV, CICD, SHARED, MGMT, MON) mit
vollständiger Allow/Block-Matrix, ~100 Regeln über alle Workflow-Status (freigegeben,
im Review mit Kommentaren, Entwurf, abgelehnt, deaktiviert), Firewall-Regeln zwischen
Zonen (Juniper/Check Point), ACI-Regeln intra-zonal, plus zwei bewusst überlappende
Regeln (SR00101/SR00102) zum Testen der Konflikt-Warnungen.

## Sicherheitszonen

Die Seite „Sicherheitszonen" bündelt drei Sichten: **Zonen-Übersicht** mit
Firewall-Erreichbarkeit (`GET /api/zones/overview`: je Zone die Firewall-Cluster aus
ihren aktiven Regeln; Zonen ohne Firewall-Anbindung werden rot markiert), eine
**bipartite Grafik** (Firewall-Cluster oben, Zonen darunter, Linien = erreichbar über)
und die **Kommunikationsmatrix** (unten).

Die Grafik ist eine **Nord-Süd-Sicht nach dem BSI P-A-P-Modell** (Paketfilter –
Application-Level-Gateway – Paketfilter): oben das Band „Extern (Nord)" mit dem Internet,
in der Mitte die **P-A-P-Ebene** mit den Firewall-Clustern (nach Nord-Süd-Ebene sortiert)
und den DMZ-/Transferzonen, unten „Intern (Süd)" mit den Zonen unterhalb der
P-A-P-Struktur. Jede Zone trägt eine **P-A-P-Einstufung** (`extern` | `pap` | `intern`,
Feld `pap_level`, änderbar über die Übersichtstabelle bzw.
`PUT /api/zones/{name}/pap-level`).

**BSI-Prinzip** (hart durchgesetzt): Der Übergang zwischen Sicherheitszonen ist immer
eine Firewall — Cisco ACI ist als Sicherheitskomponente für den Zonenübergang nicht
ausreichend (keine Firewall nach BSI-Definition). Eine zonenübergreifende Regel, deren
Komponenten ausschließlich vom Typ ACI sind, wird mit HTTP 422 abgelehnt; ACI Contracts
bleiben das Mittel innerhalb einer Zone. Im Demo-Bestand ist zudem ein externer
**Provider-Firewall-Cluster** modelliert (BGP-Peering an FW-Cluster-BER), über den die
Zone INET erreichbar ist.

## Zonen & Zonen-Kommunikationsmatrix

Sicherheitszonen sind eigene Entitäten (`/api/zones`) und im Regelformular als Dropdown
auswählbar. Die **Zonen-Kommunikationsmatrix** (Menüpunkt „Zonen-Matrix", importiert aus
„AP0400_AOKMeinLeben_Kommunikationsmatrix") regelt je Richtungspaar, ob Sicherheitsregeln
überhaupt zulässig sind:

- **Allow** – Regeln erlaubt; die Durchsetzung zwischen Zonen erfolgt immer per Firewall,
  daher wird kein Durchsetzungselement unterschieden (die FW/ACI-Angaben aus dem Excel
  werden beim Import ignoriert, `Temp` bleibt als Kennzeichen erhalten)
- **Block** – das Anlegen/Ändern einer Regel zwischen diesen Zonen wird mit HTTP 422
  abgelehnt; das Regelformular zeigt die Bewertung live beim Auswählen der Zonen
- **Intra-Zone** (Diagonale „–") – erlaubt; innerhalb einer Zone kommt ACI zum Einsatz.
  Nennt eine zonenübergreifende Regel ACI als Plattform, gibt es einen Hinweis.
- **Nicht gepflegte** Zonen/Beziehungen (Altdaten) – erlaubt, aber mit Hinweis in der
  Konfliktanzeige

Architekten/Admins pflegen die Matrix per Klick auf eine Zelle (wechselt Allow ↔ Block),
legen neue Zonen an und löschen Zonen (nur wenn keine
Regel sie verwendet; Matrix-Einträge werden mitgelöscht); API: `GET/POST /api/zones`,
`DELETE /api/zones/{name}`, `GET /api/zones/matrix`, `PUT /api/zones/matrix/{von}/{nach}`,
`GET /api/zones/check?source=&destination=&platforms=`.

## Sicherheitskomponenten

Menüpunkt „Komponenten" (`/api/components`): Verwaltungstabelle der Firewall-Cluster und
ACI-Fabrics, auf denen Regeln umgesetzt werden — mit Name, Typ (Check Point / Juniper SRX /
Cisco ACI), Standort/Zone, Management-Adresse, Beschreibung und aktiv/inaktiv-Status.
Anlegen/Bearbeiten/Löschen für Architekten, Betrieb und Admins; Namen sind eindeutig.
Der Demo-Seed legt zwei Beispiel-Cluster an: **FW-Cluster-FFM** (Check Point, Zone FFM)
und **FW-Cluster-BER** (Juniper SRX, Zone BER).

### Kommunikationsbeziehungen (Topologie)

Auf der Komponenten-Seite werden die direkten Kommunikationsbeziehungen zwischen den
Komponenten dokumentiert (`GET/POST /api/components/links`, ungerichtet, mit
Beschreibung – z.B. „ACI-Fabric-FFM ↔ FW-Cluster-FFM: PBR Service Graph" und
„FW-Cluster-FFM ↔ FW-Cluster-BER: Standort-Transit"). Eine **SVG-Topologie-Grafik**
zeigt die Komponenten als typ-farbige Knoten mit ihren Verbindungen (Tooltip mit
Details); darunter Tabelle und Formular zur Pflege. Duplikate und Selbstbezüge werden
abgelehnt.

### ACI Anycast Gateways (mit PBR)

Auf derselben Seite werden **Cisco ACI Anycast Gateway**-Konfigurationen dokumentiert
(`/api/aci-gateways`): Tenant, VRF, Bridge Domain, Anycast-Gateway-IP (validiert, z.B.
`10.10.30.1/24`) und zugehörige Sicherheitszone. Optional je Gateway eine
**PBR-Anbindung (Policy-Based Redirect)** an einen Check Point Cluster aus der
Komponenten-Tabelle: Ziel-Firewall, PBR-Node-IP/-MAC (validiert), Service-Graph-Template
und Health Group. Plausibilitätsprüfungen: PBR-Ziel muss vom Typ Check Point sein,
bei aktiviertem PBR sind Ziel-Firewall und Node-IP Pflicht, und eine Komponente, die
als PBR-Ziel referenziert wird, kann nicht gelöscht werden. Der Demo-Seed dokumentiert
drei Gateways: GW-PROD-APP und GW-PROD-DB (PBR über FW-Cluster-FFM, `SG-CHKP-FFM`)
sowie GW-SHARED (ohne PBR).

## Adress-Suche

Menüpunkt „Adress-Suche" (`GET /api/rules/ip-search?q=`, `GET /api/rules/path-search?src=&dst=`):

- **Eine Adresse** (IP, CIDR-Netz oder Hostname-Fragment) eingeben → alle Regeln, in denen
  sie als **Quelle (ausgehend)** bzw. **Ziel (eingehend)** vorkommt – inklusive
  Netz-Überlappung (`10.40.105.13` findet auch `10.40.105.0/24`) für IPv4 und IPv6.
- **Quelle und Ziel** eingeben → alle Regeln, die Verkehr zwischen beiden abdecken.
- Treffer, die nur über ein `any` zustande kommen, werden abgesetzt (ausgegraut,
  „nur über any") und nach den direkten Treffern einsortiert; die getroffenen
  Adresseinträge werden gelb hervorgehoben.

## Beispiel-Workflow

1. **Architekt** legt eine Regel an (ID wird automatisch vergeben, z.B. `SR00855` (5-stellig, bis 99999 Regeln)):
   Quelle `10.0.1.0/24`, Ziel `192.168.1.0/24`, Dienst `TCP/443`, Anlass „Erlaubt HTTPS-Verkehr für Webserver“.
   Die Anwendung prüft dabei: gültige CIDR/Hostnamen, Ports 1–65535, keine doppelten IDs, Gültigkeitszeitraum – und warnt bei **Konflikten** (überlappende Netze/Ports, Duplikate, permit/deny-Shadowing).
2. Regel **zum Review einreichen** → **Betrieb** prüft, kommentiert und gibt frei (oder lehnt ab).
3. Betrieb **exportiert** die Konfiguration mit Syntax-Vorschau:
   - Juniper: `set security policies from-zone trust to-zone untrust policy HTTPS-Webserver match … then permit` (inkl. Address-Book und Applications)
   - Check Point: `mgmt_cli`-Skript oder Management-API-JSON
   - ACI: APIC-JSON (`fvTenant`/`vzFilter`/`vzBrCP`) oder YAML
   - außerdem CSV (Spalten wie die bisherige Kommunikationsmatrix) und JSON
4. Betrieb setzt den **Umsetzungsstatus** je Plattform auf „umgesetzt“.

Beispiel-Exportdateien liegen unter [`examples/`](examples/).

## Projektstruktur

```
backend/
  app/
    main.py            FastAPI-App, CORS, Startup (Tabellen + Demo-User)
    models.py          SQLAlchemy-Modelle (Rule, RuleVersion, Comment, User)
    schemas.py         Pydantic-Schemas (Eingabe-Validierung / Ausgabe getrennt)
    validation.py      Plausibilitätsprüfung (CIDR, Ports, Protokolle)
    conflicts.py       Konflikt-Erkennung (Overlap, Duplikat, Shadowing)
    auth.py            JWT-Auth, PBKDF2-Passworthashes, Rollen-Dependency
    routers/           REST-Endpunkte (auth, rules, export, users)
    exporters/         juniper.py, checkpoint.py, aci.py, generic.py (CSV/JSON)
  import_excel.py      Import der bestehenden Kommunikationsmatrix
  tests/               pytest (Exporter, Validierung, Konflikte)
frontend/
  src/pages/           RuleList (Filter/Suche), RuleForm, RuleDetail (Review,
                       Historie, Kommentare), ExportPage (Vorschau + Highlighting)
deploy/k8s/            Kubernetes-Manifeste
docs/DEPLOYMENT.md     Deployment-Plan (Docker/Kubernetes, Härtung)
examples/              Generierte Beispiel-Exporte
data/                  Original-Excel (für den Import)
```

## Wichtige API-Endpunkte

| Methode & Pfad | Zweck |
|---|---|
| `POST /api/auth/login` | Login (OAuth2-Form), liefert JWT |
| `GET /api/rules?q=&source=&destination=&port=&protocol=&status=&platform=` | Suche/Filter |
| `POST /api/rules` · `PUT /api/rules/{id}` | Anlegen/Ändern (Architekt), versioniert |
| `POST /api/rules/{id}/submit|approve|reject|deactivate` | Review-Workflow |
| `PUT /api/rules/{id}/impl-status` | Umsetzungsstatus je Plattform (Betrieb) |
| `GET /api/rules/{id}/conflicts` | Konflikt-Warnungen |
| `GET /api/export/{fmt}?ids=&only_approved=&download=` | `csv`, `json`, `juniper`, `checkpoint-cli`, `checkpoint-api`, `aci-json`, `aci-yaml` |

## Tests

```bash
cd backend && ../.venv/bin/python -m pytest tests/
```

## Ausblick (vorbereitet, nicht im Prototyp)

- **LDAP/AD**: `auth.py` kapselt die Anmeldung an einer Stelle – dort kann statt der lokalen
  Passwortprüfung ein LDAP-Bind erfolgen (z.B. `ldap3`), Rollen über AD-Gruppen gemappt werden.
- **ServiceNow-Change-Tickets**: Der generische Change-Management-Webhook (siehe unten) liefert
  die Ereignisse; ein ServiceNow-Adapter (Scripted REST API/MID-Server) erzeugt daraus das
  Change-Ticket und schreibt die Ticket-Nummer per `PUT /api/rules/{id}` in `change_id` zurück.

## Benutzerverwaltung, E-Mail & Anmeldesicherheit

- **Admin-Bereich** (`/admin`, Rolle admin): Benutzer anlegen/ändern/deaktivieren, Rollen
  vergeben, Passwort-Resets anstoßen. Neue Benutzer ohne Passwort erhalten einen
  **Aktivierungslink** (72h gültig) – per Mail, falls SMTP konfiguriert; der Link wird dem
  Admin zusätzlich angezeigt.
- **E-Mail-Versand** (Basis für spätere Benachrichtigungen), aus solange SMTP_HOST leer:

  ```bash
  SMTP_HOST=… SMTP_PORT=587 SMTP_USER=… SMTP_PASSWORD=… SMTP_FROM=…
  PERMITRA_BASE_URL=https://permitra.example.org   # Basis für Links in Mails
  ```

- **Passwort vergessen** auf der Login-Seite (Reset-Link, 2h gültig; Antwort verrät nie,
  ob ein Konto existiert). Konto-Seite (`/account`): Passwort ändern.
- **2FA (TOTP)**: Self-Service auf der Konto-Seite (Secret für Authenticator-Apps,
  Aktivierung per Code); der Login fragt den Code danach als zweiten Faktor ab.
- **Passkeys (WebAuthn)**: Registrierung auf der Konto-Seite, Anmeldung ohne Passwort auf
  der Login-Seite. Erfordert HTTPS (bzw. localhost); Konfiguration über
  `PERMITRA_RP_ID`/`PERMITRA_ORIGIN` (Default: aus `PERMITRA_BASE_URL` abgeleitet).

## Change-Management-Integration (optional)

Permitra sendet bei Freigabe-Ereignissen einen JSON-Webhook (fire-and-forget, blockiert nie):

```bash
CHANGE_WEBHOOK_URL=https://instanz.service-now.com/api/x_permitra/change   # leer = aus
CHANGE_WEBHOOK_TOKEN=…   # optional, wird als "Authorization: Bearer" gesendet
```

Ereignisse: `rule.submitted`, `rule.approved`, `rule.rejected`,
`zone_change.approved`, `zone_change.rejected`. Payload:
`{"event": …, "source": "permitra", "timestamp": …, "data": {…}}` –
bei Regeln u.a. `rule_id`, Zonen, Adressen, Dienste, Komponenten, `change_id`,
bei Sammelanträgen `batch_id` und die Einzeländerungen. Implementierung:
`backend/app/change_management.py`.
- **CMDB/Ticket-Integration**: Die komplette Funktionalität ist als REST-API verfügbar (`/docs`).

## Lizenz

Permitra ist Open Source und steht unter der [Apache License 2.0](LICENSE).

Copyright 2026 Lars Vonhof-Hunold
