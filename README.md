# 🛡️ Permitra

Central web application for managing network security rules for **Juniper SRX**, **Check Point** and **Cisco ACI contracts** — replacing the Excel-based communication matrix. Permitra is the source of truth for the *intended* state: rules are requested, reviewed, approved and documented here; devices are still configured through the vendors' management tools, and a drift comparison shows where documentation and reality diverge.

Project website: https://permitra.de · Live demo: https://demo.permitra.de

## Architecture

```
┌──────────────┐      REST/JSON      ┌───────────────┐      SQL      ┌────────────┐
│  React SPA   │ ──────────────────► │  FastAPI      │ ────────────► │ PostgreSQL │
│  (Vite)      │  JWT (role-based)   │  backend      │  SQLAlchemy   │ (SQLite    │
│  tables,     │                     │  validation,  │               │  for dev)  │
│  review UI,  │                     │  workflow,    │               └────────────┘
│  export      │                     │  conflict     │
│  preview     │                     │  detection    │
└──────────────┘                     └──────┬────────┘
                                            │ exporters
                        ┌───────────────────┼──────────────────────┐
                        ▼                   ▼                      ▼
                 Juniper SRX          Check Point              Cisco ACI
                 (set commands)       (mgmt_cli script,        (APIC JSON,
                                       Management API JSON)     YAML)
                        plus: Capirca/Aerleon (Cisco IOS/ASA, Palo Alto,
                        zone-based SRX, iptables), host firewalls, CSV/JSON
```

**Roles:**

| Role | Permissions |
|---|---|
| `architect` | Create/edit rules, submit for review, comment |
| `operations` | Maintain implementation status per component, export, drift comparison |
| `change_approver` | Approvals: rule reviews (one approval) and zone/network/matrix requests (two approvals by different approvers); focused approvals start page |
| `admin` | Permitra administration (user management, settings); focused admin start page |

**Rule workflow:** `draft → in review → approved/rejected → (deactivated)`.
Content changes to an approved rule reset it to `draft`. When a previously implemented rule is re-approved, its implementation status switches to *to change* so operations can re-apply and mark it *implemented* again. The dashboard shows a tile with the number of rules awaiting implementation.

**Data model:** rule IDs in the `SR#####` format (5 digits, up to 99999 rules), assigned server-side; application, application ID (**APP-ID**, for per-app reports), source/destination zones (derived automatically), multiple services (protocol/port) per rule, justification, requestor, owner, change ID, business context, validity period, version history with snapshots, comments.

- **Addresses are structured**: source/destination entries are **always an IP or network (CIDR, IPv4/IPv6)** plus an optional **alias** per entry (hostname for a single IP, network name for a subnet). Special value `any`. Exporters use the alias as the object name (Juniper address book, Check Point hosts/networks); the address search matches on IP overlap **and** alias. Pure FQDN rules are deliberately not supported.
- **Rules map to concrete components** (not abstract platforms): each rule references the security components (firewall clusters or ACI fabrics) on which a firewall rule or ACI contract must be created. The platform is derived from the component type; the implementation status is maintained per component; exports can be restricted to one component.
- **Components are resolved automatically from source/destination** via the persistent address mapping (`address_component_map`): exact match or most specific containing network; intra-zone rules resolve to ACI components, cross-zone rules to firewall clusters. When a rule contains a **new address**, the form asks **once** on which components rules for that address should be created — the mapping is stored and applied automatically from then on.
- **Zone identity**: each zone has a leading **ID/code** (e.g. `Z040`) assigned at creation plus a name; rules reference the zone by its ID (stable across renames) and it is shown as `Z040-PROD-APP`. Zones also carry a protection level per C/I/A goal (set at creation).
- **Network registry**: every network belongs to exactly one security zone (`zone_networks`). Source/destination zones of a rule are derived automatically from its addresses; unassigned networks are rejected with a clear hint pointing to the Networks page. Networks themselves are managed in dedicated tools (e.g. NetBox — import hook prepared via the `source` field); Permitra only maintains the network→zone mapping. **Changes to that mapping go through the approval workflow** (two change approvers), and a move **re-assesses every affected rule**: source/destination zones are derived anew, and rules that become inadmissible — the new zone pair is Block, a side now spans two zones, or the now cross-zone traffic has no firewall — go into review **proposed for removal**. Approving such a rule means approving its removal: it is deactivated and each component is set to *to be removed* so operations sees the rollback as open work. Reworking the rule until it passes the checks clears the proposal. The pending request shows this impact **before** the approvers decide.

## Dashboard, recertification, drift & object catalog

- **Dashboard** (start page): KPI tiles (rules, open reviews, to implement, expired / expiring within 30 days), rules by status and per component, recent changes.
- **Validity monitoring**: a daily job deactivates approved rules after `valid_until` expires (with version and comment entries). The recertification page lists expired and soon-expiring rules; *extend* sets a new expiry date without resetting the approval status. Date fields are validated as real ISO dates on the way in — a value like `2020-02-30` is rejected with a clear message instead of passing the string comparison and later crashing the expiry check. Legacy or imported rules carrying an unreadable date are **skipped rather than auto-deactivated** (acting on unusable data would be worse) and listed separately on the recertification page so they can be corrected.
- **Drift comparison** on the components page: store the device's actual configuration (`PUT /api/components/{id}/actual-config`; a direct device adapter can hook in) → `GET /api/components/{id}/drift` reports **missing** (approved, not implemented), **stale** (implemented, no longer approved) and **unknown** rule IDs (shadow rules). Matching is based on the SR IDs carried by every export.
- **Object catalog**: reusable address objects (alias → IP/network) and service objects (e.g. HTTPS = TCP/443), selectable in the rule form. Changing the IP of an address object **updates all rules using that alias** (versioned).
- **Migrations & backup**: schema changes run through **Alembic** (auto-upgrade at startup; pre-Alembic databases are stamped to the baseline). Daily backup: `scripts/backup.sh` (pg_dump, 14 generations).
- **Pagination**: `GET /api/rules` returns `{total, items}` with `limit`/`offset`.

## ACI contracts (EPG-based)

The ACI export models contracts idiomatically instead of "one contract per rule":

- **EPG catalog** (maintained on the objects page): EPGs with tenant, application profile and bridge domain, plus an **address→EPG mapping** (exact match or most specific containing network; `any` → **vzAny**). Multiple addresses can be assigned to the same EPG (comma-separated bulk entry in the form).
- **Aggregation**: source → consumer, target → provider; all rules of a (consumer EPG, provider EPG) pair become **one contract** with one subject per filter — avoiding contract/TCAM explosion in the fabric.
- **Filter reuse**: services are resolved against the service object catalog (`flt-https` instead of one duplicate per rule) and deduplicated across contracts.
- **Service graph / PBR**: if the provider EPG's bridge domain carries an anycast gateway with PBR, the subject references its service graph template.
- **EPG bindings**: the APIC JSON export contains `fvAp`/`fvAEPg` with provider/consumer references; SR IDs are kept in subject descriptions for traceability/drift. Rules without an EPG mapping fall back to single contracts and are listed in the warnings.

Exports always apply the approval filter, **including when explicit `ids=` are given** — a rule ID narrows *which* rules are meant, not whether their status still counts. A deactivated or draft rule is therefore not exported by accident; a deliberate preview needs `only_approved=false`, and that export is marked as such in the audit trail. Every export path (device formats, Capirca/Aerleon, host firewall) writes an audit entry with actor, format and rule count.

## Host firewall export

For a **target IP**, Permitra generates the server's local firewall rules (`GET /api/export/host/{debian|redhat|sles}?ip=`), based on all approved permit rules whose destination covers the IP. Formats: **Debian** = nftables ruleset (default drop, loopback, established/related, ICMP), **RedHat** = firewalld script with rich rules, **SLES** = iptables script. Every line carries the SR ID as a comment; IPv6 sources are handled correctly.

## Capirca/Aerleon integration

The built-in [Aerleon](https://github.com/aerleon/aerleon) integration (the maintained Apache-2.0 fork of Google's Capirca) translates Permitra rules into Capirca policies: aliases/IPs become network objects, services become service objects (TCP/UDP is split per protocol), rules become terms with their SR ID as the term name; zone-based targets (SRX, Palo Alto) get one filter per zone pair. Endpoints: `GET /api/export/aerleon/{target}` with targets `cisco`, `ciscoasa`, `juniper`, `srx`, `paloalto`, `iptables` — and `policy`, which emits definitions + policy as YAML for existing Capirca/Aerleon pipelines. Check Point and ACI intentionally keep their specialized exporters (Capirca does not cover them).

## Path analysis (visual view)

The analysis page shows, for a source/destination pair, **whether communication is possible** and **for which protocols/ports** (intersection of approved permit rules across all components on the path), as a flow diagram (source → components → destination). Hops are ordered by north-south tier; if an address lies in the network of an ACI anycast gateway with **PBR**, the Check Point cluster appears as an additional hop ("via PBR"). Components without a matching approved rule are marked red and named in the verdict. A single address (IP, CIDR or hostname fragment) can also be searched on its own → all inbound/outbound rules, including network overlap for IPv4 and IPv6; matches that only occur via `any` are set apart.

## Security zones

The security zones page combines: the **zone plan** (see below), a **zone overview** (per zone: BSI documentation, networks, P-A-P classification, rule count, attached firewall clusters, intra-zonal ACI), a **north-south diagram** following the BSI P-A-P model (packet filter – application level gateway – packet filter: external band on top, P-A-P layer with the firewall clusters and DMZ/transfer zones in the middle, internal zones below), and the **communication matrix**.

- **Zone plan** (the BSI term is *bereinigter Netzplan*, a consolidated network plan): an audit-ready diagram generated entirely from the stored data — zones colored by protection level with owner shown at the node, ACI chip for intra-zone segmentation, firewall clusters as zone transitions, audit header (title, BSI reference NET.1.1/NET.3.2, timestamp) and a legend. **Exports**: PNG (client-side from the SVG), PDF (print-optimized A4 landscape) and **Mermaid.js** (`GET /api/zones/plan/mermaid`) for wikis and documentation systems that render Mermaid natively (e.g. GitLab).
- **BSI documentation per zone**: owner (person/team) and protection level per protection goal (**confidentiality, integrity, availability** — each normal/high/very high); the overall protection level follows the maximum principle. Maintained via an edit dialog in the overview, shown as a badge column and in the diagram tooltips.
- **BSI principle (hard-enforced)**: a zone transition is always a firewall — Cisco ACI alone is not sufficient (not a firewall by BSI definition). A cross-zone rule whose components are all of type ACI is rejected with HTTP 422; ACI contracts remain the tool *within* a zone.
- **Zone attachment**: which firewall clusters a zone is attached to is maintained explicitly (checkbox multi-select; ACI cannot be selected).

## Zone communication matrix

The matrix governs, per directed zone pair, whether security rules are allowed at all:

- **Allow** — rules permitted (enforcement between zones is always a firewall); `Temp` flag supported.
- **Block** — creating/changing a rule between these zones is rejected with HTTP 422; the rule form shows the verdict live.
- **Intra-zone** (diagonal) — allowed; ACI is the tool of choice here.
- **Unmaintained relationships** — behaviour is configurable (see settings): legacy `permit` with a hint, or **default-deny** following the least-privilege principle.

**Matrix changes are batch requests**: architects collect changes in edit mode (including new zones) and submit them as one request; **two different change approvers** must approve (four-eyes principle, requesters cannot approve their own requests). Every request is versioned with full history.

## Security components

Management of the firewall clusters and ACI fabrics rules are implemented on — name, type (Check Point / Juniper SRX / Cisco ACI), location, management address, north-south tier, active flag. The components page also documents **communication links** between components (with a link type shown on the line, e.g. "OSPF routing", "BGP peering", "PBR service graph") in an SVG topology diagram, and **ACI anycast gateways** (tenant, VRF, bridge domain, gateway IP) with optional **policy-based redirect** to a Check Point cluster (service graph template, node IP/MAC, health group — with plausibility checks).

## Approvals page (change approvers)

Change approvers land on a focused approvals page after login: open rule reviews and open zone/network batch requests with direct approve/reject actions, the 1/2 approval state, and a lock against approving twice yourself. Their navigation is slimmed down to what decisions require.

## Settings (admin area)

- **Risk hints** (Issue #10): rules are checked for risky patterns (source and destination both `any`, very broad networks ≤/8, risky services like RDP/Telnet/SMB/DB-direct — weighted higher from exposed source zones, `any` service across zones). Port **ranges and lists are expanded**, so `20-25` is flagged for the FTP and Telnet it contains and the finding names the concrete port (`Port 23 in 20-25`) instead of leaving you to search the range. Severity is raised by the target zone's protection level (a simple risk matrix). Non-blocking; shown on the rule detail page and filterable in the rule list (`risk=flagged`). API: `GET /api/rules/{id}/risk`.
- **Audit log for SIEM** (Issues #11, #24, #25, #26): unified, machine-readable change log at `GET /api/audit-log` (admin only; `since`/`type`/`limit`). It merges rule versions and zone/matrix/network requests with an **append-only event store** covering sign-in (success, failure, lockout, password change, 2FA), administration (users, settings, API tokens, NetBox) and data access (exports) — each with actor and **source IP** (taken from `X-Forwarded-For` only when the request comes from a proxy listed in `PERMITRA_TRUSTED_PROXIES`; otherwise the immediate peer, which cannot be forged). Rules are **soft-deleted** so deletion never destroys the trail. A viewer is on the admin page.
  - **Integrity (Issue #26)**: every stored event carries a SHA-256 `hash` over its content *and* its predecessor's hash (hash chain, genesis = 64 zeros). Editing an event, reordering, or removing one breaks the chain. Because a chain is also intact after its *newest* entries are cut off, **checkpoints** (`audit_checkpoints`) periodically anchor the chain end (last id, count, head hash) — hourly by default (`AUDIT_CHECKPOINT_INTERVAL`), or on demand via `POST /api/audit-log/checkpoint`. `GET /api/audit-log/verify` (admin) re-computes the whole chain, compares it against the newest checkpoint, and reports `ok`, entries checked, and the first `broken_at_id` with a reason. The admin page has **"Verify integrity"** and **"Anchor now"** buttons. Delivery columns are excluded from the hash, so operational updates never invalidate it.
  - **What this does and does not protect against** (stated plainly, because the wording matters for an audit): the hash is **keyless** — anyone who can *write* to the database can alter an event and recompute the chain from there with the same public function, and by also deleting the checkpoints make it undetectable *within the database*. The chain alone therefore protects against accidental corruption and against tampering without recomputation — not against an attacker with database write access. The load-bearing protection is **externalisation**: events *and* checkpoints are reliably delivered to a SIEM, where they are out of reach of database access, and a comparison exposes any later forgery. Without a configured SIEM sink the protection stays limited to the above — a deliberate operational choice, not a property of the application.
  - **Reliable delivery (Issue #26)**: when a SIEM sink is configured, events are persisted as `pending` and delivered by a background worker in strict order, **at-least-once** — the state lives in the database, so a crash or restart loses nothing, and a sink outage simply queues events until it returns. Delivery stops at the first failure to preserve ordering, and each delivered event carries its `hash` so the SIEM can re-verify the chain independently. All background jobs (delivery, anchoring, expiry) run their blocking work in a worker thread, so an unreachable sink never stalls the API — verified: request latency stays at ~3 ms while delivery runs into its timeouts. While a sink stays unreachable the retry interval backs off from 10 s up to 5 minutes instead of hammering it every cycle. Status: `GET /api/audit-log/siem-status`. Sinks: webhook (`AUDIT_WEBHOOK_URL`, 2xx = acknowledged) and syslog (`AUDIT_SYSLOG_HOST`/`AUDIT_SYSLOG_PORT`, `AUDIT_SYSLOG_PROTO=udp|tcp`; TCP uses RFC 6587 octet framing and is acknowledged, UDP is best-effort).
- **Least privilege / default-deny** (`zone_matrix_default`): behaviour for zone relationships without a matrix entry. `permit` = allowed with a hint (legacy behaviour, default), `deny` = rules are rejected (422) until the relationship is explicitly set to Allow via a matrix request with two approvals — BSI recommendation, active in the demo dataset. API: `GET/PUT /api/settings`.
- **Mandatory fields for rules** (`require_justification`, `require_requestor`, `require_valid_until`): justification, requestor and expiry date are **mandatory by default** (BSI documentation duties) — the admin area offers a deactivation option per field. Enforced server-side (422 with field list), marked with `*` in the rule form.

## User management, email & sign-in security

- **Admin area** (`/admin`, role admin): create/update/deactivate users, assign roles, trigger password resets. New users without a password receive an **activation link** (valid 72h) — by email if SMTP is configured; the link is also shown to the admin.
- **Email notifications** (Issue #5): on rule submission (→ change approvers), approval/rejection (→ requester), implementation/decommission required (→ operations) and recertification (→ operations, from the daily expiry job). Recipients are derived from roles; each user can opt out on the account page (`notify_email`). Requires SMTP and a stored email address; silently does nothing otherwise.
- **Email delivery**, disabled while `SMTP_HOST` is empty:

  ```bash
  SMTP_HOST=… SMTP_PORT=587 SMTP_USER=… SMTP_PASSWORD=… SMTP_FROM=…
  PERMITRA_BASE_URL=https://permitra.example.org   # base for links in emails
  ```

- **Forgot password** on the login page (reset link, valid 2h; responses never reveal whether an account exists). Account page: change password.
- **2FA (TOTP)**: self-service on the account page (secret for authenticator apps, activation by code); login then asks for the code as a second factor. Implemented per RFC 6238 without extra dependencies.
- **Passkeys (WebAuthn)**: registration on the account page, passwordless sign-in on the login page. Requires HTTPS (or localhost); configured via `PERMITRA_RP_ID`/`PERMITRA_ORIGIN` (default derived from `PERMITRA_BASE_URL`).

## Reports & printing

- **Per-APP-ID report**: filter the rule list by APP-ID and export a CSV report of all its rules (`GET /api/export/csv?app_id=…`; the APP-ID column is included in CSV/JSON). The `app_id` filter also works on `GET /api/rules`.
- **Print / PDF of the analysis**: the analysis page offers a print button that renders a clean, print-optimized view (source→destination, timestamp, matching rules) for saving as PDF.

## NetBox import (networks)

Permitra manages only the **network→zone mapping**; the networks themselves live in a
dedicated IPAM. Prefixes can be imported from **NetBox** (status *active* and *planned*):
configure the NetBox URL and API token in the admin area (token stored encrypted), run the
import (`POST /api/netbox/import`), then adopt prefixes into the zone registry on the Networks
page — assigning each a zone, which goes through the normal approval workflow (source `netbox`).

## Automation: read-only API tokens (Ansible/Terraform)

Permitra is API-first, so external tools can use it as the source of truth. Create a
**read-only API token** in the admin area (shown once). Tokens allow only `GET` requests
(writes return 403) and never expose admin endpoints. Use `updated_since` for efficient polling.

```yaml
# Ansible
- name: Read approved rules from Permitra
  ansible.builtin.uri:
    url: "https://permitra.example.org/api/rules?status=approved&component=FW-Cluster-BER"
    headers:
      Authorization: "Bearer {{ permitra_token }}"
  register: permitra
# permitra.json.items is the source of truth for templates/modules
```

```hcl
# Terraform
data "http" "permitra_rules" {
  url             = "https://permitra.example.org/api/rules?status=approved"
  request_headers = { Authorization = "Bearer ${var.permitra_token}" }
}
locals { rules = jsondecode(data.http.permitra_rules.response_body).items }
```

Endpoints: `GET/POST/DELETE /api/api-tokens` (admin). The token itself is authenticated via
`Authorization: Bearer pat_…`.

## Change management integration (optional)

Permitra sends a JSON webhook on approval events (fire-and-forget, never blocks):

```bash
CHANGE_WEBHOOK_URL=https://instance.service-now.com/api/x_permitra/change   # empty = off
CHANGE_WEBHOOK_TOKEN=…   # optional, sent as "Authorization: Bearer"
```

Events: `rule.submitted`, `rule.approved`, `rule.rejected`, `zone_change.approved`, `zone_change.rejected`. Payload: `{"event": …, "source": "permitra", "timestamp": …, "data": {…}}` — for rules this includes rule ID, zones, addresses, services, components and `change_id`; for batch requests the batch ID and individual changes. A ServiceNow adapter can create the change ticket and write the ticket number back into `change_id` via `PUT /api/rules/{id}`. Implementation: `backend/app/change_management.py`. The complete functionality is also available as a REST API (`/docs`) for CMDB/ticket integrations.

## Quick start (local, without Docker)

```bash
# 1. Backend
python3 -m venv .venv
.venv/bin/pip install -r backend/requirements.txt
cd backend
../.venv/bin/python -m uvicorn app.main:app --port 8000   # API on :8000, creates SQLite + demo users

# 2. Generate demo data (11 zones, matrix, ~100 rules) – recommended for testing
../.venv/bin/python seed_demo.py --wipe

# 3. Frontend
cd ../frontend
npm install
npm run dev                                               # UI on http://localhost:5173
```

**Demo logins:** `architekt`, `betrieb`, `approver`, `approver2`, `admin` — password is the username + `123`.
API documentation (Swagger): http://localhost:8000/docs

## Quick start (Docker Compose)

```bash
docker compose up --build
# UI: http://localhost:8080  (PostgreSQL, backend and frontend included)

# Seed demo data into the running stack:
docker compose exec backend python seed_demo.py --wipe
```

### Demo dataset (`backend/seed_demo.py`)

Deterministic (fixed seed), entirely fictional (networks from `10.10.0.0/16`, hosts `*.demo.local`): 11 zones with a complete allow/block matrix and BSI documentation (owner, C/I/A), ~100 rules across all workflow states, firewall rules between zones (Juniper/Check Point), intra-zonal ACI rules, two deliberately overlapping rules (SR00101/SR00102) for testing conflict warnings, and one rule (SR00103) spanning all three components.

## Example workflow

1. An **architect** creates a rule (ID assigned automatically, e.g. `SR00855`): source `10.0.1.0/24`, target `192.168.1.0/24`, service `TCP/443`, justification "HTTPS for web servers". Permitra validates CIDR/ports/IDs, derives zones and components, checks the zone matrix and warns about **conflicts** (overlapping networks/ports, duplicates, permit/deny shadowing).
2. The rule is **submitted for review** → a **change approver** reviews, comments and approves (or rejects).
3. **Operations** exports the configuration with a syntax preview (Juniper set commands, Check Point mgmt_cli/API, ACI APIC JSON/YAML, Capirca targets, CSV/JSON) and applies it in the vendor tools.
4. Operations sets the **implementation status** per component to *implemented*. Drift comparison verifies the result.

Example export files are provided under [`examples/`](examples/).

## Project structure

```
backend/
  app/
    main.py            FastAPI app, CORS, startup (migrations + demo users)
    models.py          SQLAlchemy models (rules, zones, components, users, …)
    schemas.py         Pydantic schemas (input validation / output separated)
    validation.py      plausibility checks (CIDR, ports, protocols)
    conflicts.py       conflict detection (overlap, duplicate, shadowing)
    zone_check.py      zone derivation and matrix checks
    component_resolution.py  automatic component resolution
    auth.py            JWT auth, PBKDF2 password hashes, role dependency
    totp.py            TOTP two-factor (RFC 6238, stdlib only)
    mailer.py          optional SMTP delivery (activation/reset mails)
    change_management.py  optional change-management webhook
    settings.py        Permitra settings (admin area)
    routers/           REST endpoints
    exporters/         juniper, checkpoint, aci, aerleon_export, hostfw, generic
  alembic/             database migrations (auto-run at startup)
  seed_demo.py         deterministic demo dataset
  tests/               pytest
frontend/
  src/pages/           React pages (rules, zones, networks, components, admin, …)
  src/i18n.jsx         bilingual UI (German/English, toggle in the top bar)
deploy/k8s/            Kubernetes manifests
docs/DEPLOYMENT.md     deployment guide (Docker/Kubernetes, hardening)
website/               static project website (permitra.de)
examples/              generated example exports
```

## Key API endpoints

| Method & path | Purpose |
|---|---|
| `POST /api/auth/login` | Login (OAuth2 form, optional `otp` field), returns JWT |
| `GET /api/rules?q=&source=&destination=&port=&protocol=&status=&component=&impl=&vrf=` | Search/filter with pagination |
| `POST /api/rules` · `PUT /api/rules/{id}` | Create/update (architect), versioned |
| `POST /api/rules/{id}/submit\|approve\|reject\|deactivate` | Review workflow |
| `PUT /api/rules/{id}/impl-status` | Implementation status per component (operations) |
| `GET /api/rules/{id}/conflicts` | Conflict warnings |
| `GET /api/zones/…` | Zones, overview, matrix, batch requests, network mapping |
| `GET /api/export/{fmt}` | `csv`, `json`, `juniper`, `checkpoint-cli`, `checkpoint-api`, `aci-json`, `aci-yaml` |
| `GET /api/export/aerleon/{target}` | Capirca/Aerleon targets incl. `policy` YAML |
| `GET /api/export/host/{os}?ip=` | Host firewall config for a target server |

## Tests

```bash
cd backend && ../.venv/bin/python -m pytest tests/
```

## Roadmap

Tracked as GitLab issues: email notifications, ServiceNow adapter, configurable mandatory fields, rule rollback, risk hints (any-to-any, risky services), SIEM audit log export, AD/LDAP sign-in, read-only API tokens for automation (Ansible/Terraform). Multi-environment support (overlapping IP ranges per environment, e.g. IT/OT) is fully built and currently dormant behind a single default environment.

## How this project was built

In the spirit of transparency: **Permitra was built with [Claude](https://claude.com/claude-code), Anthropic's AI coding assistant** — every commit carries the co-author trailer.

The author is a solution architect who has delivered many cloud infrastructure projects, each of them accompanied by Excel sheets full of security rules. With limited programming skills of their own, working with Claude made it possible to turn that hands-on domain experience into a working solution: the architecture principles, workflows and requirements behind Permitra come from real project practice; the implementation grew out of an iterative dialogue with the AI.

That is also part of why Permitra is open source: so that experienced developers can review the code critically, point out what should be done better — and use the ideas as inspiration for their own work.

## License

Permitra is open source under the [Apache License 2.0](LICENSE).

Copyright 2026 Lars Vonhof-Hunold
