<img src="frontend/public/permitra-logo.svg" alt="Permitra" width="200">

# Permitra

Central web application for managing network security rules for **Juniper SRX**, **Check Point** and **Cisco ACI contracts** — replacing the Excel-based communication matrix. Permitra is the source of truth for the *intended* state: rules are requested, reviewed, approved and documented here; devices are still configured through the vendors' management tools, and a drift comparison shows where documentation and reality diverge.

Project website: https://permitra.de · Live demo: https://demo.permitra.de

> **0.7.4-alpha** — the first public release. The feature set is complete enough
> to work with end to end and the audit's critical and high findings are closed,
> but nothing has run in production yet and the API may still change without a
> deprecation path. Good for a lab, not yet for your production communication
> matrix. [What is missing](CHANGELOG.md#074-alpha--2026-08-23) ·
> [Security policy](SECURITY.md)

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
| `architect` | Create/edit rules, submit for review, comment, retire an application (proposing its rules for removal) |
| `operations` | Maintain implementation status per component, export, drift comparison, evidence report |
| `change_approver` | Approvals: rule reviews (one approval) and zone/network/matrix requests (two approvals by different approvers); runs the recertification cycle (starts and closes campaigns); focused approvals start page |
| `admin` | Permitra administration only — installation, user management, settings. Deliberately not a superuser: no rule views in the interface, no approvals, no recertification, no reports. It keeps exactly three rule powers, all of them administrative: deleting a rule, and proposing or ending a requestor handover once that account is gone |

An account can hold **several roles**, and its permission is their union — small
teams do not have four people for four roles. This does not soften separation of
duties, because the four-eyes checks key on the acting *account*, not on a role:

- an account holding both `architect` and `change_approver` still cannot approve
  a rule it requested, created or submitted (it may approve everyone else's), and
- the two approvals on a zone, network or matrix change must come from two
  different accounts, so one multi-role account cannot supply both.

Two hats on one person is still one pair of eyes.

## What it does

Each of these has its own page — this list is the map, not the manual.

| | |
|---|---|
| **[The model](docs/CONCEPTS.md)** | Rule workflow and statuses, why `approved` and `active` are different things, why a rule is never deleted, security zones and the P-A-P model, the communication matrix, components, path analysis, drift and coverage |
| **[Exports](docs/EXPORTS.md)** | Juniper SRX, Check Point, EPG-based ACI contracts, host firewalls, Capirca/Aerleon, CSV/JSON — and which rules are allowed into an export at all |
| **[API and automation](docs/API.md)** | Endpoints, read-only tokens for Ansible/Terraform, the change-management webhook |
| **[Audit log](docs/AUDIT.md)** | What is recorded, the hash chain, SIEM delivery — and what that protection is worth |
| **[Administration](docs/ADMINISTRATION.md)** | Settings, risk criteria, accounts, 2FA and passkeys, NetBox import |
| **[Deployment](docs/DEPLOYMENT.md)** | Docker and Kubernetes, hardening, encrypted backups and the restore rehearsal |
| **[Security policy](SECURITY.md)** | What this release protects against, and what it does not |

Two things worth knowing before the rest:

- **Permitra never writes to a device.** It produces the configuration to apply;
  the rollout happens in the vendors' tools. What it does instead is compare:
  did the rules arrive, and — the question it exists for — is every rule on the
  device backed by an approved security rule?
- **`approved` and `active` are not the same thing.** Approval says the rule
  *may* exist; `active` is operations confirming that it *does*. Keeping them
  apart is what makes "approved but never rolled out" visible.

## Quick start (local, without Docker)

```bash
# 1. Backend
python3 -m venv .venv
.venv/bin/pip install -r backend/requirements.txt
cd backend
../.venv/bin/python -m uvicorn app.main:app --port 8000   # API on :8000, creates SQLite + demo users

# 2. Generate demo data (13 zones, matrix, ~100 rules) – recommended for testing
../.venv/bin/python seed_demo.py --wipe

# 3. Frontend
cd ../frontend
npm install
npm run dev                                               # UI on http://localhost:5173
```

**Demo logins:** two accounts per role — `architekt`/`architekt2`, `betrieb`/`betrieb2`,
`approver`/`approver2`, `admin`/`admin2`, plus `doppelrolle` (architect *and* change
approver, to walk the multi-role case). Password is the username + `123`. Two accounts
per role is what makes the four-eyes paths walkable: one requests, the other approves.
API documentation (Swagger): http://localhost:8000/docs

## Quick start (Docker Compose)

```bash
docker compose up --build
# UI: http://localhost:8080  (PostgreSQL, backend and frontend included)

# Seed demo data into the running stack:
docker compose exec backend python seed_demo.py --wipe
```

### Demo dataset (`backend/seed_demo.py`)

Deterministic (fixed seed), entirely fictional (networks from `10.10.0.0/16`, hosts `*.demo.local`): 13 zones with a complete allow/block matrix and BSI documentation (owner, C/I/A), ~100 rules across all workflow states, firewall rules between zones (Juniper/Check Point), intra-zonal ACI rules, two deliberately overlapping rules (SR00101/SR00102) for testing conflict warnings, and one rule (SR00103) spanning all three components, plus two ping baselines (SR00104 in service, SR00105 in review) showing the one rule that is allowed to be any-to-any. It also uploads device configurations generated with the real exporters — some carrying rules nobody documented, so the drift comparison has something to find — and leaves one rule standing as an emergency change awaiting approval. A demo that shows only the happy path demonstrates none of what the tool is for.

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
    drift.py           target/actual comparison per component
    config_blocks.py   finds where a rule starts in a device configuration
    coverage.py        one coverage figure for the estate, and what it misses
    messages.py        message catalogue; entries render in the reader's language
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
scripts/               encrypted backup and restore, secret scan
  tests/               pytest
frontend/
  src/pages/           React pages (rules, zones, networks, components, admin, …)
  src/i18n.jsx         bilingual UI (German/English, set by the admin per instance)
deploy/k8s/            Kubernetes manifests
docs/                  CONCEPTS, EXPORTS, API, AUDIT, ADMINISTRATION, DEPLOYMENT
examples/              generated example exports
```

## Where this lives

**GitHub is the home**: <https://github.com/Panxatony/permitra> — issues, pull
requests, releases and CI. A self-hosted GitLab mirrors the repository and runs
the same pipeline; it is a copy, not a second place to work. Anything merged
there and not here would be lost on the next sync.

Note when reading older text: issue numbers in this file refer to the **GitLab**
tracker the project started in. They are written out as "GitLab issue 26" rather
than `#26`, because on GitHub that number now belongs to a pull request.

## Tests

```bash
cd backend && ../.venv/bin/python -m pytest tests/
```

## Roadmap

Tracked as [GitHub issues](https://github.com/Panxatony/permitra/issues). The
larger open pieces: time windows on rules (#83), Layer 7 / App-ID in the export
(#84), deputies and escalation for approvers (#50), NAT (#38) and rule order
(#33).

Multi-environment support — overlapping IP ranges per environment, e.g. IT and
OT — is fully built and currently dormant behind a single default environment.

## How this project was built

In the spirit of transparency: **Permitra was built with [Claude](https://claude.com/claude-code), Anthropic's AI coding assistant** — every commit carries the co-author trailer.

The author is a solution architect who has delivered many cloud infrastructure projects, each of them accompanied by Excel sheets full of security rules. With limited programming skills of their own, working with Claude made it possible to turn that hands-on domain experience into a working solution: the architecture principles, workflows and requirements behind Permitra come from real project practice; the implementation grew out of an iterative dialogue with the AI.

That is also part of why Permitra is open source: so that experienced developers can review the code critically, point out what should be done better — and use the ideas as inspiration for their own work.

## License

Permitra is open source under the [Apache License 2.0](LICENSE).

Copyright 2026 Lars Vonhof-Hunold
