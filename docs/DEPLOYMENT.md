# Permitra – Deployment Guide

## Option A: Docker Compose (recommended for the prototype / small teams)

**Components:** PostgreSQL 16, FastAPI backend (uvicorn), frontend (nginx with static build + API proxy).

```bash
# Create .env (do not commit!)
cat > .env <<'EOF'
DB_PASSWORD=<strong-password>
SECRET_KEY=<long-random-string>   # e.g. openssl rand -hex 32
EOF

docker compose up --build -d
docker compose exec backend python seed_demo.py --wipe   # optional demo data
```

- UI/API reachable on port **8080** (nginx proxies `/api` to the backend; backend and DB are not exposed directly). Override with `FRONTEND_PORT`.
- Data is stored in the `pgdata` volume.
- **The stack comes back after a reboot.** All three services carry
  `restart: unless-stopped`, so Docker starts them again when the host
  does. A stack you stopped on purpose (`docker compose stop`) stays
  stopped. Without this the containers simply do not come back and
  nothing says so — the instance is down until somebody visits it.
- **After the stack is up:** sign in as the initial admin and follow the
  **Initial configuration** checklist on the dashboard/admin page — language,
  zones, networks, components, matrix, accounts, first rule, in that order,
  each step saying why the next one needs it. It disappears once the essentials
  exist. The initial admin password comes from `PERMITRA_INITIAL_ADMIN_PASSWORD`
  in `.env`, or, if unset, from `/app/initial-admin-password.txt` inside the
  backend container.
- **Backup and restore:** see [Backups](#backups) below. Short version: `scripts/backup.sh` writes an encrypted dump, `scripts/restore.sh` plays one back — and you should run the second one on purpose, at least once, before you need it.
- **Update:** `git pull && docker compose up --build -d` — schema changes run automatically via Alembic migrations at startup.
- **Imprint and privacy policy.** `PERMITRA_IMPRINT_URL` and
  `PERMITRA_PRIVACY_URL` put two links in the footer and on the sign-in page.
  They are empty by default and then nothing is shown, which is right for an
  instance reachable only inside a company network. **An instance reachable
  from the internet has to set them, and has to point them at its own
  operator's pages** — § 5 DDG names the operator of the service, and that is
  you, not the supplier of the software. Only absolute `http(s)` URLs are
  accepted; anything else is dropped with a warning in the log, because the
  value ends up in an `href` on every page.
- **Optional environment variables** (see README for details): `SMTP_*` + `PERMITRA_BASE_URL` (email delivery and links), `PERMITRA_RP_ID`/`PERMITRA_ORIGIN` (passkeys/WebAuthn), `CHANGE_WEBHOOK_URL`/`CHANGE_WEBHOOK_TOKEN` (change management webhook), `AUDIT_WEBHOOK_URL` and/or `AUDIT_SYSLOG_HOST`/`AUDIT_SYSLOG_PORT`/`AUDIT_SYSLOG_PROTO` (SIEM delivery of the audit log).

> **Single instance by design.** The backend runs background jobs in-process — SIEM delivery, audit-chain anchoring and the daily expiry/recertification run. They carry no cross-instance locking, so a second backend instance would deliver audit events to the SIEM twice, send recertification mails twice, and race on the Alembic migrations at startup. Scale the frontend freely (it is stateless); keep the backend at one replica unless those jobs are reworked.

## Backups

The dump holds everything Permitra is trusted with: password hashes, the
encrypted NetBox token, TOTP seeds, API token hashes and the whole audit chain.
Left as plain SQL on a filesystem, reading the backup directory is as good as
reading the database — and backup directories travel: to a share, to off-site
storage, onto somebody's laptop. So `scripts/backup.sh` encrypts, and refuses to
run if it cannot.

### Setting it up

```bash
# A passphrase, kept where the backups are NOT.
sudo mkdir -p /etc/permitra
openssl rand -base64 32 | sudo tee /etc/permitra/backup.key >/dev/null
sudo chmod 600 /etc/permitra/backup.key

# Daily at 02:30
30 2 * * * cd /opt/permitra && PERMITRA_BACKUP_PASSPHRASE_FILE=/etc/permitra/backup.key ./scripts/backup.sh /var/backups/permitra
```

**Keep the passphrase somewhere the backups are not.** The script checks this and
refuses if the key file sits inside the backup directory — a key that is copied
along with what it protects protects nothing. Back the passphrase up separately,
in a password manager or a sealed envelope: **without it the dumps are lost**,
and that is the point of them being encrypted.

| Variable | Meaning |
|---|---|
| `PERMITRA_BACKUP_PASSPHRASE_FILE` | file holding the passphrase (preferred) |
| `PERMITRA_BACKUP_PASSPHRASE` | the passphrase itself, if a file is impractical |
| `PERMITRA_BACKUP_KEEP` | generations to keep (default 14) |
| `PERMITRA_BACKUP_PLAINTEXT=1` | skip encryption deliberately — only when the storage is encrypted at another layer; it warns on every run |
| `PERMITRA_PG_URL` | connect directly instead of through `docker compose` (Kubernetes, managed database) |

### Restoring

```bash
# Into a fresh, empty database — the normal rehearsal
PERMITRA_BACKUP_PASSPHRASE_FILE=/etc/permitra/backup.key \
  ./scripts/restore.sh /var/backups/permitra/permitra-20260823-023000.sql.gz.gpg
```

The script refuses a database that already holds data unless you repeat the
command with `--force`. The most expensive mistake available here is restoring
last night's dump over a healthy production database, and it is one keystroke
away from a legitimate one.

Afterwards it re-verifies the **audit hash chain**. That check is the interesting
part: "the SQL applied without error" is a weak claim, while a chain that still
verifies proves the dump preserved the property the audit log exists for. If it
had been truncated, or rows had come back in a different order, this is where you
find out — in a rehearsal rather than in an incident.

### Version mismatch

A `pg_dump` newer than the server writes statements the server does not know —
PostgreSQL 17 emits `SET transaction_timeout = 0`, which a 16 server rejects, and
the restore stops on the first line. The dump looks perfectly fine until the day
it is needed. The script warns when it notices; through `docker compose` it uses
the server's own client and the question does not arise.

### What is checked automatically

CI runs the whole round trip on every pull request: dump a migrated database,
encrypt, refuse to overwrite a populated target, restore into a fresh one, and
verify the audit chain. It also greps the encrypted file for readable SQL, so
encryption silently ceasing to happen fails the build rather than being
discovered later.

## Option B: Kubernetes

Manifests under `deploy/k8s/permitra.yaml` (namespace, secret, Postgres StatefulSet with PVC, backend deployment with readiness probe on `/api/health`, frontend deployment, ingress).

```bash
# Build and push images
docker build -t $REGISTRY/permitra-backend:latest backend/
docker build -t $REGISTRY/permitra-frontend:latest frontend/
docker push $REGISTRY/permitra-backend:latest
docker push $REGISTRY/permitra-frontend:latest

# Adjust REGISTRY/hostnames + secrets in permitra.yaml, then:
kubectl apply -f deploy/k8s/permitra.yaml
```

Recommended for production: a managed PostgreSQL service or operator (e.g. CloudNativePG) instead of the simple StatefulSet, TLS at the ingress (cert-manager), NetworkPolicies.

## Hardening (before production use)

1. **SECRET_KEY is mandatory** — the app refuses to start without it (fail-secure). Generate with `openssl rand -hex 32`. Do **not** set `PERMITRA_DEMO`; leave it unset in production so no known demo accounts are created — instead a single `admin` with a random password is created on first start and printed once to the log (change it immediately). `PERMITRA_DEV=1` is for local development only (random per-process key).
2. Terminate **TLS** (reverse proxy/ingress); HTTP internal only. Passkeys/WebAuthn require HTTPS.
3. Restrict **CORS** via `PERMITRA_CORS_ORIGINS` (comma-separated) to the real frontend origin; a wildcard is intentionally rejected (credentials are enabled).
4. Enable **2FA/passkeys** for accounts, or connect **LDAP/AD** instead of local accounts (extension point: `auth.py`).
5. Database access only from the backend network; regular dumps.
6. **Rate limiting**: the app locks an account for `LOGIN_LOCK_MINUTES` (default 15) after `LOGIN_MAX_FAILS` (default 5) failed logins; additionally rate-limit at the reverse proxy (see the public demo: strict limit on `/api/auth/login`, moderate limit on `/api/`).
7. **Audit**: the version history plus the append-only event store (sign-in, administration, data access — with source IP) cover the application level. Verify the hash chain regularly via `GET /api/audit-log/verify` (or the admin area) — it detects any change, reordering or removal of an event, including edits made directly in the database, and compares the chain against the newest checkpoint so that cutting off the *newest* entries is caught too (checkpoints are written hourly; tune with `AUDIT_CHECKPOINT_INTERVAL`, or anchor on demand via `POST /api/audit-log/checkpoint` before securing evidence). **Be aware of the limit:** the hash is keyless, so an attacker with database write access can recompute the chain and delete the checkpoints. Only the copies held by the SIEM are beyond that reach — configuring a sink is what turns the chain into real evidence, which is why the next point matters. Configure a SIEM sink (`AUDIT_WEBHOOK_URL` or `AUDIT_SYSLOG_HOST`) so evidence is also held outside the application: events are queued durably and delivered at-least-once, surviving restarts and sink outages; watch `GET /api/audit-log/siem-status` for a growing `pending` count (it also reports `anchors_pending`, i.e. checkpoints not yet handed over). An unreachable sink does not affect API latency — the delivery runs in a worker thread and backs off from 10 s to at most 5 minutes between attempts — but events do queue up, so a `pending` count that keeps climbing is the signal to look at the sink. Set `AUDIT_SYSLOG_PROTO=tcp` for acknowledged syslog delivery (UDP is best-effort). Behind a reverse proxy, set `PERMITRA_TRUSTED_PROXIES` to that proxy's IP or CIDR — only then is `X-Forwarded-For` evaluated at all. Without it the header is ignored entirely and the immediate peer is recorded, which cannot be forged. Do **not** widen the list to whole private ranges unless the published port is reachable only by that proxy (bind it to localhost, e.g. `FRONTEND_PORT=127.0.0.1:8100`): any client able to reach the port from a trusted range could otherwise invent its own source IP. Additionally collect central API logs. **Retention:** set `audit_retention_days` in the admin area to enforce a deletion period for the personal data (usernames, source IPs) in the audit log — expired prefixes collapse behind a sealed anchor so the chain stays verifiable (GDPR Art. 5(1)(e), BSI CON.6). With a SIEM configured, nothing is deleted before it has been delivered there.
