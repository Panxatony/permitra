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
- **Backup:** `scripts/backup.sh` (pg_dump, 14 generations) via cron, or `docker compose exec db pg_dump -U permitra permitra > backup.sql`.
- **Update:** `git pull && docker compose up --build -d` — schema changes run automatically via Alembic migrations at startup.
- **Optional environment variables** (see README for details): `SMTP_*` + `PERMITRA_BASE_URL` (email delivery and links), `PERMITRA_RP_ID`/`PERMITRA_ORIGIN` (passkeys/WebAuthn), `CHANGE_WEBHOOK_URL`/`CHANGE_WEBHOOK_TOKEN` (change management webhook), `AUDIT_WEBHOOK_URL` and/or `AUDIT_SYSLOG_HOST`/`AUDIT_SYSLOG_PORT`/`AUDIT_SYSLOG_PROTO` (SIEM delivery of the audit log).

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
7. **Audit**: the version history plus the append-only event store (sign-in, administration, data access — with source IP) cover the application level. Verify the hash chain regularly via `GET /api/audit-log/verify` (or the admin area) — it detects any change, reordering or removal of an event, including edits made directly in the database, and compares the chain against the newest checkpoint so that cutting off the *newest* entries is caught too (checkpoints are written hourly; tune with `AUDIT_CHECKPOINT_INTERVAL`, or anchor on demand via `POST /api/audit-log/checkpoint` before securing evidence). **Be aware of the limit:** the hash is keyless, so an attacker with database write access can recompute the chain and delete the checkpoints. Only the copies held by the SIEM are beyond that reach — configuring a sink is what turns the chain into real evidence, which is why the next point matters. Configure a SIEM sink (`AUDIT_WEBHOOK_URL` or `AUDIT_SYSLOG_HOST`) so evidence is also held outside the application: events are queued durably and delivered at-least-once, surviving restarts and sink outages; watch `GET /api/audit-log/siem-status` for a growing `pending` count (it also reports `anchors_pending`, i.e. checkpoints not yet handed over). Set `AUDIT_SYSLOG_PROTO=tcp` for acknowledged syslog delivery (UDP is best-effort). Behind a reverse proxy, set `PERMITRA_TRUSTED_PROXIES` to that proxy's IP or CIDR — only then is `X-Forwarded-For` evaluated at all. Without it the header is ignored entirely and the immediate peer is recorded, which cannot be forged. Do **not** widen the list to whole private ranges unless the published port is reachable only by that proxy (bind it to localhost, e.g. `FRONTEND_PORT=127.0.0.1:8100`): any client able to reach the port from a trusted range could otherwise invent its own source IP. Additionally collect central API logs.
