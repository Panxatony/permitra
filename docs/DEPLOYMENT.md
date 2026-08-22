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
- **Optional environment variables** (see README for details): `SMTP_*` + `PERMITRA_BASE_URL` (email delivery and links), `PERMITRA_RP_ID`/`PERMITRA_ORIGIN` (passkeys/WebAuthn), `CHANGE_WEBHOOK_URL`/`CHANGE_WEBHOOK_TOKEN` (change management webhook).

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

1. Set a strong **SECRET_KEY** (JWT signing) and remove the demo users or change their passwords (`seed.py` only creates them when the user table is empty).
2. Terminate **TLS** (reverse proxy/ingress); HTTP internal only. Passkeys/WebAuthn require HTTPS.
3. Restrict **CORS** in `backend/app/main.py` to the real frontend origin.
4. Enable **2FA/passkeys** for accounts, or connect **LDAP/AD** instead of local accounts (extension point: `auth.py`).
5. Database access only from the backend network; regular dumps.
6. **Rate limiting** at the reverse proxy (see the public demo: strict limit on `/api/auth/login`, moderate limit on `/api/`).
7. Audit: the version history covers the application level; additionally collect central API logs.
