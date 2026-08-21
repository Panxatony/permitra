# Permitra – Deployment-Plan

## Variante A: Docker Compose (empfohlen für den Prototyp / kleine Teams)

**Komponenten:** PostgreSQL 16, FastAPI-Backend (uvicorn), Frontend (nginx mit statischem Build + API-Proxy).

```bash
# .env anlegen (nicht einchecken!)
cat > .env <<'EOF'
DB_PASSWORD=<starkes-passwort>
SECRET_KEY=<langer-zufallsstring>   # z.B. openssl rand -hex 32
EOF

docker compose up --build -d
docker compose exec backend python import_excel.py /data/AP0400Sicherheitsregeln.xlsx
```

- UI/API erreichbar auf Port **8080** (nginx proxied `/api` zum Backend; Backend und DB sind nicht direkt exponiert).
- Datenhaltung im Volume `pgdata`.
- **Backup:** `docker compose exec db pg_dump -U permitra permitra > backup.sql` (per Cron).
- **Update:** `git pull && docker compose up --build -d` – das Schema wird beim Start angelegt;
  für spätere Schema-Änderungen Alembic-Migrationen ergänzen.

## Variante B: Kubernetes

Manifeste unter `deploy/k8s/permitra.yaml` (Namespace, Secret, Postgres-StatefulSet mit PVC,
Backend-Deployment mit Readiness-Probe auf `/api/health`, Frontend-Deployment, Ingress).

```bash
# Images bauen und pushen
docker build -t $REGISTRY/permitra-backend:latest backend/
docker build -t $REGISTRY/permitra-frontend:latest frontend/
docker push $REGISTRY/permitra-backend:latest
docker push $REGISTRY/permitra-frontend:latest

# REGISTRY/Hostnamen + Secrets in permitra.yaml anpassen, dann:
kubectl apply -f deploy/k8s/permitra.yaml
```

Für Produktion empfohlen: verwalteter PostgreSQL-Dienst oder Operator (z.B. CloudNativePG)
statt des einfachen StatefulSets, TLS am Ingress (cert-manager), NetworkPolicies.

## Härtung (vor Produktivbetrieb)

1. **SECRET_KEY** setzen (JWT-Signierung) und Demo-Benutzer entfernen bzw. Passwörter ändern
   (`seed.py` legt sie nur an, wenn die Benutzertabelle leer ist).
2. **TLS** terminieren (Reverse-Proxy/Ingress); HTTP nur intern.
3. **CORS** in `backend/app/main.py` auf die echte Frontend-Origin einschränken.
4. **LDAP/AD-Anbindung** statt lokaler Konten (Erweiterungspunkt: `auth.py`).
5. Datenbank-Zugang nur aus dem Backend-Netz; regelmäßige Dumps.
6. Audit: Versionshistorie ist fachlich vorhanden; zusätzlich zentrale API-Logs sammeln.
