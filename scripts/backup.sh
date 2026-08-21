#!/bin/bash
# Permitra – PostgreSQL-Backup des Docker-Compose-Stacks.
# Aufruf:  ./scripts/backup.sh [zielverzeichnis]
# Cron-Beispiel (täglich 02:30):
#   30 2 * * * cd /pfad/zu/permitra && ./scripts/backup.sh /var/backups/permitra
set -euo pipefail
cd "$(dirname "$0")/.."

TARGET_DIR="${1:-./backups}"
mkdir -p "$TARGET_DIR"
STAMP=$(date +%Y%m%d-%H%M%S)
FILE="$TARGET_DIR/permitra-$STAMP.sql.gz"

docker compose exec -T db pg_dump -U permitra permitra | gzip > "$FILE"
echo "Backup geschrieben: $FILE ($(du -h "$FILE" | cut -f1))"

# Aufbewahrung: die letzten 14 Backups behalten
ls -1t "$TARGET_DIR"/permitra-*.sql.gz 2>/dev/null | tail -n +15 | xargs -r rm --
