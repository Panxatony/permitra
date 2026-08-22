#!/bin/bash
# Permitra – PostgreSQL backup of the Docker Compose stack.
# Usage:  ./scripts/backup.sh [target_dir]
# Cron example (daily at 02:30):
#   30 2 * * * cd /path/to/permitra && ./scripts/backup.sh /var/backups/permitra
set -euo pipefail
cd "$(dirname "$0")/.."

TARGET_DIR="${1:-./backups}"
mkdir -p "$TARGET_DIR"
STAMP=$(date +%Y%m%d-%H%M%S)
FILE="$TARGET_DIR/permitra-$STAMP.sql.gz"

docker compose exec -T db pg_dump -U permitra permitra | gzip > "$FILE"
echo "Backup written: $FILE ($(du -h "$FILE" | cut -f1))"

# Retention: keep the last 14 backups
ls -1t "$TARGET_DIR"/permitra-*.sql.gz 2>/dev/null | tail -n +15 | xargs -r rm --
