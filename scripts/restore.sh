#!/bin/bash
# Permitra – restore a backup written by scripts/backup.sh.
#
# Usage:  ./scripts/restore.sh <backup-file> [--force]
#
# Environment:
#   PERMITRA_BACKUP_PASSPHRASE_FILE  file holding the passphrase
#   PERMITRA_BACKUP_PASSPHRASE       the passphrase itself
#   PERMITRA_PG_URL                  connect directly instead of via docker compose
#   PERMITRA_SKIP_VERIFY=1           skip the audit-chain check afterwards
#
# This exists because a backup that has never been restored is a guess. Run it
# against a scratch database now and then - the point of the exercise is to find
# out that it works while nothing is on fire.
#
# It refuses to overwrite a database that already holds data unless --force is
# given. The most expensive mistake available here is restoring last night's
# dump over a healthy production database, and that mistake is one keystroke
# away from a legitimate one.
set -euo pipefail
cd "$(dirname "$0")/.."
# shellcheck source=lib/db.sh
. scripts/lib/db.sh
# shellcheck source=lib/crypt.sh
. scripts/lib/crypt.sh

FILE="${1:-}"
FORCE="${2:-}"

if [ -z "$FILE" ] || [ ! -r "$FILE" ]; then
  echo "Usage: $0 <backup-file> [--force]" >&2
  echo "  <backup-file>  a permitra-*.sql.gz.gpg (or .sql.gz) written by backup.sh" >&2
  exit 1
fi

# `return 0` matters: an EXIT trap ending on a false test makes bash report
# that status as the script's exit code.
cleanup() { [ -n "${TMP_PASS:-}" ] && rm -f "$TMP_PASS"; return 0; }
trap cleanup EXIT

# --- Refuse to overwrite a populated database without being told twice -------
EXISTING=$(pg_query "SELECT count(*) FROM information_schema.tables WHERE table_schema='public'" | tr -d '[:space:]')
if [ "${EXISTING:-0}" != "0" ] && [ "$FORCE" != "--force" ]; then
  ROWS=$(pg_query "SELECT count(*) FROM rules" 2>/dev/null | tr -d '[:space:]' || echo "?")
  echo "permitra: the target database is not empty ($EXISTING tables, $ROWS rules)." >&2
  echo "          Restoring would replace it. If that is what you want, repeat with --force:" >&2
  echo "            $0 $FILE --force" >&2
  exit 1
fi

# --- Decrypt / decompress into SQL on stdout --------------------------------
decoded() {
  case "$FILE" in
    *.gpg)
      crypt_require_tool
      PASS_FILE=$(crypt_passphrase_file)
      [ "$PASS_FILE" = "${PERMITRA_BACKUP_PASSPHRASE_FILE:-}" ] || TMP_PASS="$PASS_FILE"
      crypt_decrypt "$PASS_FILE" < "$FILE" | gunzip ;;
    *.gz)
      gunzip -c "$FILE" ;;
    *)
      cat "$FILE" ;;
  esac
}

echo "permitra: restoring $FILE …"
# Drop and recreate the schema first. Restoring on top of existing tables would
# fail halfway through on the first conflicting object and leave a mixture of
# two databases, which is worse than either.
pg_apply <<'SQL'
DROP SCHEMA public CASCADE;
CREATE SCHEMA public;
SQL
decoded | pg_apply

# --- Prove the restore preserved the property the audit log exists for ------
#
# "The SQL applied without error" is a weak claim. The interesting question is
# whether the hash chain still verifies: if the dump had been truncated, or the
# rows had come back in a different order, or an event had been lost, the chain
# would break here and the backup would be worthless for exactly the purpose it
# is kept for.
if [ "${PERMITRA_SKIP_VERIFY:-}" = "1" ]; then
  echo "permitra: restore finished (audit-chain check skipped)."
  exit 0
fi

VERIFY_PY='
from app.database import SessionLocal
from app import audit
db = SessionLocal()
result = audit.verify_chain(db)
db.close()
print(f"audit chain: ok={result[\"ok\"]} checked={result[\"checked\"]}")
raise SystemExit(0 if result["ok"] else 1)
'

if [ "$(pg_mode)" = "direct" ]; then
  (cd backend && DATABASE_URL="$PERMITRA_PG_URL" PYTHONPATH=. python -c "$VERIFY_PY")
else
  docker compose exec -T backend python -c "$VERIFY_PY"
fi

echo "permitra: restore finished and the audit chain verifies."
