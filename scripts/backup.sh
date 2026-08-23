#!/bin/bash
# Permitra – encrypted PostgreSQL backup.
#
# Usage:  ./scripts/backup.sh [target_dir]
#
# Cron example (daily at 02:30):
#   30 2 * * * cd /path/to/permitra && PERMITRA_BACKUP_PASSPHRASE_FILE=/etc/permitra/backup.key ./scripts/backup.sh /var/backups/permitra
#
# Environment:
#   PERMITRA_BACKUP_PASSPHRASE_FILE  file holding the passphrase (preferred)
#   PERMITRA_BACKUP_PASSPHRASE       the passphrase itself (visible in the parent's environment)
#   PERMITRA_BACKUP_PLAINTEXT=1      deliberately skip encryption (see below)
#   PERMITRA_BACKUP_KEEP             how many generations to keep (default 14)
#   PERMITRA_PG_URL                  connect directly instead of via docker compose
#
# The dump is encrypted because of what is in it: password hashes, the encrypted
# NetBox token, TOTP seeds, API token hashes and the whole audit chain. Left as
# plain SQL, reading the backup directory is as good as reading the database -
# and backup directories travel: to a share, to off-site storage, onto a laptop.
#
# Restore with scripts/restore.sh - and do it once on purpose, against a scratch
# database, before you need it. A backup that has never been played back is a
# guess, and the moment you find out is the worst possible one.
set -euo pipefail
cd "$(dirname "$0")/.."
# shellcheck source=lib/db.sh
. scripts/lib/db.sh
# shellcheck source=lib/crypt.sh
. scripts/lib/crypt.sh

TARGET_DIR="${1:-./backups}"
KEEP="${PERMITRA_BACKUP_KEEP:-14}"
mkdir -p "$TARGET_DIR"
STAMP=$(date +%Y%m%d-%H%M%S)

# `return 0` matters: an EXIT trap ending on a false test makes bash report
# that status as the script's exit code.
cleanup() { [ -n "${TMP_PASS:-}" ] && rm -f "$TMP_PASS"; return 0; }
trap cleanup EXIT

pg_version_check

if [ "${PERMITRA_BACKUP_PLAINTEXT:-}" = "1" ]; then
  # Said out loud on every single run rather than configured once and forgotten.
  echo "permitra: WARNING - writing an UNENCRYPTED dump (PERMITRA_BACKUP_PLAINTEXT=1)." >&2
  echo "          It contains password hashes, TOTP seeds and API token hashes." >&2
  FILE="$TARGET_DIR/permitra-$STAMP.sql.gz"
  pg_dump_stream | gzip > "$FILE.part"
else
  crypt_require_tool
  PASS_FILE=$(crypt_passphrase_file "$TARGET_DIR")
  # Only remove it afterwards if this script created it.
  [ "$PASS_FILE" = "${PERMITRA_BACKUP_PASSPHRASE_FILE:-}" ] || TMP_PASS="$PASS_FILE"

  FILE="$TARGET_DIR/permitra-$STAMP.sql.gz$CRYPT_EXTENSION"
  pg_dump_stream | gzip | crypt_encrypt "$PASS_FILE" > "$FILE.part"
fi

# Written under a .part name first: a crash mid-dump would otherwise leave a
# truncated file that looks like a backup and restores like a disaster.
mv "$FILE.part" "$FILE"
chmod 600 "$FILE"
echo "permitra: backup written to $FILE ($(du -h "$FILE" | cut -f1))"

# Retention. Both naming schemes are matched, so switching encryption on or off
# does not strand old generations forever.
#
# Wrapped so its status cannot become the script's: with one of the two globs
# unmatched, `ls` returns non-zero, `pipefail` fails the pipeline, and being the
# last command it would report a perfectly good backup as a failure. Which is
# the one thing a backup script must never do.
prune_old_backups() {
  # nullglob rather than passing both patterns to `ls`: with one of them
  # unmatched - which is the normal case, since a directory holds either
  # encrypted or plain dumps - ls returns non-zero and the pruning silently
  # never happened. Backups then accumulate until the disk fills.
  local files sorted old
  shopt -s nullglob
  files=( "$TARGET_DIR"/permitra-*.sql.gz "$TARGET_DIR"/permitra-*.sql.gz.gpg )
  shopt -u nullglob

  [ "${#files[@]}" -gt "$KEEP" ] || return 0
  sorted=$(ls -1t "${files[@]}")
  old=$(echo "$sorted" | tail -n +$((KEEP + 1)))
  [ -n "$old" ] || return 0
  echo "$old" | xargs -r rm --
  echo "permitra: pruned $(echo "$old" | wc -l | tr -d ' ') old backup(s), keeping $KEEP."
}
prune_old_backups
