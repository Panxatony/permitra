#!/bin/bash
# Encryption for the backup dumps.
#
# The dump holds everything Permitra is trusted with: password hashes, the
# encrypted NetBox token, TOTP seeds, API token hashes and the whole audit
# chain. As plain SQL on a filesystem, anyone who can read the backup directory
# has the database without needing the database - a misconfigured share, a
# stolen laptop, an off-site copy on someone else's storage.
#
# The tool is `gpg --symmetric` and only that. `age` was considered and dropped:
# its passphrase mode insists on a terminal, so it cannot run from cron without
# an expect wrapper, and its non-interactive mode needs a different key model
# (recipient/identity files). One well-understood path that works unattended
# beats two that need explaining.
#
# The passphrase comes from PERMITRA_BACKUP_PASSPHRASE_FILE (preferred) or
# PERMITRA_BACKUP_PASSPHRASE. It must not live inside the backup directory - a
# key stored next to what it protects protects nothing, and that is checked
# rather than merely advised.

# shellcheck shell=bash

CRYPT_EXTENSION=".gpg"

crypt_require_tool() {
  command -v gpg >/dev/null 2>&1 && return 0
  echo "permitra: gpg is not installed - it is needed to encrypt the dump." >&2
  echo "          Install gnupg, or set PERMITRA_BACKUP_PLAINTEXT=1 if the storage" >&2
  echo "          is encrypted at another layer and you accept the risk." >&2
  return 1
}

# Prints the path of a file holding the passphrase, creating a temporary one
# when the passphrase came from the environment. The caller removes it.
#
# A file rather than a command-line argument on purpose: arguments are visible
# in `ps` to every user on the host for as long as gpg runs.
crypt_passphrase_file() {
  local target_dir="${1:-}"
  local configured="${PERMITRA_BACKUP_PASSPHRASE_FILE:-}"

  if [ -n "$configured" ]; then
    [ -r "$configured" ] || {
      echo "permitra: cannot read PERMITRA_BACKUP_PASSPHRASE_FILE ($configured)" >&2
      return 1
    }
    if [ -n "$target_dir" ] && ! crypt_key_is_outside "$configured" "$target_dir"; then
      return 1
    fi
    echo "$configured"
    return 0
  fi

  if [ -n "${PERMITRA_BACKUP_PASSPHRASE:-}" ]; then
    local tmp
    tmp=$(mktemp) || return 1
    chmod 600 "$tmp"
    printf '%s' "$PERMITRA_BACKUP_PASSPHRASE" > "$tmp"
    echo "$tmp"
    return 0
  fi

  echo "permitra: no backup passphrase set - refusing to write an unencrypted dump." >&2
  echo "          Set PERMITRA_BACKUP_PASSPHRASE_FILE (preferred) or PERMITRA_BACKUP_PASSPHRASE." >&2
  echo "          If the storage is encrypted at another layer and you accept the risk," >&2
  echo "          set PERMITRA_BACKUP_PLAINTEXT=1 deliberately." >&2
  return 1
}

# Refuses a passphrase file that lives inside the backup directory: it would be
# copied along with the backups it protects, to wherever they go.
crypt_key_is_outside() {
  local key_file="$1" target_dir="$2" key_dir backup_dir
  key_dir=$(cd "$(dirname "$key_file")" 2>/dev/null && pwd -P) || return 0
  backup_dir=$(cd "$target_dir" 2>/dev/null && pwd -P) || return 0
  case "$key_dir/" in
    "$backup_dir"/*)
      echo "permitra: the passphrase file lies inside the backup directory ($backup_dir)." >&2
      echo "          Keep it elsewhere - otherwise it travels with what it protects." >&2
      return 1 ;;
  esac
  return 0
}

# stdin -> encrypted stdout
crypt_encrypt() {
  local passphrase_file="$1"
  gpg --batch --quiet --yes --pinentry-mode loopback \
      --passphrase-file "$passphrase_file" \
      --symmetric --cipher-algo AES256 --compress-algo none
}

# stdin -> decrypted stdout
crypt_decrypt() {
  local passphrase_file="$1"
  gpg --batch --quiet --yes --pinentry-mode loopback \
      --passphrase-file "$passphrase_file" --decrypt
}
