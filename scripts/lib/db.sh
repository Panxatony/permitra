#!/bin/bash
# How the backup and restore scripts reach the database.
#
# Two environments have to work, and they reach PostgreSQL differently:
#
#   - a Docker Compose stack, where the database has no published port and is
#     reachable only from inside (`docker compose exec db …`)
#   - anything else - Kubernetes, a managed database, or CI - where a plain
#     connection URL and the postgres client tools are what exist
#
# Without the second one, the restore path could not be exercised in CI, and an
# untested restore is a guess rather than a backup. So both scripts talk to the
# database through the two functions here and neither one cares which it got.
#
# Selection: set PERMITRA_PG_URL to use a direct connection. Otherwise Compose.

# shellcheck shell=bash

pg_mode() {
  if [ -n "${PERMITRA_PG_URL:-}" ]; then
    echo "direct"
  else
    echo "compose"
  fi
}

# Warns when the client tools are newer than the server.
#
# A pg_dump newer than the server writes statements the server does not know -
# PostgreSQL 17 emits `SET transaction_timeout = 0`, which a 16 server rejects,
# and the restore stops on the first line. The dump looks perfectly fine until
# the day it is needed. Said here, at backup time, because that is when it can
# still be fixed.
pg_version_check() {
  [ "$(pg_mode)" = "direct" ] || return 0   # compose uses the server's own client
  command -v pg_dump >/dev/null 2>&1 || return 0

  # No `| head -1` here: head exits after the first line, the producer takes a
  # SIGPIPE, and under `set -o pipefail` that aborts the whole backup. Parsing
  # the string instead keeps a version check from being able to stop a backup.
  local raw client server
  raw=$(pg_dump --version 2>/dev/null) || return 0   # "pg_dump (PostgreSQL) 16.4"
  raw=${raw##* }
  client=${raw%%.*}
  server=$(pg_query "SHOW server_version_num" 2>/dev/null | tr -d '[:space:]') || return 0
  case "$client$server" in *[!0-9]*|'') return 0 ;; esac   # unreadable: say nothing
  server=$((server / 10000))

  if [ "$client" -gt "$server" ]; then
    echo "permitra: WARNING - pg_dump is version $client, the server is $server." >&2
    echo "          A dump from a newer client can fail to restore into the older" >&2
    echo "          server. Use a client matching the server, or restore only into" >&2
    echo "          a server of version $client or newer." >&2
  fi
}

# Streams a plain SQL dump of the database to stdout.
pg_dump_stream() {
  if [ "$(pg_mode)" = "direct" ]; then
    pg_dump --no-owner --no-privileges "$PERMITRA_PG_URL"
  else
    docker compose exec -T db pg_dump --no-owner --no-privileges \
      -U "${PERMITRA_DB_USER:-permitra}" "${PERMITRA_DB_NAME:-permitra}"
  fi
}

# Reads SQL from stdin and applies it. Stops at the first error rather than
# limping on: a half-restored database that reports success is the worst
# possible outcome of a restore.
pg_apply() {
  if [ "$(pg_mode)" = "direct" ]; then
    psql --quiet --no-psqlrc -v ON_ERROR_STOP=1 -o /dev/null "$PERMITRA_PG_URL"
  else
    docker compose exec -T db psql --quiet --no-psqlrc -v ON_ERROR_STOP=1 -o /dev/null \
      -U "${PERMITRA_DB_USER:-permitra}" -d "${PERMITRA_DB_NAME:-permitra}"
  fi
}

# Answers a single-value query, e.g. a table count. Used to tell an empty
# database from one that already holds data.
pg_query() {
  local sql="$1"
  if [ "$(pg_mode)" = "direct" ]; then
    psql --quiet --no-psqlrc -tAc "$sql" "$PERMITRA_PG_URL"
  else
    docker compose exec -T db psql --quiet --no-psqlrc -tAc "$sql" \
      -U "${PERMITRA_DB_USER:-permitra}" -d "${PERMITRA_DB_NAME:-permitra}"
  fi
}
