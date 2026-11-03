#!/bin/bash
# Permitra – wait until an instance answers /api/health with "ok".
#
# Usage:  ./scripts/wait_health.sh <base-url> [timeout-seconds]
#         ./scripts/wait_health.sh https://demo.permitra.de 180
#
# The backend runs its Alembic migrations on start, so a 502 or a connection
# refused right after `docker compose up` is normal; this script keeps asking
# until the health endpoint says ok or the timeout is reached. Exit code 0 on
# ok, 1 on timeout, so it can gate a follow-up step.
set -u
base="${1:?base url, e.g. https://demo.permitra.de}"
timeout="${2:-180}"
deadline=$((SECONDS + timeout))
while (( SECONDS < deadline )); do
  body=$(curl -s -m 5 "${base%/}/api/health" 2>/dev/null)
  if [[ "$body" == *'"ok"'* ]]; then
    echo "health: $body"
    exit 0
  fi
  sleep 5
done
echo "timeout after ${timeout}s, last answer: ${body:-<none>}" >&2
exit 1
