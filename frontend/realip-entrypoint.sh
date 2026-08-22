#!/bin/sh
# Generates the trust list for X-Forwarded-For at container startup.
#
# The source IP ends up in the tamper-evident audit log. An X-Forwarded-For may
# therefore only be evaluated if it comes from an explicitly named reverse
# proxy – otherwise any client could make up its own origin.
#
# PERMITRA_TRUSTED_PROXIES: comma-separated IPs/CIDRs of the upstream proxy.
#   not set -> no X-Forwarded-For is evaluated (safe default)
set -e
TARGET=/etc/nginx/conf.d/10-realip.conf

if [ -z "${PERMITRA_TRUSTED_PROXIES:-}" ]; then
  echo "# PERMITRA_TRUSTED_PROXIES not set: X-Forwarded-For is not evaluated." > "$TARGET"
  echo "permitra: no trusted proxy configured – X-Forwarded-For is ignored"
  exit 0
fi

: > "$TARGET"
echo "# Generated from PERMITRA_TRUSTED_PROXIES – do not edit by hand." >> "$TARGET"
echo "$PERMITRA_TRUSTED_PROXIES" | tr ',' '\n' | while read -r cidr; do
  cidr=$(echo "$cidr" | tr -d '[:space:]')
  [ -n "$cidr" ] || continue
  echo "set_real_ip_from $cidr;" >> "$TARGET"
done
{
  echo "real_ip_header X-Forwarded-For;"
  echo "real_ip_recursive on;"
} >> "$TARGET"
echo "permitra: trusting X-Forwarded-For from: $PERMITRA_TRUSTED_PROXIES"
