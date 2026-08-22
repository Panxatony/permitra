#!/bin/sh
# Erzeugt die Vertrauensliste für X-Forwarded-For beim Containerstart.
#
# Die Quell-IP landet im revisionssicheren Audit-Log. Ein X-Forwarded-For darf
# deshalb nur ausgewertet werden, wenn er von einem ausdrücklich benannten
# Reverse-Proxy stammt – sonst kann jeder Client seine Herkunft frei erfinden.
#
# PERMITRA_TRUSTED_PROXIES: kommagetrennte IPs/CIDRs des vorgelagerten Proxys.
#   nicht gesetzt -> kein X-Forwarded-For wird ausgewertet (sicherer Standard)
set -e
TARGET=/etc/nginx/conf.d/10-realip.conf

if [ -z "${PERMITRA_TRUSTED_PROXIES:-}" ]; then
  echo "# PERMITRA_TRUSTED_PROXIES nicht gesetzt: X-Forwarded-For wird nicht ausgewertet." > "$TARGET"
  echo "permitra: kein vertrauenswürdiger Proxy konfiguriert – X-Forwarded-For wird ignoriert"
  exit 0
fi

: > "$TARGET"
echo "# Erzeugt aus PERMITRA_TRUSTED_PROXIES – nicht von Hand bearbeiten." >> "$TARGET"
echo "$PERMITRA_TRUSTED_PROXIES" | tr ',' '\n' | while read -r cidr; do
  cidr=$(echo "$cidr" | tr -d '[:space:]')
  [ -n "$cidr" ] || continue
  echo "set_real_ip_from $cidr;" >> "$TARGET"
done
{
  echo "real_ip_header X-Forwarded-For;"
  echo "real_ip_recursive on;"
} >> "$TARGET"
echo "permitra: vertraue X-Forwarded-For von: $PERMITRA_TRUSTED_PROXIES"
