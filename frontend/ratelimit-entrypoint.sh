#!/bin/sh
# Generates the sign-in rate limit at container startup.
#
# The account lockout in the application protects one account at a time. This
# limit is the other half: it slows down someone spreading a few guesses across
# many accounts, where no single counter ever climbs high enough to trigger.
#
# It is configurable because the right value depends on where Permitra sits.
# Behind a corporate NAT or a reverse proxy whose address is not listed in
# PERMITRA_TRUSTED_PROXIES, every user shares one source address - and the limit
# then applies to the whole office at once. 60r/m with burst=20 absorbs a
# Monday morning while still being useless for guessing passwords.
#
# PERMITRA_LOGIN_RATE: nginx rate, e.g. "60r/m" or "5r/s". "off" disables it.
set -e
TARGET=/etc/nginx/conf.d/05-ratelimit.conf
RATE="${PERMITRA_LOGIN_RATE:-60r/m}"

if [ "$RATE" = "off" ]; then
  # The zone still has to exist - default.conf references it unconditionally.
  # An absurdly high rate is the way to keep the reference valid while letting
  # everything through.
  RATE="1000r/s"
  echo "permitra: login rate limit disabled (PERMITRA_LOGIN_RATE=off)"
else
  echo "permitra: login rate limit $RATE (burst 20)"
fi

cat > "$TARGET" <<EOF
# Generated from PERMITRA_LOGIN_RATE – do not edit by hand.
limit_req_zone \$binary_remote_addr zone=permitra_login:1m rate=$RATE;
EOF
