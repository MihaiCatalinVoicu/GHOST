#!/usr/bin/env bash
# Starts Tor (onion service) and the relay. The onion hostname is printed once so the operator can
# add it to the signed release manifest; it is never sent anywhere by this script.
set -euo pipefail

GHOST_DATA=${GHOST_DATA:-/var/lib/ghost}
GHOST_LISTEN=${GHOST_LISTEN:-127.0.0.1:7443}
GHOST_FLAGS=${GHOST_FLAGS:-}

chown -R ghost:ghost "$GHOST_DATA"
su -s /bin/sh debian-tor -c "tor -f /etc/tor/torrc" &
TOR_PID=$!

for _ in $(seq 1 60); do
  if [ -s /var/lib/tor/ghost-relay/hostname ]; then break; fi
  sleep 1
done
if [ -s /var/lib/tor/ghost-relay/hostname ]; then
  echo "onion address: $(cat /var/lib/tor/ghost-relay/hostname)"
else
  echo "warning: onion hostname not yet published; tor is still bootstrapping" >&2
fi

# shellcheck disable=SC2086
su -s /bin/sh ghost -c "ghost-relay serve --data-dir '$GHOST_DATA' --listen '$GHOST_LISTEN' $GHOST_FLAGS" &
RELAY_PID=$!

trap 'kill $RELAY_PID $TOR_PID 2>/dev/null || true' TERM INT
wait -n $RELAY_PID $TOR_PID
kill $RELAY_PID $TOR_PID 2>/dev/null || true
exit 1
