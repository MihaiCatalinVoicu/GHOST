#!/usr/bin/env bash
# Starts Tor (onion service) and the relay. The onion hostname is printed once so the operator can
# add it to the signed release manifest; it is never sent anywhere by this script.
# Token redemption (Phase 8 design §10.5, §19.10 point 3): with --schedule in GHOST_FLAGS the relay
# must serve the onion its slot names in the Entitlement Schedule, so the onion service key set is
# mounted into the HiddenServiceDir and the start is refused without one (Tor would otherwise create
# an onion the schedule does not list). The HiddenServiceDir is private to Tor: the unprivileged
# relay reads a copy of the public hostname file (--onion-hostname-file /run/ghost-relay/onion-hostname).
set -euo pipefail

GHOST_DATA=${GHOST_DATA:-/var/lib/ghost}
GHOST_LISTEN=${GHOST_LISTEN:-127.0.0.1:7443}
GHOST_FLAGS=${GHOST_FLAGS:-}
HS_DIR=/var/lib/tor/ghost-relay
ONION_HOSTNAME=/run/ghost-relay/onion-hostname

chown -R ghost:ghost "$GHOST_DATA"
case " $GHOST_FLAGS " in
  *" --schedule "*)
    if [ ! -s "$HS_DIR/hs_ed25519_secret_key" ]; then
      echo "error: --schedule needs the onion service key set of the relay's slot in $HS_DIR" >&2
      exit 64
    fi
    ;;
esac
# A key set mounted from the host belongs to Tor, which refuses a directory others can read.
chown -R debian-tor:debian-tor "$HS_DIR"
chmod 0700 "$HS_DIR"
su -s /bin/sh debian-tor -c "tor -f /etc/tor/torrc" &
TOR_PID=$!

for _ in $(seq 1 60); do
  if [ -s "$HS_DIR/hostname" ]; then break; fi
  sleep 1
done
if [ -s "$HS_DIR/hostname" ]; then
  echo "onion address: $(cat "$HS_DIR/hostname")"
  mkdir -p "${ONION_HOSTNAME%/*}"
  install -m 0444 "$HS_DIR/hostname" "$ONION_HOSTNAME"
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
