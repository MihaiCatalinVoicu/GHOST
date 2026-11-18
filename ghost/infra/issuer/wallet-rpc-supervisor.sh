#!/usr/bin/env bash
# Supervise one monero-wallet-rpc process. Three consecutive real JSON-RPC failures terminate the
# container; compose's unless-stopped policy starts a fresh process without touching Tor or monerod.
set -uo pipefail

readonly interval="${GHOST_WALLET_WATCHDOG_INTERVAL_SECONDS:-30}"
readonly max_failures="${GHOST_WALLET_WATCHDOG_MAX_FAILURES:-3}"
pid=""

shutdown() {
  trap - TERM INT EXIT
  if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
    kill -TERM "$pid" 2>/dev/null || true
  fi
  [ -z "$pid" ] || wait "$pid" 2>/dev/null || true
}

trap 'exit 143' TERM
trap 'exit 130' INT
trap shutdown EXIT

monero-wallet-rpc --stagenet \
  --wallet-file /var/lib/monero-wallet/issuer-view --password-file /run/ghost/wallet.password \
  --rpc-bind-ip 127.0.0.1 --rpc-bind-port 38083 --rpc-ssl disabled \
  --daemon-address 127.0.0.1:38081 --daemon-login "$DAEMON_RPC_LOGIN" --daemon-ssl disabled --trusted-daemon \
  --log-level 0 --log-file /var/log/monero/wallet-rpc.log --max-log-files 1 --max-log-file-size 10485760 \
  > /dev/null 2>&1 &
pid=$!

failures=0
while kill -0 "$pid" 2>/dev/null; do
  sleep "$interval" &
  sleeper=$!
  wait "$sleeper" 2>/dev/null || true
  kill -0 "$pid" 2>/dev/null || break
  if ghost-wallet-watchdog; then
    failures=0
  else
    failures=$((failures + 1))
  fi
  if [ "$failures" -ge "$max_failures" ]; then
    echo "wallet-watchdog: wallet-rpc failed $failures consecutive healthchecks" >&2
    exit 1
  fi
done

set +e
wait "$pid"
code=$?
set -e
exit "$code"
