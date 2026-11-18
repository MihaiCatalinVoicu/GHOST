#!/usr/bin/env bash
# Fast functional test of wallet-rpc-supervisor.sh with no Docker, Monero or host changes.
set -euo pipefail

root="$(cd "$(dirname "$0")" && pwd)"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
mkdir "$tmp/bin"

cat > "$tmp/bin/monero-wallet-rpc" <<'SH'
#!/usr/bin/env bash
set -u
echo $$ > "$FAKE_WALLET_PID"
trap 'exit 0' TERM INT
while :; do sleep 1 & wait $! || true; done
SH
cat > "$tmp/bin/ghost-wallet-watchdog" <<'SH'
#!/usr/bin/env bash
set -eu
n=0
[ ! -f "$FAKE_WATCHDOG_COUNT" ] || n="$(cat "$FAKE_WATCHDOG_COUNT")"
n=$((n + 1))
echo "$n" > "$FAKE_WATCHDOG_COUNT"
exit 1
SH
chmod +x "$tmp/bin/monero-wallet-rpc" "$tmp/bin/ghost-wallet-watchdog"

set +e
PATH="$tmp/bin:$PATH" \
RPC_LOGIN='test-user:test-password' \
DAEMON_RPC_LOGIN='test-daemon:test-password' \
FAKE_WALLET_PID="$tmp/wallet.pid" \
FAKE_WATCHDOG_COUNT="$tmp/watchdog.count" \
GHOST_WALLET_WATCHDOG_INTERVAL_SECONDS=0.05 \
  "$root/wallet-rpc-supervisor.sh" >"$tmp/out" 2>"$tmp/err"
code=$?
set -e

[ "$code" -eq 1 ]
[ "$(cat "$tmp/watchdog.count")" -eq 3 ]
wallet="$(cat "$tmp/wallet.pid")"
if kill -0 "$wallet" 2>/dev/null; then
  echo "wallet-rpc-supervisor test: child survived watchdog restart" >&2
  exit 1
fi
grep -q 'wallet-watchdog: wallet-rpc failed 3 consecutive healthchecks' "$tmp/err"
echo "wallet-rpc-supervisor test: OK"
