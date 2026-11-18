#!/usr/bin/env bash
# Functional tests for external-healthcheck.sh with a fake cargo; no network or Docker access.
set -euo pipefail

root="$(cd "$(dirname "$0")" && pwd)"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
mkdir -p "$tmp/bin" "$tmp/host/data"
cat > "$tmp/bin/cargo" <<'SH'
#!/usr/bin/env bash
set -eu
n=0
[ ! -f "$FAKE_CARGO_COUNT" ] || n="$(cat "$FAKE_CARGO_COUNT")"
n=$((n + 1))
echo "$n" > "$FAKE_CARGO_COUNT"
if [ "${FAKE_CARGO_FAIL_ALL:-0}" = 1 ]; then exit 1; fi
[ "$n" -lt 3 ] && exit 1
exit 0
SH
chmod +x "$tmp/bin/cargo"
export PATH="$tmp/bin:$PATH" FAKE_CARGO_COUNT="$tmp/cargo.count"
export GHOST_ISSUER_HOST_DIR="$tmp/host" GHOST_EXTERNAL_HEALTH_RETRY_SECONDS=0

# Two failures followed by success: bounded retry, fresh success timestamp and reset counter.
GHOST_EXTERNAL_HEALTH_ATTEMPTS=3 bash "$root/external-healthcheck.sh" >/dev/null 2>&1
[ "$(cat "$tmp/cargo.count")" -eq 3 ]
grep -q '"EXTERNAL_ERRORS_CONSECUTIVE":0' "$tmp/host/data/external-health.json"
grep -q '"EXTERNAL_ONION_GRPC":"REACHABLE"' "$tmp/host/data/external-health.json"

# Persistent failure keeps the previous success and increments the consecutive counter.
success="$(sed -n 's/.*"LAST_EXTERNAL_SUCCESS_AT":\([0-9][0-9]*\).*/\1/p' "$tmp/host/data/external-health.json")"
rm -f "$tmp/cargo.count"
set +e
FAKE_CARGO_FAIL_ALL=1 GHOST_EXTERNAL_HEALTH_ATTEMPTS=2 \
  bash "$root/external-healthcheck.sh" >/dev/null 2>&1
code=$?
set -e
[ "$code" -eq 1 ]
[ "$(cat "$tmp/cargo.count")" -eq 2 ]
grep -q '"LAST_EXTERNAL_SUCCESS_AT":'"$success" "$tmp/host/data/external-health.json"
grep -q '"EXTERNAL_ERRORS_CONSECUTIVE":1' "$tmp/host/data/external-health.json"
grep -q '"EXTERNAL_ONION_GRPC":"UNREACHABLE"' "$tmp/host/data/external-health.json"
echo "external-healthcheck test: OK"
