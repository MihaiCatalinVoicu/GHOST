#!/usr/bin/env bash
# External post-restart healthcheck. A fresh Tor client performs a read-only gRPC status call.
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
HOST_DIR="${GHOST_ISSUER_HOST_DIR:?set GHOST_ISSUER_HOST_DIR}"
STATUS="$HOST_DIR/data/external-health.json"
ATTEMPTS="${GHOST_EXTERNAL_HEALTH_ATTEMPTS:-3}"
SLEEP_SECONDS="${GHOST_EXTERNAL_HEALTH_RETRY_SECONDS:-20}"

previous_success=0
previous_errors=0
if [ -f "$STATUS" ]; then
  previous_success="$(sed -n 's/.*"LAST_EXTERNAL_SUCCESS_AT":\([0-9][0-9]*\).*/\1/p' "$STATUS")"
  previous_errors="$(sed -n 's/.*"EXTERNAL_ERRORS_CONSECUTIVE":\([0-9][0-9]*\).*/\1/p' "$STATUS")"
  previous_success="${previous_success:-0}"
  previous_errors="${previous_errors:-0}"
fi

result=1
attempt=1
while [ "$attempt" -le "$ATTEMPTS" ]; do
  echo "external-healthcheck: attempt $attempt/$ATTEMPTS" >&2
  if (cd "$ROOT/ghost" && timeout 360 cargo test --locked -p ghost-client-net \
      --test live_issuer_health -- --ignored --nocapture); then
    result=0
    break
  fi
  attempt=$((attempt + 1))
  [ "$attempt" -gt "$ATTEMPTS" ] || sleep "$SLEEP_SECONDS"
done

now="$(date +%s)"
if [ "$result" -eq 0 ]; then
  code=REACHABLE
  success="$now"
  errors=0
else
  code=UNREACHABLE
  success="$previous_success"
  errors=$((previous_errors + 1))
fi

tmp="$STATUS.tmp"
printf '{"EXTERNAL_CHECK_GENERATED_AT":%s,"LAST_EXTERNAL_SUCCESS_AT":%s,"EXTERNAL_ERRORS_CONSECUTIVE":%s,"EXTERNAL_ONION_GRPC":"%s"}\n' \
  "$now" "$success" "$errors" "$code" > "$tmp"
mv "$tmp" "$STATUS"
exit "$result"
