#!/usr/bin/env bash
# messaging-exit-gate.sh — the local equivalent of the legacy
# .github/workflows/messaging-exit-gate.yml (Phase 9 design §16.2's DM exit gate; ADR-58: CI is
# local). The gate's steps, unchanged: the ghost-dm-host build WITHOUT the provenance feature
# (this gate has no T35), G-R6 and G-M6 over the closed JNI surfaces of that build, then the DM
# exit-gate harness — the whole :messaging suite with crash injection at every event, 64 seeds,
# privacy off — and dm-report-check.sh … gate over report.txt.
#
# Usage: messaging-exit-gate.sh [--work <dir>] [--native <library>]
# --native skips the host build (a provenance build must NOT be passed here: this gate wants the
# plain one).
set -uo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GHOST="$(cd "$DIR/../../" && pwd)"
ANDROID="$GHOST/android"
WORK="$GHOST/t2-reports/messaging-exit-gate"
NATIVE=""
while [ $# -gt 0 ]; do
  case "$1" in
    --work) WORK="$2"; shift 2 ;;
    --native) NATIVE="$2"; shift 2 ;;
    *) echo "messaging-exit-gate: unknown argument: $1" >&2; exit 2 ;;
  esac
done
mkdir -p "$WORK"

if [ -z "$NATIVE" ]; then
  ( cd "$GHOST" && \
    cargo clean -p libcrux-ml-kem -p libcrux-sha3 -p libcrux-intrinsics -p libcrux-aes --release 2>/dev/null || true; \
    cargo build -p ghost-dm-host --release --locked \
      --message-format=json-render-diagnostics > "$WORK/dm-host-build.json" ) || \
    { echo "messaging-exit-gate: the host build failed" >&2; exit 1; }
  bash "$GHOST/scripts/gates/libcrux-portable.sh" --with-aes --json "$WORK/dm-host-build.json" || \
    { echo "messaging-exit-gate: libcrux-portable.sh refused the host build" >&2; exit 1; }
  case "$(uname -s)" in
    *NT*|MINGW*|CYGWIN*) NATIVE="$GHOST/target/release/ghost_dm_host.dll" ;;
    *)                   NATIVE="$GHOST/target/release/libghost_dm_host.so" ;;
  esac
fi
[ -f "$NATIVE" ] || { echo "messaging-exit-gate: no host library at $NATIVE" >&2; exit 2; }

bash "$GHOST/scripts/gates/dm-jni-surface.sh" --test "$NATIVE" || exit 1
bash "$GHOST/scripts/gates/mls-jni-surface.sh" --test "$NATIVE" || exit 1

( cd "$ANDROID" && ./gradlew --no-daemon :messaging:testDebugUnitTest --rerun \
    -Dghost.dm.native="$NATIVE" -Dghost.dm.crash=full -Dghost.dm.seeds=64 -Dghost.dm.privacy=off ) \
  > "$WORK/messaging-exit-gate.log" 2>&1
rc=$?
tail -5 "$WORK/messaging-exit-gate.log"
if [ "$rc" -ne 0 ]; then
  echo "messaging-exit-gate: FAIL (harness; log: $WORK/messaging-exit-gate.log)" >&2
  exit 1
fi

REPORT="$ANDROID/messaging/build/reports/dm/report.txt"
bash "$GHOST/scripts/gates/dm-report-check.sh" "$REPORT" gate || rc=1
if [ "$rc" = 0 ]; then
  echo "messaging-exit-gate: PASS (report: $REPORT)"
else
  echo "messaging-exit-gate: FAIL (report check)" >&2
fi
exit "$rc"
