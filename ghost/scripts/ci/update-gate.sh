#!/usr/bin/env bash
# The local update gate (Phase 14 design faza14-distribution.md §12.1 G-D7, §12.2; slice S6f) —
# the shard-for-shard local equivalent of the future `update-gate.yml` CI job, per the owner's
# CI-local rule (this script IS the job's content on the owner's Windows machine until the CI
# job exists, run as local slice evidence, never gate evidence, D23):
#
#   update-gate.sh pr       the default `:update:testDebugUnitTest` (the PR-scale UpdateWorld,
#                           the mutants' kill suite, the NI-U twins, the named worlds): writes
#                           android/update/build/update-mutants/report.txt;
#   update-gate.sh gate     the gate job's run, `-Dghost.update.gate=1` (50 clients x 120 days,
#                           the named worlds and the twins sampled inside the run — the drill
#                           lines G-D7's `gate` kind requires), same fragment;
#   update-gate.sh check <gate|pr>
#                           `update-report-check.sh` (G-D7) on the fragment;
#   update-gate.sh all      pr, then check pr.
#
# Environment: ANDROID_HOME and JAVA_HOME default to this machine's installed SDK/JDK; the host
# library defaults to target/release/ghost_dm_host.dll (build it with
# `cargo build -p ghost-dm-host --release --locked`).
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
ANDROID_DIR="$ROOT/android"
export ANDROID_HOME="${ANDROID_HOME:-C:\\Users\\mihai\\AppData\\Local\\Android\\Sdk}"
export JAVA_HOME="${JAVA_HOME:-C:\\Program Files\\Microsoft\\jdk-17.0.20.101-hotspot\\}"
DM_NATIVE="${GHOST_NET_NATIVE:-$ROOT/target/release/ghost_dm_host.dll}"
REPORT="${GHOST_UPDATE_REPORT:-$ANDROID_DIR/update/build/update-mutants/report.txt}"
export LC_ALL=C.UTF-8

usage() {
  echo "usage: update-gate.sh pr|gate|check <gate|pr>|all" >&2
  exit 2
}
cmd="${1:-}"
[ -n "$cmd" ] || usage
kind=""
if [ "$cmd" = check ]; then
  kind="${2:-}"
  case "$kind" in gate|pr) ;; *) usage ;; esac
fi

[ -f "$DM_NATIVE" ] || { echo "update-gate: the host library $DM_NATIVE is missing (cargo build -p ghost-dm-host --release --locked)" >&2; exit 2; }

run_suite() { # $1 = log name, rest = extra -D args
  local log="$1"
  shift
  mkdir -p "$ANDROID_DIR/build"
  echo "[update-gate] ./gradlew --no-daemon :update:testDebugUnitTest -Dghost.net.native=$DM_NATIVE $* (log: $ANDROID_DIR/build/update-gate-$log.log)"
  ( cd "$ANDROID_DIR" && ./gradlew --no-daemon :update:testDebugUnitTest \
      -Dghost.net.native="$DM_NATIVE" "$@" ) > "$ANDROID_DIR/build/update-gate-$log.log" 2>&1
  local rc=$?
  if [ "$rc" -ne 0 ]; then
    echo "[update-gate] FAILED (rc=$rc): tail of the log:" >&2
    tail -30 "$ANDROID_DIR/build/update-gate-$log.log" >&2
  fi
  return "$rc"
}

case "$cmd" in
  pr)
    run_suite pr
    ;;
  gate)
    run_suite gate -Dghost.update.gate=1
    ;;
  check)
    bash "$ROOT/scripts/gates/update-report-check.sh" "$REPORT" "$kind"
    ;;
  all)
    rc=0
    "$0" pr || rc=1
    "$0" check pr || rc=1
    exit "$rc"
    ;;
  *) usage ;;
esac
