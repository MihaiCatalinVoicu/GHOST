#!/usr/bin/env bash
# The local media exit gate (Phase 11 design faza11-media.md §15.3, §15.6, §15.9, §16.2; slice S9) —
# the shard-for-shard local equivalent of the `media-exit-gate.yml` CI job, per the owner's
# CI-local rule (the KVM runner and the CI quota are the owner's Q32 items; until they exist this
# script IS the job's content, run on the owner's Windows machine and recorded as local slice
# evidence, never gate evidence, D23):
#
#   media-exit-gate.sh shard <1..8>   one crash-enumeration shard (≤ 180 min each, §15.3's split):
#                                     the SCN-M scenarios' per-statement/per-file-op enumeration and
#                                     the seeded worlds, filtered to the media suites through
#                                     `-Dghost.media.shard=<n> -Dghost.media.shards=8`;
#   media-exit-gate.sh world          the gate-scale privacy world in its own step (≤ 240 min,
#                                     N = 300, 28 days, 5 seed pairs, `-Dghost.media.privacy=gate`):
#                                     JM1–JM7, NI-M1–NI-M7, the T25-media suite and the seizure
#                                     check, written to the media report;
#   media-exit-gate.sh mutants        the 43 JVM/Rust mutants (`MediaMutantDetectionTest` and
#                                     `scripts/ci/media-mutants.sh`), their close-out appended to
#                                     the media report;
#   media-exit-gate.sh check          `media-report-check.sh` (G-M9) on the report;
#   media-exit-gate.sh all            shards 1..8 (sequentially — the host is one machine), then
#                                     world, mutants, check.
#
# Every gradle invocation is isolated (`--no-daemon`, one suite filter per invocation, its own log
# under build/reports/media/logs/) and run under nohup+poll so an interrupted shell never leaves a
# JVM half-started. Environment: ANDROID_HOME and JAVA_HOME default to this machine's installed
# SDK/JDK; the host library defaults to target/release/ghost_dm_host.dll (build it with
# `cargo build -p ghost-dm-host --release --locked`); the heap to 4g (the design's §15.1 budget).
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
ANDROID_DIR="$ROOT/android"
export ANDROID_HOME="${ANDROID_HOME:-C:\\Users\\mihai\\AppData\\Local\\Android\\Sdk}"
export JAVA_HOME="${JAVA_HOME:-C:\\Program Files\\Microsoft\\jdk-17.0.20.101-hotspot\\}"
DM_NATIVE="${GHOST_DM_NATIVE:-$ROOT/target/release/ghost_dm_host.dll}"
DM_HEAP="${GHOST_DM_HEAP:-4g}"
REPORT="${GHOST_MEDIA_REPORT:-$ANDROID_DIR/messaging/build/reports/media/exit.txt}"
LOG_DIR="${GHOST_MEDIA_LOG_DIR:-$ANDROID_DIR/messaging/build/reports/media/logs}"
export LC_ALL=C.UTF-8

usage() {
  echo "usage: media-exit-gate.sh shard <1..8>|world|mutants|check|all" >&2
  exit 2
}
cmd="${1:-}"
[ -n "$cmd" ] || usage
shard=""
if [ "$cmd" = shard ]; then
  shard="${2:-}"
  case "$shard" in
    1|2|3|4|5|6|7|8) ;;
    *) usage ;;
  esac
fi

[ -f "$DM_NATIVE" ] || { echo "media-exit-gate: the host library $DM_NATIVE is missing (cargo build -p ghost-dm-host --release --locked)" >&2; exit 2; }
mkdir -p "$LOG_DIR"

# nohup+poll: start the command detached, then wait with a heartbeat so a stalled JVM is visible
# in the log's directory long before anyone misses it.
run_isolated() { # $1 = log name, rest = command
  local log="$LOG_DIR/$1.log"
  shift
  echo "[media-exit-gate] $* (log: $log)"
  nohup "$@" > "$log" 2>&1 &
  local pid=$!
  while kill -0 "$pid" 2>/dev/null; do sleep 15; done
  wait "$pid"
  local rc=$?
  if [ "$rc" -ne 0 ]; then
    echo "[media-exit-gate] FAILED (rc=$rc): tail of $log:" >&2
    tail -30 "$log" >&2
  fi
  return "$rc"
}

gradle_media() { # $1 = log name, rest = extra args
  local log="$1"
  shift
  ( cd "$ANDROID_DIR" && run_isolated "$log" ./gradlew --no-daemon :messaging:testDebugUnitTest --rerun "$@" \
      -Dghost.dm.native="$DM_NATIVE" -Dghost.dm.heap="$DM_HEAP" -Dghost.media.report="$REPORT" )
}

case "$cmd" in
  shard)
    gradle_media "shard-$shard" \
      --tests 'org.ghost.messaging.media.*' \
      -Dghost.media.shard="$shard" -Dghost.media.shards=8
    ;;
  world)
    gradle_media world \
      --tests 'org.ghost.messaging.media.MediaPrivacyWorldTest' \
      --tests 'org.ghost.messaging.media.MediaEphemeralTest' \
      -Dghost.media.privacy=gate
    ;;
  mutants)
    rc=0
    gradle_media mutants-jvm --tests 'org.ghost.messaging.media.MediaMutantDetectionTest' || rc=1
    # The Rust half of the 43 (the S1 crate's patches; the design's media_mutants). Its line is
    # `media S1 mutants:` — the report's `media mutants:` line is the JVM suites' close-out of
    # the design's 43 (§15.9's homes), which the Rust kills feed through MediaMutantDetectionTest's
    # registration, not by counting patches.
    ( cd "$ROOT" && MEDIA_MUTANTS_LOG_DIR="$LOG_DIR" bash scripts/ci/media-mutants.sh ) || rc=1
    exit "$rc"
    ;;
  check)
    bash "$ROOT/scripts/gates/media-report-check.sh" "$REPORT" gate
    ;;
  all)
    rc=0
    for s in 1 2 3 4 5 6 7 8; do "$0" shard "$s" || rc=1; done
    "$0" world || rc=1
    "$0" mutants || rc=1
    "$0" check || rc=1
    exit "$rc"
    ;;
  *) usage ;;
esac
