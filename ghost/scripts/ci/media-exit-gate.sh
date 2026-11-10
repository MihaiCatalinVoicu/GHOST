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

gradle_media() { # $1 = log name, $2 = module (e.g. :messaging), rest = extra args
  local log="$1" module="$2"
  shift 2
  ( cd "$ANDROID_DIR" && run_isolated "$log" ./gradlew --no-daemon "$module":testDebugUnitTest --rerun "$@" \
      -Dghost.dm.native="$DM_NATIVE" -Dghost.dm.heap="$DM_HEAP" -Dghost.media.report="$REPORT" )
}

case "$cmd" in
  shard)
    rc=0
    # Only the SCN scenario classes: the world/mutants/twins have their own steps, and rerunning
    # them per shard would multiply the gate's dominant cost. The shard properties are read by
    # MediaScenarios (scenario index i runs in shard i % shards + 1); with six scenarios and eight
    # shards, shards 7-8 take the seeded worlds when that suite lands (§15.3's remaining pieces).
    gradle_media "shard-$shard" :messaging \
      --tests 'org.ghost.messaging.media.MediaSendScenarioTest' \
      --tests 'org.ghost.messaging.media.MediaUploadScenarioTest' \
      --tests 'org.ghost.messaging.media.MediaReceiveScenarioTest' \
      --tests 'org.ghost.messaging.media.MediaViewOnceScenarioTest' \
      --tests 'org.ghost.messaging.media.MediaViewOnceSenderTest' \
      --tests 'org.ghost.messaging.media.MediaExpiryScenarioTest' \
      -Dghost.media.shard="$shard" -Dghost.media.shards=8 || rc=1
    # SCN-ME's storage half (:media) and SCN-MF's migration enumeration (:storage) run once —
    # in shard 1; the media report collects their close-out lines like the messaging ones.
    if [ "$shard" = 1 ]; then
      gradle_media "shard-1-media-store" :media --tests 'org.ghost.media.store.MediaStoreScenarioTest' || rc=1
      gradle_media "shard-1-migration" :storage --tests 'org.ghost.storage.Migration8Test' || rc=1
    fi
    # §15.4's seeded worlds take shard 7 (MediaScenarios.owns(6)): the gate's 1 000 worlds.
    if [ "$shard" = 7 ]; then
      gradle_media "shard-7-seeded" :messaging \
        --tests 'org.ghost.messaging.media.MediaSeededWorldsTest' \
        -Dghost.media.seededWorlds=1000 || rc=1
    fi
    ;;
  world)
    gradle_media world :messaging \
      --tests 'org.ghost.messaging.media.MediaPrivacyWorldTest' \
      --tests 'org.ghost.messaging.media.MediaEphemeralTest' \
      -Dghost.media.privacy=gate
    ;;
  mutants)
    rc=0
    gradle_media mutants-jvm :messaging --tests 'org.ghost.messaging.media.MediaMutantDetectionTest' || rc=1
    # The Rust half of the 43 (the S1 crate's patches; the design's media_mutants). Its line is
    # `media S1 mutants:` — appended to the report by the script itself when GHOST_MEDIA_REPORT is
    # set. The half needs a working cargo + unix (the patches and /dev/urandom-dependent tests do
    # not run on a bare Windows shell: the first local gate run gave 'cargo exited 127' for every
    # mutant); on this host that means the ghost-runner WSL distro and its synced tree.
    if command -v cargo >/dev/null 2>&1; then
      ( cd "$ROOT" && GHOST_MEDIA_REPORT="$REPORT" MEDIA_MUTANTS_LOG_DIR="$LOG_DIR" bash scripts/ci/media-mutants.sh ) || rc=1
    elif command -v wsl.exe >/dev/null 2>&1; then
      # The report lives on the Windows D: drive (not visible from the distro), so the S1
      # close-out is captured from stdout and appended here.
      if MSYS_NO_PATHCONV=1 wsl.exe -d ghost-runner -u runner -- bash -lc \
        "cd /srv/ghost-src/ghost && MEDIA_MUTANTS_LOG_DIR=/tmp/mmut-logs bash scripts/ci/media-mutants.sh" \
        > "$LOG_DIR/mutants-rust.out" 2>&1; then
        grep -m1 '^media S1 mutants:' "$LOG_DIR/mutants-rust.out" >> "$REPORT" || \
          { echo "[media-exit-gate] the Rust half printed no S1 close-out" >&2; rc=1; }
      else
        tail -5 "$LOG_DIR/mutants-rust.out" >&2; rc=1
      fi
    else
      echo "[media-exit-gate] no cargo and no WSL for the Rust mutant half" >&2; rc=1
    fi
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
