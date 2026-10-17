#!/usr/bin/env bash
# The local media emulator job (Phase 11 design faza11-media.md §15.7, §15.8, §15.9, §16.2; slice
# S9) — the local equivalent of the `media-emulator.yml` CI job, per the owner's CI-local rule.
# On the CI runner this job needs KVM; locally it drives the owner's Windows WHPX emulator, exactly
# as Phase 9's device suites ran (F9 §22.32), and its evidence is local slice evidence, never gate
# evidence (D23).
#
#   media-emulator.sh api <29|35|37>   boot the x86_64 image (API 29 with `-feature
#                                      GLESDynamicVersion`, S0-1), run the instrumented media suites
#                                      (the §15.7 corpus through sendMedia/receive with the ExifTool
#                                      oracle on the host, §15.8's no-plaintext-cache scans, the
#                                      host-driven restart run), pull the artifacts;
#   media-emulator.sh mutants          the 7 emulator mutants (PM-M12, PM-M18, PM-M21, PM-M23,
#                                      PM-M26, MC-M23, MC-M24), each a source patch applied to a
#                                      fresh install, killed by its named §15.8 check;
#   media-emulator.sh check            `media-report-check.sh --emulator` (G-M9) on the report;
#   media-emulator.sh all              api 29, api 35, api 37, mutants, check.
#
# The committed corpus and its manifest live in `android/media/src/androidTest/assets/corpus/`
# (built once, §15.7 — the generated half is S0a's, the device captures S0b's, both owner-timed);
# ExifTool's production release is pinned by SHA-256 by the owner (S0b), and this script refuses to
# run without the pinned binary on the PATH.
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
ANDROID_DIR="$ROOT/android"
export ANDROID_HOME="${ANDROID_HOME:-C:\\Users\\mihai\\AppData\\Local\\Android\\Sdk}"
export JAVA_HOME="${JAVA_HOME:-C:\\Program Files\\Microsoft\\jdk-17.0.20.101-hotspot\\}"
REPORT="${GHOST_MEDIA_EMULATOR_REPORT:-$ANDROID_DIR/media/build/reports/media/emulator.txt}"
LOG_DIR="${GHOST_MEDIA_EMULATOR_LOG_DIR:-$ANDROID_DIR/media/build/reports/media/logs}"
export LC_ALL=C.UTF-8

usage() {
  echo "usage: media-emulator.sh api <29|35|37>|mutants|check|all" >&2
  exit 2
}
cmd="${1:-}"
[ -n "$cmd" ] || usage
api=""
if [ "$cmd" = api ]; then
  api="${2:-}"
  case "$api" in
    29|35|37) ;;
    *) usage ;;
  esac
fi

ADB="$ANDROID_HOME/platform-tools/adb.exe"
EMULATOR="$ANDROID_HOME/emulator/emulator.exe"
command -v exiftool >/dev/null 2>&1 || { echo "media-emulator: exiftool is not on the PATH (the owner pins the production release by SHA-256, S0b)" >&2; exit 2; }
[ -x "$ADB" ] || { echo "media-emulator: no adb at $ADB (ANDROID_HOME=$ANDROID_HOME)" >&2; exit 2; }
[ -x "$EMULATOR" ] || { echo "media-emulator: no emulator at $EMULATOR (ANDROID_HOME=$ANDROID_HOME)" >&2; exit 2; }
mkdir -p "$LOG_DIR"

# Boot one emulator, run the media instrumented tests against it, pull what §15.8 scans need.
run_api() { # $1 = api level
  local level="$1"
  local boot_args=(-avd "$AVD" -no-snapshot-save -gpu swiftshader_indirect -no-boot-anim)
  [ "$level" = 29 ] && boot_args+=(-feature GLESDynamicVersion)
  echo "[media-emulator] booting $AVD (api $level)"
  nohup "$EMULATOR" "${boot_args[@]}" > "$LOG_DIR/emulator-$level.log" 2>&1 &
  local ep=$!
  # Wait for full boot (sys.boot_completed), polling.
  for _ in $(seq 1 120); do
    [ "$("$ADB" shell getprop sys.boot_completed 2>/dev/null | tr -d '\r')" = 1 ] && break
    sleep 5
  done
  [ "$("$ADB" shell getprop sys.boot_completed 2>/dev/null | tr -d '\r')" = 1 ] || {
    echo "[media-emulator] $AVD did not boot in 10 minutes" >&2; kill "$ep" 2>/dev/null; return 1; }
  ( cd "$ANDROID_DIR" && ./gradlew --no-daemon :media:connectedDebugAndroidTest \
      -Pandroid.testInstrumentationRunnerArguments.class=org.ghost.media.MediaCorpusTest,org.ghost.media.MediaCacheTest \
      > "$LOG_DIR/instrumented-$level.log" 2>&1 )
  local rc=$?
  "$ADB" pull /data/local/tmp/media-report "$LOG_DIR/media-report-$level" >/dev/null 2>&1 || true
  "$ADB" emu kill >/dev/null 2>&1 || true
  wait "$ep" 2>/dev/null || true
  return "$rc"
}

case "$cmd" in
  api) run_api "$api" ;;
  mutants)
    # The 7 emulator mutants of §15.9: each patch breaks one invariant; its killer is the named
    # §15.8 instrumentation check. The patch set lives beside this script
    # (emulator-mutants/<id>.patch over android/); the runner applies, installs, runs the killer
    # suite, reverts — the media-mutants.sh discipline.
    rc=0
    for p in "$ROOT/scripts/ci/emulator-mutants"/*.patch; do
      [ -e "$p" ] || { echo "[media-emulator] no emulator mutant patches (emulator-mutants/)" >&2; exit 2; }
      id="$(basename "$p" .patch)"
      echo "[media-emulator] mutant $id"
      ( cd "$ROOT" && patch -p1 -s < "$p" ) || { echo "[media-emulator] $id: does not apply" >&2; rc=2; continue; }
      for level in 29 35 37; do
        run_api "$level" || { echo "[media-emulator] $id: killed on api $level (expected: its named check)"; continue; }
        echo "[media-emulator] $id SURVIVED on api $level" >&2; rc=1
      done
      ( cd "$ROOT" && patch -p1 -R -s < "$p" ) || { echo "[media-emulator] $id: does not revert" >&2; rc=2; }
    done
    exit "$rc"
    ;;
  check)
    bash "$ROOT/scripts/gates/media-report-check.sh" --emulator "$REPORT"
    ;;
  all)
    rc=0
    for level in 29 35 37; do run_api "$level" || rc=1; done
    "$0" mutants || rc=1
    "$0" check || rc=1
    exit "$rc"
    ;;
  *) usage ;;
esac
