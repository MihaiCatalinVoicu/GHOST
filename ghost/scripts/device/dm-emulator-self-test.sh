#!/usr/bin/env bash
# Self-test of scripts/device/dm-emulator-run.sh (Phase 9 design §15.9; slice S12): the run script
# against test-harness/device/fake-emulator-adb, and its output through
# scripts/gates/dm-emulator-check.sh, the way dm-emulator.yml chains them. An honest emulator is
# green; a crashed suite, an emulator that installs nothing and one of another API level are red at
# the check, whatever the run script's own status; a run without the fixture's commit is refused.
set -uo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GHOST="$(cd "$DIR/../.." && pwd)"
FAKE="$GHOST/test-harness/device/fake-emulator-adb"
CASES="$GHOST/test-harness/gates/dm-emulator/cases.txt"
rc=0
ok() { echo "self-test ok: dm-emulator-run $1"; }
bad() { echo "SELF-TEST FAIL: dm-emulator-run $1" >&2; rc=1; }

# The build outputs the run script installs; the fake adb never reads them.
android="$(mktemp -d)"
for apk in crypto-bridge/build/outputs/apk/androidTest/debug/crypto-bridge-debug-androidTest.apk \
           messaging/build/outputs/apk/androidTest/debug/messaging-debug-androidTest.apk \
           app/build/outputs/apk/release/app-release.apk \
           app/build/outputs/apk/androidTest/release/app-release-androidTest.apk; do
  mkdir -p "$android/$(dirname "$apk")"
  printf 'PK' > "$android/$apk"
done

run() { # bug api-reported api-asked -> run status in $run_rc, check status in $check_rc, check output in $check_out
  local out
  out="$(mktemp -d)"
  env GHOST_ADB="$FAKE" GHOST_ANDROID="$android" GHOST_DM_COMMIT=0123abc FAKE_EMU_BUG="$1" FAKE_EMU_API="$2" \
    bash "$DIR/dm-emulator-run.sh" "$3" "$out" > /dev/null 2>&1
  run_rc=$?
  check_out="$(GHOST_DM_EQUIVALENCE_CASES="$CASES" bash "$GHOST/scripts/gates/dm-emulator-check.sh" "$out" "$3" 2>&1)"
  check_rc=$?
  rm -rf "$out"
}

run "" 35 35
if [ "$run_rc" = 0 ] && [ "$check_rc" = 0 ]; then ok "and the check pass an honest emulator"; else bad "fails an honest emulator: $check_out"; fi
run crash 35 35
if [ "$run_rc" != 0 ] && [ "$check_rc" != 0 ] && grep -qF crashed <<<"$check_out"; then ok "reports a crashed suite, and the check fails it"; else bad "passes a crashed suite"; fi
run noinstall 35 35
if [ "$run_rc" != 0 ] && [ "$check_rc" != 0 ] && grep -qF "not run" <<<"$check_out"; then ok "reports an emulator that installs nothing as not run"; else bad "passes an emulator that installs nothing"; fi
run "" 34 35
if [ "$run_rc" != 0 ] && [ "$check_rc" != 0 ] && grep -qF "reported API '34'" <<<"$check_out"; then ok "refuses an emulator of another API level"; else bad "accepts an emulator of another API level"; fi
if env GHOST_ADB="$FAKE" GHOST_ANDROID="$android" bash "$DIR/dm-emulator-run.sh" 35 "$(mktemp -d)" > /dev/null 2>&1; then
  bad "runs without the commit the host fixture was recorded for"
else
  ok "refuses to run without the host fixture's commit"
fi
rm -rf "$android"
exit $rc
