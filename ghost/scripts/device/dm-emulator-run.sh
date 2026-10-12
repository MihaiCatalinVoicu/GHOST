#!/usr/bin/env bash
# Runs the emulator suites of Phase 9 design §15.9 on one booted emulator (slice S12) and writes the
# raw instrumentation output `scripts/gates/dm-emulator-check.sh` reads. `dm-emulator.yml` calls it
# as the `script` of `reactivecircus/android-emulator-runner`, once per API level.
#
#   dm-emulator-run.sh <api> <out-dir>
#
# Writes `<out-dir>/api<api>/`:
#   device.txt         the emulator's `sdk=` and `abi=` (the check refuses another API level or ABI);
#   crypto-bridge.txt  the host/Android equivalence test on the x86_64 **test library**
#                      (§15.9 item 7), with the commit the host fixture was recorded for;
#   messaging.txt      `DeviceGateSuite`: SQLCipher v3 -> current, SCN-A, SCN-B, SCN-F with T25's
#                      WAL, the alarm scheduled and cancelled, SCN-D with the logcat scan (§15.9
#                      items 2, 4, 5 and 6);
#   app-smoke.txt      the release smoke test in the R8-shrunk release APK (§15.9 item 3).
# Each suite file is the complete `am instrument -r -w` output, so the check sees the result code
# and the runner's summary line as the device printed them. Nothing here holds message content: the
# suites print report lines and test names, and the canary scan prints a count.
#
# Environment:
#   GHOST_DM_COMMIT  required: the commit the host fixture was recorded for (the equivalence test
#                    refuses a fixture of another commit);
#   GHOST_ADB        the adb to use (default: adb);
#   GHOST_ANDROID    the Android project whose build outputs are installed (default: <ghost>/android).
#
# Exit status: 0 when every suite finished RESULT_OK, 1 otherwise, 2 on a usage error. **The check
# is the judge**, not this status: it also requires the report lines and the test counts, and a
# missing file is "not run".
set -uo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
api="${1:-}"
out="${2:-}"
[ -n "$api" ] && [ -n "$out" ] || { echo "usage: dm-emulator-run.sh <api> <out-dir>" >&2; exit 2; }
case "$api" in *[!0-9]*) echo "not an API level: $api" >&2; exit 2 ;; esac
commit="${GHOST_DM_COMMIT:?GHOST_DM_COMMIT must name the commit the host fixture was recorded for}"
adb="${GHOST_ADB:-adb}"
android="${GHOST_ANDROID:-$DIR/../../android}"

dir="$out/api$api"
rm -rf "$dir"
mkdir -p "$dir"
rc=0

"$adb" wait-for-device
sdk="$("$adb" shell getprop ro.build.version.sdk | tr -d '\r')"
abi="$("$adb" shell getprop ro.product.cpu.abi | tr -d '\r')"
printf 'sdk=%s\nabi=%s\n' "$sdk" "$abi" > "$dir/device.txt"
echo "dm-emulator: API $sdk, $abi"
if [ "$sdk" != "$api" ]; then
  echo "dm-emulator: the emulator runs API $sdk, not $api" >&2
  exit 1
fi

install() { # apk...
  local apk
  for apk in "$@"; do
    if [ ! -f "$apk" ]; then
      echo "dm-emulator: $apk was not built" >&2
      return 1
    fi
    # -r replaces, -t allows a test-only package (the androidTest APKs are test-only).
    "$adb" install -r -t "$apk" > /dev/null || { echo "dm-emulator: install failed: $apk" >&2; return 1; }
  done
}

suite() { # name component [-e key value ...] -- apk...
  local name="$1" component="$2" args=() apks=()
  shift 2
  while [ $# -gt 0 ] && [ "$1" != -- ]; do args+=("$1"); shift; done
  shift
  apks=("$@")
  if ! install "${apks[@]}"; then
    rc=1
    return
  fi
  "$adb" shell am instrument -r -w "${args[@]}" "$component" > "$dir/$name.txt" 2>&1
  tr -d '\r' < "$dir/$name.txt" | grep -E '^(dm-|device tests:|INSTRUMENTATION_CODE:|INSTRUMENTATION_RESULT: stream=)' \
    | sed "s/^/dm-emulator: $name: /"
  if ! tr -d '\r' < "$dir/$name.txt" | grep -qx 'INSTRUMENTATION_CODE: -1'; then rc=1; fi
}

suite crypto-bridge org.ghost.crypto.bridge.test/org.ghost.crypto.bridge.device.CryptoBridgeDeviceRunner \
  -e commit "$commit" -- \
  "$android/crypto-bridge/build/outputs/apk/androidTest/debug/crypto-bridge-debug-androidTest.apk"
suite messaging org.ghost.messaging.test/org.ghost.messaging.device.MessagingDeviceRunner -- \
  "$android/messaging/build/outputs/apk/androidTest/debug/messaging-debug-androidTest.apk"
suite app-smoke org.ghost.app.test/org.ghost.app.smoke.AppDeviceRunner -- \
  "$android/app/build/outputs/apk/release/app-release.apk" \
  "$android/app/build/outputs/apk/androidTest/release/app-release-androidTest.apk"
exit $rc
