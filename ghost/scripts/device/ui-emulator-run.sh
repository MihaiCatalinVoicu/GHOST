#!/usr/bin/env bash
# Runs the UI emulator suites of Phase 13 design faza13-ux.md §12.3 on one booted emulator and
# writes the raw instrumentation output `scripts/gates/ui-emulator-check.sh` reads.
# `ui-emulator.yml` calls it on the ghost-runner machines (and the owner calls it locally for
# the signed runs Q44 accepts); the judge is always ui-emulator-check.sh, never this status.
#
#   ui-emulator-run.sh <api> <out-dir>
#
# Writes `<out-dir>/api<api>/`:
#   device.txt         the emulator's `sdk=` and `abi=` (the check refuses another level or ABI);
#   suite-<name>.txt   the complete `am instrument -r -w` output of each suite the counts pin
#                      names (`test-harness/gates/ui-emulator-counts.txt`), so the check sees
#                      the result code and the runner's summary line as the device printed them.
#
# The suite list is the counts pin — a suite lands with its count line and its run block here in
# the same commit (S1's smoke first). Until then the pin is empty and this script has nothing
# to run: it says so and exits 1 (not run is red), it does not pretend a pass.
#
# Environment:
#   GHOST_ADB        the adb to use (default: adb);
#   GHOST_ANDROID    the Android project whose gate APKs are installed (default: <ghost>/android).
#
# Exit status: 0 when every suite finished RESULT_OK, 1 otherwise, 2 on a usage error.
set -uo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GHOST_ROOT="${GHOST_ROOT:-$(cd "$DIR/../.." && pwd)}"
api="${1:-}"
out="${2:-}"
[ -n "$api" ] && [ -n "$out" ] || { echo "usage: ui-emulator-run.sh <api> <out-dir>" >&2; exit 2; }
case "$api" in *[!0-9]*) echo "not an API level: $api" >&2; exit 2 ;; esac
adb="${GHOST_ADB:-adb}"
android="${GHOST_ANDROID:-$DIR/../../android}"
counts="$GHOST_ROOT/test-harness/gates/ui-emulator-counts.txt"

suites=()
while IFS=' ' read -r name count; do
  case "$name" in ''|\#*) continue ;; esac
  suites+=("$name")
done < "$counts"
if [ "${#suites[@]}" -eq 0 ]; then
  echo "ui-emulator-run: the counts pin names no suites (S0b: none have landed; not run is red)" >&2
  exit 1
fi

dir="$out/api$api"
rm -rf "$dir"
mkdir -p "$dir"
"$adb" shell getprop ro.build.version.sdk | sed 's/^/sdk=/' > "$dir/device.txt"
"$adb" shell getprop ro.product.cpu.abi | sed 's/^/abi=/' >> "$dir/device.txt"

# The gate variant and its instrumentation, built by the workflow's build step (or by
# `./gradlew :app:assembleGate :app-uitest:assembleGate` in a local run — the test module's gate
# build type wires its APK at :app's gate variant, org.ghost.app.gate, the process Q25 fixes).
app_apk=$(find "$android/app/build/outputs/apk/gate" -name '*.apk' 2>/dev/null | head -1)
test_apk=$(find "$android/app-uitest/build/outputs/apk/gate" -name '*.apk' 2>/dev/null | head -1)
[ -n "$app_apk" ] && [ -n "$test_apk" ] || {
  echo "ui-emulator-run: the gate APKs are missing (build :app:assembleGate :app:assembleGateAndroidTest first)" >&2
  exit 1
}

"$adb" install -r "$app_apk" >/dev/null
"$adb" install -r "$test_apk" >/dev/null
# The instrumentation runner of Q25's AndroidJUnitRunner; a suite that needs another names it
# in its own run block.
runner="androidx.test.runner.AndroidJUnitRunner"

# The S1 smoke suite: GateSmokeTest in the gate process (Q25). The instrumentation component is
# the test module's package (org.ghost.uitest — its applicationId) over the shared runner; the
# gate build type of the module wires its target at org.ghost.app.gate.
run_smoke() { # $1 = adb, $2 = out file, $3 = runner
  "$1" shell am instrument -r -w -e class org.ghost.uitest.GateSmokeTest \
    "org.ghost.uitest/$3" > "$2" 2>&1
  tr -d '\r' < "$2" | grep -qx 'INSTRUMENTATION_CODE: -1'
}

# The S9 ATF suite (design §9.2, ADR-57 item 7): AccessibilityValidator over the live semantics
# tree of the channel journey - zero errors is the requirement, over the same runner.
run_atf() { # $1 = adb, $2 = out file, $3 = runner
  "$1" shell am instrument -r -w -e class org.ghost.uitest.AtfSuite \
    "org.ghost.uitest/$3" > "$2" 2>&1
  tr -d '\r' < "$2" | grep -qx 'INSTRUMENTATION_CODE: -1'
}

# The T20 inventory suite (Appendix B.2): the sandbox file floor after a launch, over the
# same runner. T20's baseline is a fresh install: clear the target's data before the run.
run_inventory() { # $1 = adb, $2 = out file, $3 = runner
  "$1" shell pm clear org.ghost.app.gate >/dev/null 2>&1 || true
  sleep 3 # the clear settles the package state; am instrument right behind it races a bad userId
  "$1" shell am instrument -r -w -e class org.ghost.uitest.InventorySuite \
    "org.ghost.uitest/$3" > "$2" 2>&1
  tr -d '\r' < "$2" | grep -qx 'INSTRUMENTATION_CODE: -1'
}

# The S9 accessibility suite (design §9.2-§9.4): font scale 2.0 composition and the ro/en label
# twins at runtime, over the same runner. The yardstick is a device condition: the block puts
# the device at font_scale 2.0 for the suite and restores it afterwards.
run_accessibility() { # $1 = adb, $2 = out file, $3 = runner
  local scale
  scale=$("$1" shell settings get system font_scale | tr -d '\r')
  "$1" shell settings put system font_scale 2.0 >/dev/null
  "$1" shell am instrument -r -w -e class org.ghost.uitest.AccessibilitySuite \
    "org.ghost.uitest/$3" > "$2" 2>&1
  "$1" shell settings put system font_scale "${scale:-1.0}" >/dev/null
  tr -d '\r' < "$2" | grep -qx 'INSTRUMENTATION_CODE: -1'
}

rc=0
for name in "${suites[@]}"; do
  # Each suite's run block lands with the suite itself; until it does, the suite name in the
  # pin with no block here is a build error, not a silent skip.
  if ! declare -f "run_$name" >/dev/null 2>&1; then
    echo "ui-emulator-run: suite $name has no run block (land it with the suite)" >&2
    rc=1
    continue
  fi
  "run_$name" "$adb" "$dir/suite-$name.txt" "$runner" || rc=1
done
exit "$rc"
