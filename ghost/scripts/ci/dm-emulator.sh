#!/usr/bin/env bash
# dm-emulator.sh — the local equivalent of the legacy .github/workflows/dm-emulator.yml (Phase 9
# design §15.9/§15.10; ADR-58: CI is local, the owner's Windows WHPX emulator stands in for the
# runner's KVM, exactly as media-emulator.sh does). The workflow's steps, condensed: build the
# shipped libraries and G-R6/G-M6 on them, the x86_64 test library and the host library with
# G-R6 --test, G-R3 over the four builds, the host equivalence fixture for this commit, the
# device suites and the R8-shrunk smoke release with G-DM5 on its mapping — then the emulator
# itself: boot it (like media-emulator.sh boots the owner's emulator), run
# scripts/device/dm-emulator-run.sh and judge the output with dm-emulator-check.sh ("not run"
# is red, like the workflow).
#
# Usage: dm-emulator.sh <api 29|35> [--work <dir>]
#   The emulator is booted here (avd ghost-dm-api<api>, -no-snapshot-save, swiftshader). KVM note:
#   the workflow skipped itself when /dev/kvm was missing; locally a WHPX emulator is expected.
set -uo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GHOST="$(cd "$DIR/../../" && pwd)"
ANDROID="$GHOST/android"
WORK="$GHOST/t2-reports/dm-emulator"
api="${1:-}"; [ $# -gt 0 ] && shift
while [ $# -gt 0 ]; do
  case "$1" in
    --work) WORK="$2"; shift 2 ;;
    *) echo "dm-emulator: unknown argument: $1" >&2; exit 2 ;;
  esac
done
case "$api" in
  29|35) ;;
  *) echo "usage: dm-emulator.sh <api 29|35> [--work <dir>]" >&2; exit 2 ;;
esac
mkdir -p "$WORK/$api"

export ANDROID_HOME="${ANDROID_HOME:-C:\\Users\\mihai\\AppData\\Local\\Android\\Sdk}"
ADB="$ANDROID_HOME/platform-tools/adb.exe"
EMULATOR_BIN="$ANDROID_HOME/emulator/emulator.exe"
NATIVE_TMP="$WORK/$api/native"

# Native half: shipped libraries, the x86_64 test library, the host library, G-R3 over all four.
(
  cd "$GHOST"
  export ANDROID_NDK_HOME="${ANDROID_NDK_HOME:-$ANDROID_SDK_ROOT/ndk/30.0.16248370}"
  for triple in aarch64-linux-android x86_64-linux-android; do
    CARGO_TARGET_DIR=target/android-native cargo clean -p libcrux-ml-kem -p libcrux-sha3 -p libcrux-intrinsics -p libcrux-aes --target "$triple" --release 2>/dev/null || true
  done
  rm -rf "$NATIVE_TMP"; mkdir -p "$NATIVE_TMP"
  bash scripts/build-native.sh "$NATIVE_TMP/native" "$NATIVE_TMP/native.sha256"
  mkdir -p android/network/src/main/jniLibs
  cp -r "$NATIVE_TMP/native/." android/network/src/main/jniLibs/
  bash scripts/gates/dm-jni-surface.sh \
    "$NATIVE_TMP/native/arm64-v8a/libghost_client_net.so" \
    "$NATIVE_TMP/native/x86_64/libghost_client_net.so"
  bash scripts/gates/mls-jni-surface.sh \
    "$NATIVE_TMP/native/arm64-v8a/libghost_client_net.so" \
    "$NATIVE_TMP/native/x86_64/libghost_client_net.so"
  CARGO_TARGET_DIR=target/dm-test-jni cargo clean -p libcrux-ml-kem -p libcrux-sha3 -p libcrux-intrinsics -p libcrux-aes --target x86_64-linux-android --release 2>/dev/null || true
  rm -rf android/crypto-bridge/build/dm-test-jni
  CARGO_TARGET_DIR=target/dm-test-jni cargo ndk -t x86_64 -o android/crypto-bridge/build/dm-test-jni \
    build --release --locked -p ghost-dm-host
  bash scripts/gates/dm-jni-surface.sh --test android/crypto-bridge/build/dm-test-jni/x86_64/libghost_dm_host.so
  bash scripts/gates/mls-jni-surface.sh --test android/crypto-bridge/build/dm-test-jni/x86_64/libghost_dm_host.so
  cargo clean -p libcrux-ml-kem -p libcrux-sha3 -p libcrux-intrinsics -p libcrux-aes --release 2>/dev/null || true
  cargo build -p ghost-dm-host --release --locked
  bash scripts/gates/dm-jni-surface.sh --test "$GHOST/target/release/libghost_dm_host.so"
  bash scripts/gates/mls-jni-surface.sh --test "$GHOST/target/release/libghost_dm_host.so"
  bash scripts/gates/libcrux-portable.sh --with-aes \
    --target-dir target/android-native/aarch64-linux-android/release \
    --target-dir target/android-native/x86_64-linux-android/release \
    --target-dir target/dm-test-jni/x86_64-linux-android/release \
    --target-dir target/release
) > "$WORK/$api/native.log" 2>&1 || { echo "dm-emulator: the native half failed (log: $WORK/$api/native.log)" >&2; exit 1; }

commit="$(git -C "$GHOST" rev-parse HEAD)"
# The host equivalence fixture, recorded for this commit (the workflow's host half).
( cd "$ANDROID" && ./gradlew --no-daemon :crypto-bridge:testDebugUnitTest --rerun \
    --tests 'org.ghost.crypto.bridge.DmEquivalenceHostTest' \
    -Dghost.dm.native="$GHOST/target/release/libghost_dm_host.so" -Dghost.dm.commit="$commit" ) \
  > "$WORK/$api/equivalence.log" 2>&1 || { echo "dm-emulator: the host equivalence run failed" >&2; exit 1; }
fixture="$ANDROID/crypto-bridge/build/dm-equivalence/dm_equivalence_host.txt"
grep -qx "# commit $commit" "$fixture" || { echo "dm-emulator: the fixture is not for $commit" >&2; exit 1; }

# Device suites + the R8-shrunk smoke release, G-DM5 on its mapping.
( cd "$ANDROID" && ./gradlew --no-daemon -Pghost.smoke.release=true \
    :crypto-bridge:assembleDebugAndroidTest :messaging:assembleDebugAndroidTest \
    :app:assembleRelease :app:assembleReleaseAndroidTest && \
  bash ../scripts/gates/apk-no-debug-hooks.sh app/build/outputs/mapping/release/mapping.txt ) \
  > "$WORK/$api/assemble.log" 2>&1 || { echo "dm-emulator: the device build failed (log: $WORK/$api/assemble.log)" >&2; exit 1; }

# The emulator itself: boot, run the suites, kill. (The runner half of the workflow.)
AVD="ghost-dm-api$api"
boot_args=(-avd "$AVD" -no-snapshot-save -gpu swiftshader_indirect -no-boot-anim -noaudio)
[ "$api" = 29 ] && boot_args+=(-feature GLESDynamicVersion)
nohup "$EMULATOR_BIN" "${boot_args[@]}" > "$WORK/$api/emulator.log" 2>&1 &
ep=$!
for _ in $(seq 1 120); do
  [ "$("$ADB" shell getprop sys.boot_completed 2>/dev/null | tr -d '\r')" = 1 ] && break
  sleep 5
done
[ "$("$ADB" shell getprop sys.boot_completed 2>/dev/null | tr -d '\r')" = 1 ] || {
  echo "dm-emulator: $AVD did not boot in 10 minutes" >&2; kill "$ep" 2>/dev/null; exit 1; }

GHOST_DM_COMMIT="$commit" GHOST_ADB="$ADB" \
  bash "$GHOST/scripts/device/dm-emulator-run.sh" "$api" "$WORK/$api"
rc=$?
"$ADB" emu kill >/dev/null 2>&1 || true
wait "$ep" 2>/dev/null || true

bash "$GHOST/scripts/gates/dm-emulator-check.sh" "$WORK/$api" "$api" || rc=1
[ "$rc" = 0 ] && echo "dm-emulator: API $api PASS" || echo "dm-emulator: API $api FAIL" >&2
exit "$rc"
