#!/usr/bin/env bash
# Gate T12 (ADR-07): two independent release builds must produce byte-identical unsigned APKs,
# and the APK must carry the Tor core (libghost_client_net.so) for every shipped ABI with exactly
# the bytes recorded by scripts/build-native.sh (native-libs.sha256), only the shipped ABI
# directories and only allowlisted native library names (see apk-native-libs.sh). An APK without
# the Tor core, with different Tor-core bytes, or with an unlisted native library fails. In CI the
# sums come from the same run's android-native job (two same-path builds that must agree); they
# are not a separately reviewed reference.
# Usage: reproducible-build.sh [outdir] [native-libs.sha256]. Requires ANDROID_HOME and JAVA_HOME,
# and the libraries in android/network/src/main/jniLibs (build them with scripts/build-native.sh).
source "$(dirname "${BASH_SOURCE[0]}")/common.sh"
OUT="${1:-$GHOST_ROOT/../build-repro}"
NATIVE_SUMS="${2:-$GHOST_ROOT/native-libs.sha256}"
ABIS=(arm64-v8a x86_64)
JNI="$GHOST_ROOT/android/network/src/main/jniLibs"
mkdir -p "$OUT"

for abi in "${ABIS[@]}"; do
  [ -f "$JNI/$abi/libghost_client_net.so" ] || fail "missing $JNI/$abi/libghost_client_net.so (run scripts/build-native.sh)"
done
if [ -f "$NATIVE_SUMS" ]; then
  NATIVE_SUMS="$(cd "$(dirname "$NATIVE_SUMS")" && pwd)/$(basename "$NATIVE_SUMS")" # absolute: we cd below
else
  fail "missing $NATIVE_SUMS (written by scripts/build-native.sh / CI android-native)"
fi
[ "$FAILURES" -eq 0 ] || finish reproducible-build

cd "$GHOST_ROOT/android"
build_once() {
  local tag="$1"
  ./gradlew --no-daemon --no-build-cache --rerun-tasks -q :app:assembleRelease
  cp app/build/outputs/apk/release/app-release-unsigned.apk "$OUT/app-release-unsigned-$tag.apk"
}
build_once a
./gradlew --no-daemon -q clean
build_once b
A="$(sha256sum "$OUT/app-release-unsigned-a.apk" | cut -d' ' -f1)"
B="$(sha256sum "$OUT/app-release-unsigned-b.apk" | cut -d' ' -f1)"
echo "build a: $A"; echo "build b: $B"
[ "$A" = "$B" ] || fail "release APK is not reproducible"

bash "$GATES_DIR/apk-native-libs.sh" "$OUT/app-release-unsigned-a.apk" "$NATIVE_SUMS" || fail "native libraries in the APK"
finish reproducible-build
