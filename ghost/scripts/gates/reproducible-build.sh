#!/usr/bin/env bash
# Gate T12 (ADR-07): two independent release builds must produce byte-identical unsigned APKs.
# Usage: reproducible-build.sh [outdir]. Requires ANDROID_HOME and JAVA_HOME.
source "$(dirname "${BASH_SOURCE[0]}")/common.sh"
OUT="${1:-$GHOST_ROOT/../build-repro}"
mkdir -p "$OUT"
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
finish reproducible-build
