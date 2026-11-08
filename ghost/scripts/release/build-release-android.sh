#!/usr/bin/env bash
# build-release-android.sh <tag> [--out <dir>] — the Android half of recipe A
# (docs/design/faza14-distribution.md §6). From a clean checkout of <tag>: build the native
# libraries with scripts/build-native.sh (ADR-19/ADR-07 discipline: pinned cargo-ndk, remapped
# paths, jniLibs checksums), then ONE unsigned release APK (the A/B/C comparison happens
# between environments on the resulting SHA-256; the signing ceremony RK1 signs the unsigned
# core afterwards). Runs inside the pinned builder image (infra/builder/).
#
# What this script deliberately is not: the signing step (RK1, hardware key), the A/B/C
# cross-environment comparison (sums-compare), and the apk/libs verification a monitor runs
# (ghost-verify apk). Gradle dependency verification (gradle/verification-metadata.xml)
# pins every Java artifact by digest; the Rust side is pinned by Cargo.lock + --locked.
set -euo pipefail

TAG="${1:?usage: build-release-android.sh <tag> [--out <dir>]}"
OUT="${2:-$(pwd)/build-out-android}"
[ "${2:-}" = "--out" ] && OUT="${3:?--out needs a directory}"

# Resolve the invocation path BEFORE any cd: "$0" is relative to the invocation
# directory, and the archive+cd below would otherwise make it point into $WORK
# (the guard would compare the archive against itself and never re-exec — measured).
CALLER="$(cd "$(dirname "$0")" && pwd)/$(basename "$0")"

REPO="$(git rev-parse --show-toplevel)"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# (1) A clean checkout: exactly the tag's bytes, no local state.
git -C "$REPO" archive "$TAG" | tar -x -C "$WORK"
cd "$WORK/ghost"

# The recipe runs from the tag, not the caller's tree (same bootstrap as build-release.sh:
# a stale working-tree copy must not define the recipe).
SELF="$WORK/ghost/scripts/release/build-release-android.sh"
if ! cmp -s "$CALLER" "$SELF" 2>/dev/null; then
  exec bash "$SELF" "$TAG" ${OUT:+--out "$OUT"}
fi

# (2) The fixed environment (design §6.3): no cache may survive between environments.
export SOURCE_DATE_EPOCH="$(git -C "$REPO" log -1 --format=%ct "$TAG")"
export GRADLE_USER_HOME="$WORK/.gradle"
export CARGO_TARGET_DIR="$WORK/target"
mkdir -p "$OUT/bin"

# (3) Native libraries for the shipped ABIs, with the checksum record the gates verify.
bash scripts/build-native.sh "$WORK/jniLibs"
install -m 0644 native-libs.sha256 "$OUT/bin/native-libs.sha256"
cp -r "$WORK/jniLibs/." "$OUT/bin/"
# build-native.sh writes to its own out dir; the app consumes the libraries from the
# module tree (mirroring CI's android-native -> reproducible hand-off).
JNI="$WORK/ghost/android/network/src/main/jniLibs"
rm -rf "$JNI"
mkdir -p "$JNI"
cp -r "$WORK/jniLibs/." "$JNI/"

# (4) The unsigned release APK: single invocation, caches off (the reproducible-build gate
# proves same-path double-build identity; cross-environment identity is recipe A's claim).
cd "$WORK/ghost/android"
./gradlew --no-daemon --no-build-cache --rerun-tasks -q :app:assembleRelease
APK="$WORK/ghost/android/app/build/outputs/apk/release/app-release-unsigned.apk"
install -m 0644 "$APK" "$OUT/bin/app-release-unsigned.apk"

# (5) The value job B prints (and the owner recomputes independently).
cd "$OUT"
sha256sum bin/app-release-unsigned.apk bin/native-libs.sha256 > SHA256SUMS-ANDROID
ADIGEST="$(sha256sum bin/app-release-unsigned.apk | cut -c1-16)"
echo "ANDROID_BUILD_OK tag=$TAG apk_digest=$ADIGEST"
