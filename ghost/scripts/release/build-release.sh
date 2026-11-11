#!/usr/bin/env bash
# build-release.sh <tag> [--out <dir>] [--android-only] — recipe A, the single release recipe
# (Phase 14 design §6.1's path table, §6.2's nine steps, slice S3d). From a clean checkout of
# <tag>: the host binaries, the ghost-verify public targets, the Android half (native
# libraries with the symbol split, the zip-aligned unsigned APK), the notices (G-L1), the
# SBOMs, the recipe itself, the identity scrub (G-D9) — one output tree, ONE SHA256SUMS over
# every path of §6.1. Exit prints BUILD_OK tag=… files=<n> b_digest=…; the b_digest is the
# value job B prints and the owner recomputes independently (RK1 step 2).
#
# --android-only runs just the Android half (apk/, lib/, symbols/) with a SHA256SUMS-ANDROID
# over that subset and the ANDROID_BUILD_OK line; scripts/release/build-release-android.sh
# is the thin wrapper, and infra/builder/selfcheck-android.sh compares two such runs
# (ANDROID_SELFCHECK_EQUAL). The host selfcheck (selfcheck.sh) runs this script twice in the
# default mode and compares the whole SHA256SUMS (IMAGE_SELFCHECK_EQUAL) — the default mode
# has no cross toolchains, so no ghost-verify cross binaries; GHOST_RELEASE_CROSS=1 adds the
# export + the three public targets (and, today, ends at the EXPECTED mingw exit-1 until
# mingw-w64 is pinned — see step (6)).
#
# The tag re-exec guard, the fixed environment (§6.3: SOURCE_DATE_EPOCH, CARGO_NET_OFFLINE,
# remapped paths, the image's processor pin) and one cargo invocation per binary are the
# standing discipline — do not relax them.
set -euo pipefail

TAG="${1:?usage: build-release.sh <tag> [--out <dir>] [--android-only]}"
OUT="${2:-$(pwd)/build-out}"
[ "${2:-}" = "--out" ] && OUT="${3:?--out needs a directory}"
ANDROID_ONLY=0
for arg in "$@"; do [ "$arg" = "--android-only" ] && ANDROID_ONLY=1; done

# Resolve the invocation path BEFORE any cd: "$0" is relative to the invocation
# directory, and the archive+cd below would otherwise make it point into $WORK
# (the guard would compare the archive against itself and never re-exec — measured).
CALLER="$(cd "$(dirname "$0")" && pwd)/$(basename "$0")"

REPO="${REPO:-$(git rev-parse --show-toplevel)}"
export REPO
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# (1) A clean checkout: exactly the tag's bytes, no local state.
git -C "$REPO" archive "$TAG" | tar -x -C "$WORK"
cd "$WORK/ghost"

# The recipe itself must come from the tag, not from the caller's tree: a stale or edited
# working-tree copy would run a different recipe against the tag's sources (measured on
# 2026-11-08: a not-yet-synced working tree silently skipped the cross block; the debugging
# cost a container trace). Re-exec from the archive whenever the two differ.
SELF="$WORK/ghost/scripts/release/build-release.sh"
if ! cmp -s "$CALLER" "$SELF" 2>/dev/null; then
  exec bash "$SELF" "$TAG" ${OUT:+--out "$OUT"} $([ "$ANDROID_ONLY" = 1 ] && echo --android-only)
fi

# (2) The fixed environment (design §6.3's core; the image pins the rest). SOURCE_DATE_EPOCH
# removes the one timestamp some toolchains embed; CARGO_NET_OFFLINE makes a forgotten lock
# update fail instead of silently resolving fresh.
export SOURCE_DATE_EPOCH="$(git -C "$REPO" log -1 --format=%ct "$TAG")"
export CARGO_NET_OFFLINE=true
export CARGO_TARGET_DIR="$WORK/target"
# The build path is not part of the release: tonic's generated-code paths (and any panic
# location) embed it otherwise, and two honest builds in different directories would differ
# (measured: ghost-relay carried /tmp/tmp.XXX/target/... into its bytes). The same remap
# discipline as scripts/build-native.sh (V-D1).
export RUSTFLAGS="${RUSTFLAGS:-} --remap-path-prefix=$WORK=/build"
# No Gradle state may survive between environments (§6.3); the image pins the worker count.
export GRADLE_USER_HOME="$WORK/.gradle"
export GRADLE_OPTS="${GRADLE_OPTS:-} -Dorg.gradle.workers.max=2"

mkdir -p "$OUT/bin"

# (3) The host binaries: one invocation per binary (design §6.4: a joint invocation would
# unify features across packages and differ from the operators' builds).
build_one() {
  local pkg="$1" name="$2"
  cargo build --release --locked -p "$pkg"
  # The release profile is stripped by definition (design §6.4); `install` adds nothing.
  install -m 0755 "$WORK/target/release/$name" "$OUT/bin/$name"
}
if [ "$ANDROID_ONLY" = 1 ]; then
  echo "note: --android-only — host binaries, notices, SBOMs and the public targets skipped" >&2
else
  build_one ghost-relay-node ghost-relay
  build_one ghost-issuer ghost-issuer
  build_one ghost-issuer-ops ghost-issuer-ops
  build_one ghost-release-ops ghost-release-ops
  build_one ghost-verify ghost-verify
fi

# (4) The Android half (design §6.1's apk/, lib/ and symbols/ rows; the android selfcheck's
# shape): native libraries with the symbol split, the unsigned APK aligned once, the checksum
# record beside the libraries it lists.
android_half() {
  # Native libraries for the shipped ABIs; build-native.sh splits the debug info into the
  # symbols dir and strips the shipped .so (.dynsym stays). The checksum record the gates
  # verify lives next to the libraries it lists.
  bash scripts/build-native.sh "$WORK/jniLibs" "$OUT/lib/native-libs.sha256" "$WORK/symbols"
  mkdir -p "$OUT/lib" "$OUT/symbols"
  for abi in arm64-v8a x86_64; do
    mkdir -p "$OUT/lib/$abi" "$OUT/symbols/$abi"
    install -m 0644 "$WORK/jniLibs/$abi/libghost_client_net.so" "$OUT/lib/$abi/libghost_client_net.so"
    install -m 0644 "$WORK/symbols/$abi/libghost_client_net.so.debug" "$OUT/symbols/$abi/libghost_client_net.so.debug"
  done
  # build-native.sh writes to its own out dir; the app consumes the libraries from the
  # module tree (mirroring CI's android-native -> reproducible hand-off).
  JNI="$WORK/ghost/android/network/src/main/jniLibs"
  rm -rf "$JNI"
  mkdir -p "$JNI"
  cp -r "$WORK/jniLibs/." "$JNI/"

  # The unsigned release APK: single invocation, caches off (§6.3; the reproducible-build
  # gate proves same-path double-build identity; cross-environment identity is this recipe).
  cd "$WORK/ghost/android"
  ./gradlew --no-daemon --no-build-cache --rerun-tasks -q :app:assembleRelease
  RAW="$WORK/ghost/android/app/build/outputs/apk/release/app-release-unsigned.apk"
  [ -f "$RAW" ] || { echo "assembleRelease produced no unsigned APK" >&2; exit 1; }

  # The zipalign step (§6.1's first row): the assembleRelease output if it already satisfies
  # the -P 16 alignment, else an explicit align — one script decides per run, so both
  # environments run the same decision (V-D4's decide-once is this check).
  ZIPALIGN="$(find "${ANDROID_HOME:?android only in the builder image}/build-tools" -maxdepth 2 -name zipalign -type f | sort | tail -1)"
  [ -n "$ZIPALIGN" ] || { echo "zipalign not found under $ANDROID_HOME/build-tools" >&2; exit 1; }
  ALIGNED="$WORK/aligned.apk"
  if "$ZIPALIGN" -c -P 16 "$RAW" >/dev/null 2>&1; then
    ALIGNED="$RAW"
  else
    "$ZIPALIGN" -P 16 -f 4 "$RAW" "$ALIGNED"
  fi

  # The §6.1 name: ghost-<network>-<version_code>-unsigned.apk. The network is the stagenet
  # recipe today (§6.2's builder image is the stagenet one; a mainnet release build changes
  # this constant). The version code comes from the tag's own build file.
  NETWORK="stagenet"
  VC="$(sed -n 's/^[[:space:]]*versionCode *= *\([0-9][0-9]*\).*/\1/p' "$WORK/ghost/android/app/build.gradle.kts" | head -1)"
  [ -n "$VC" ] || { echo "versionCode not found in app/build.gradle.kts" >&2; exit 1; }
  mkdir -p "$OUT/apk"
  APK_OUT="$OUT/apk/ghost-$NETWORK-$VC-unsigned.apk"
  install -m 0644 "$ALIGNED" "$APK_OUT"
  cd "$WORK/ghost"
}
android_half

# (5) The notices (design §6.1's notices/ row, G-L1): regenerate from what ships, re-verify as
# a gate, copy into the output. The android notices need the Gradle half's component list
# (G-L2 runs in the android job against verification-metadata); here the committed file — the
# tag's own bytes — ships, exactly as the §6.1 row says ("regenerated, equal to the committed
# files (G-L1)").
if [ "$ANDROID_ONLY" != 1 ]; then
  bash scripts/gates/license-notices.sh rust --write
  bash scripts/gates/license-notices.sh rust
  mkdir -p "$OUT/notices"
  for part in client-net relay issuer android; do
    install -m 0644 "licenses/THIRD_PARTY_NOTICES-$part.txt" "$OUT/notices/THIRD_PARTY_NOTICES-$part.txt"
  done
fi

# (6) The SBOMs (§6.1's sbom/ row), the native-libraries gate (§6.1's "what the APK contains"
# note: the APK's lib entries equal the recorded build), the public source export and the
# ghost-verify cross targets (kinds 19-22; behind GHOST_RELEASE_CROSS — the musl toolchains
# are in the image, mingw-w64 is the expected loud exit-1 until its slice lands).
bash scripts/gates/apk-native-libs.sh "$APK_OUT" "$OUT/lib/native-libs.sha256"
if [ "$ANDROID_ONLY" != 1 ]; then
  mkdir -p "$OUT/sbom"
  for spec in "client:ghost-client-net" "relay:ghost-relay-node" "issuer:ghost-issuer"; do
    "$WORK/target/release/ghost-release-ops" sbom --package "${spec##*:}" --out "$OUT/sbom/${spec%%:*}.cdx.json"
  done
  if [ "${GHOST_RELEASE_CROSS:-0}" = 1 ]; then
    "$WORK/target/release/ghost-release-ops" export-public --tag "$TAG" --out "$OUT"
    PUB="$WORK/public-tree"
    mkdir -p "$PUB"
    tar -xf "$OUT/ghost-public-$TAG.tar" -C "$PUB"
    cross_one() {
      local target="$1" name="$2" exe="${3:-}"
      # Works with and without rustup: rustc refuses an unknown target either way (the image
      # installs stds by direct archive, no rustup).
      if ! rustc --print target-libdir --target "$target" >/dev/null 2>&1; then
        echo "GHOST_RELEASE_CROSS=1 and $target has no installed std: rebuild the builder image (its pins.txt gained the rust-std archives)" >&2
        exit 1
      fi
      ( cd "$PUB" && CARGO_TARGET_DIR="$WORK/target-public" cargo build --release --locked --target "$target" )
      install -m 0755 "$WORK/target-public/$target/release/ghost-verify$exe" "$OUT/bin/$name"
    }
    cross_one x86_64-unknown-linux-musl ghost-verify-x86_64-linux
    cross_one aarch64-unknown-linux-musl ghost-verify-aarch64-linux
    if command -v x86_64-w64-mingw32-gcc >/dev/null 2>&1; then
      cross_one x86_64-pc-windows-gnu ghost-verify-x86_64-windows.exe .exe
    else
      echo "GHOST_RELEASE_CROSS=1 and x86_64-w64-mingw32-gcc is absent: mingw-w64 is not in the builder image yet (declared, not pinned) — the Windows target cannot build" >&2
      exit 1
    fi
  else
    echo "note: ghost-verify cross targets skipped (GHOST_RELEASE_CROSS=1 enables them; design §6.1 kinds 19-22)" >&2
  fi
  # The recipe itself ships with the output (§6.1's recipe/ row).
  mkdir -p "$OUT/recipe"
  install -m 0644 infra/builder/Dockerfile "$OUT/recipe/Dockerfile"
  install -m 0644 infra/builder/pins.txt "$OUT/recipe/pins.txt"
fi

# (7) The identity scrub (G-D9, D25): every output byte carries no personal identifier.
bash scripts/gates/public-identity-scrub.sh "$OUT"

# (8) The sums. ONE SHA256SUMS over the whole output tree (§6.1's every path), so the
# selfcheck's byte-equality covers the notices' and SBOMs' determinism too. In --android-only
# mode the android subset gets its own SHA256SUMS-ANDROID (the android selfcheck's shape).
cd "$OUT"
if [ "$ANDROID_ONLY" = 1 ]; then
  sha256sum apk/* lib/*/*.so lib/native-libs.sha256 symbols/*/*.so.debug > SHA256SUMS-ANDROID
  ADIGEST="$(sha256sum "$APK_OUT" | cut -c1-16)"
  echo "ANDROID_BUILD_OK tag=$TAG apk_digest=$ADIGEST"
else
  mapfile -t SUM_FILES < <(find . -type f ! -name 'SHA256SUMS*' -print | sed 's|^\./||' | sort)
  sha256sum "${SUM_FILES[@]}" > SHA256SUMS
  BDIGEST="$(sha256sum SHA256SUMS | cut -c1-16)"
  echo "BUILD_OK tag=$TAG files=$(wc -l < SHA256SUMS) b_digest=$BDIGEST"
fi
