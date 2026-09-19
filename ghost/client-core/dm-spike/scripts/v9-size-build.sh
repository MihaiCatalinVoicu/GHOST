#!/usr/bin/env bash
# V-9: builds libghost_client_net.so for both shipped ABIs the way scripts/build-native.sh does
# (pinned cargo-ndk, release profile with strip = "symbols", path remapping), but into
# $CARGO_TARGET_DIR and with optional features, and prints the size of each library.
#
#   v9-size-build.sh <out-dir> [cargo features for -p ghost-client-net]
#
# Variants (size-probe/size-probe.patch applied for all but the baseline; docs/design/faza9-s0-evidence.md §9):
#   baseline                       (patch not applied)
#   ghost-dm-probe/v11,ghost-dm-probe/kem
#   ghost-dm-probe/v10,ghost-dm-probe/kem
#   ghost-dm-probe/v11
#   ghost-dm-probe/kem
#   (empty features: the probe linked with its JNI exports only)
#   ghost-dm-probe/v11,ghost-dm-probe/kem-trait
#   ghost-dm-probe/v11,ghost-dm-probe/kem-trait,ghost-dm-probe/tables
# libcrux is built portable-only (LIBCRUX_DISABLE_SIMD128/256 = 1, design §2.3); build a variant
# in a target directory whose libcrux build scripts first ran with those values (V-6: cargo does
# not re-run them when the variables change).
set -euo pipefail
GHOST_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
OUT_ARG="${1:?usage: v9-size-build.sh <out-dir> [features]}"
FEATURES="${2:-}"
mkdir -p "$OUT_ARG"
OUT="$(cd "$OUT_ARG" && pwd)"
TARGET_DIR="${CARGO_TARGET_DIR:?set CARGO_TARGET_DIR}"
CARGO_HOME_DIR="${CARGO_HOME:-$HOME/.cargo}"
spellings() {
  local p="$1"
  [ -n "$p" ] || return 0
  echo "$p"
  if command -v cygpath >/dev/null 2>&1; then
    cygpath -w "$p"
    cygpath -m "$p"
  fi
}
flags=()
while IFS= read -r p; do flags+=("--remap-path-prefix=$p=/cargo"); done < <(spellings "$CARGO_HOME_DIR")
while IFS= read -r p; do flags+=("--remap-path-prefix=$p=/src"); done < <(spellings "$GHOST_ROOT")
while IFS= read -r p; do flags+=("--remap-path-prefix=$p=/target"); done < <(spellings "$TARGET_DIR")
unset RUSTFLAGS
CARGO_ENCODED_RUSTFLAGS="$(IFS=$'\x1f'; echo "${flags[*]}")"
export CARGO_ENCODED_RUSTFLAGS
export LIBCRUX_DISABLE_SIMD128=1 LIBCRUX_DISABLE_SIMD256=1
cd "$GHOST_ROOT"
args=(ndk -t arm64-v8a -t x86_64 -o "$OUT" build --release --offline -p ghost-client-net)
[ -z "$FEATURES" ] || args+=(--features "$FEATURES")
cargo "${args[@]}" 1>&2
for abi in arm64-v8a x86_64; do
  so="$OUT/$abi/libghost_client_net.so"
  printf 'V9 %s %s %s bytes\n' "${FEATURES:-baseline}" "$abi" "$(wc -c < "$so" | tr -d ' ')"
done
