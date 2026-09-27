#!/usr/bin/env bash
# V10-3 (and the build half of V10-1, V10-7): builds libghost_client_net.so for both shipped ABIs
# the way scripts/build-native.sh does (pinned cargo-ndk, release profile with strip = "symbols",
# path remapping, the workspace's portable-libcrux [env]), but into $CARGO_TARGET_DIR, --offline
# instead of --locked (the probe patch changes the lock), and with the probe's features.
# Evidence tooling, not product code (docs/design/faza10-s0-evidence.md §3).
#
#   v10-03-size-build.sh <out-dir> [cargo features for -p ghost-client-net] [--unstripped]
#
# Variants (size-probe/size-probe.patch applied for all but the baseline):
#   baseline         patch not applied
#   (no features)    the probe linked with its JNI export only (lock and feature-unification drift)
#   mls-probe        OpenMLS 0.9.0 + libcrux provider + GhostKv + GHOST's extensions and calls
#   mls-probe-pq     the same with OpenMLS's X-Wing suites compiled in (Q2 evidence only)
# Before each build the libcrux packages with SIMD build scripts are cleaned for both triples
# (G-R3's rule of ghost/.cargo/config.toml, extended to libcrux-aes, V10-7), and afterwards their
# build-script outputs are printed so the portable claim is read from the build that produced the
# library.
set -euo pipefail
GHOST_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
OUT_ARG="${1:?usage: v10-03-size-build.sh <out-dir> [features] [--unstripped]}"
FEATURES="${2:-}"
UNSTRIPPED="${3:-}"
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
cd "$GHOST_ROOT"
for triple in aarch64-linux-android x86_64-linux-android; do
  cargo clean --offline -p libcrux-ml-kem -p libcrux-sha3 -p libcrux-intrinsics -p libcrux-aes \
    --target "$triple" --release >/dev/null 2>&1 || true
done
args=(ndk -t arm64-v8a -t x86_64 -o "$OUT" build --release --offline -p ghost-client-net)
[ -z "$FEATURES" ] || args+=(--features "$FEATURES")
[ "$UNSTRIPPED" != "--unstripped" ] || args+=(--config profile.release.strip=false)
cargo "${args[@]}" 1>&2
for abi in arm64-v8a x86_64; do
  so="$OUT/$abi/libghost_client_net.so"
  printf 'V10-3 %s%s %s %s bytes\n' "${FEATURES:-no-features}" "${UNSTRIPPED:+ (unstripped)}" "$abi" "$(wc -c < "$so" | tr -d ' ')"
done
for triple in aarch64-linux-android x86_64-linux-android; do
  for pkg in libcrux-ml-kem libcrux-sha3 libcrux-intrinsics libcrux-aes; do
    for o in "$TARGET_DIR/$triple/release/build/$pkg"-*/output; do
      [ -f "$o" ] || continue
      printf 'V10-7 %s %s %s cfg-lines=%s simd=%s\n' "$triple" "$pkg" "$(basename "$(dirname "$o")")" \
        "$(grep -c 'cargo:rustc-cfg' "$o" || true)" "$(grep -cE 'feature="simd(128|256)"' "$o" || true)"
    done
  done
done
