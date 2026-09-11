#!/usr/bin/env bash
# Builds libghost_client_net.so for the Android ABIs into <out-dir> (ADR-19, ADR-07).
#   - pinned cargo-ndk version and --locked dependency resolution;
#   - a fixed target directory inside the workspace, so two builds of the same checkout at the
#     same path produce identical bytes (checked in CI);
#   - build paths remapped so the binary carries no builder home, registry or workspace path;
#     fails if any such path (or HOME, RUSTUP_HOME, the NDK path) is still present in the output;
#   - writes "sha256  <abi>/libghost_client_net.so" lines to <sums-file>.
# Cross-environment byte identity is NOT claimed: Windows hosts keep '\' separators after the
# remapped prefix, and cargo hashes the remap flags (which name the builder's paths) into
# build-script directories. A fixed-path builder image is Phase 14 work (ADR-07).
# Usage: build-native.sh <out-dir> [sums-file (default: <ghost>/native-libs.sha256)]
# Requires: ANDROID_NDK_HOME, rust targets aarch64-linux-android + x86_64-linux-android.
set -euo pipefail

CARGO_NDK_VERSION="4.1.2"
ABIS=(arm64-v8a x86_64) # keep in sync with scripts/gates/rust-client-allowlist.sh

GHOST_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_ARG="${1:?usage: build-native.sh <out-dir> [sums-file]}"
mkdir -p "$OUT_ARG"
OUT="$(cd "$OUT_ARG" && pwd)"
SUMS_ARG="${2:-$GHOST_ROOT/native-libs.sha256}"
mkdir -p "$(dirname "$SUMS_ARG")"
SUMS="$(cd "$(dirname "$SUMS_ARG")" && pwd)/$(basename "$SUMS_ARG")"
TARGET_DIR="$GHOST_ROOT/target/android-native"
CARGO_HOME_DIR="${CARGO_HOME:-$HOME/.cargo}"
mkdir -p "$TARGET_DIR"

have="$(cargo ndk --version 2>/dev/null | awk '{print $2}' || true)"
if [ "$have" != "$CARGO_NDK_VERSION" ]; then
  echo "cargo-ndk $CARGO_NDK_VERSION required (found '${have:-none}'): cargo install cargo-ndk --version $CARGO_NDK_VERSION --locked" >&2
  exit 2
fi

# Every spelling rustc may see for a path (POSIX; on Windows also C:\ and C:/ forms).
spellings() {
  local p="$1"
  [ -n "$p" ] || return 0
  echo "$p"
  if command -v cygpath >/dev/null 2>&1; then
    cygpath -w "$p"
    cygpath -m "$p"
  fi
}

# Later flags win in rustc, so the target dir (inside the workspace) is remapped last.
flags=()
while IFS= read -r p; do flags+=("--remap-path-prefix=$p=/cargo"); done < <(spellings "$CARGO_HOME_DIR")
while IFS= read -r p; do flags+=("--remap-path-prefix=$p=/src"); done < <(spellings "$GHOST_ROOT")
while IFS= read -r p; do flags+=("--remap-path-prefix=$p=/target"); done < <(spellings "$TARGET_DIR")
# CARGO_ENCODED_RUSTFLAGS (0x1f-separated) keeps paths with spaces intact.
unset RUSTFLAGS
CARGO_ENCODED_RUSTFLAGS="$(IFS=$'\x1f'; echo "${flags[*]}")"
export CARGO_ENCODED_RUSTFLAGS
export CARGO_TARGET_DIR="$TARGET_DIR"

cd "$GHOST_ROOT"
targets=()
for abi in "${ABIS[@]}"; do targets+=(-t "$abi"); done
# cargo-ndk prints compiler messages on stdout; keep stdout clean for callers.
cargo ndk "${targets[@]}" -o "$OUT" build --release --locked -p ghost-client-net 1>&2

leaks=0
check_paths=()
for d in "$CARGO_HOME_DIR" "$GHOST_ROOT" "$TARGET_DIR" "${HOME:-}" "${RUSTUP_HOME:-}" "${ANDROID_NDK_HOME:-}"; do
  while IFS= read -r p; do [ -n "$p" ] && check_paths+=("$p"); done < <(spellings "$d")
done
for abi in "${ABIS[@]}"; do
  so="$OUT/$abi/libghost_client_net.so"
  [ -f "$so" ] || { echo "missing $so" >&2; exit 1; }
  for p in "${check_paths[@]}"; do
    if grep -a -F -q -- "$p" "$so"; then
      echo "LEAK: $so contains build path '$p'" >&2
      leaks=$((leaks + 1))
    fi
  done
done
[ "$leaks" -eq 0 ] || exit 1
(cd "$OUT" && for abi in "${ABIS[@]}"; do sha256sum "$abi/libghost_client_net.so"; done) > "$SUMS"
echo "native libraries: $OUT; sums: $SUMS" >&2
