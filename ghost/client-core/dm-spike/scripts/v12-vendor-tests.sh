#!/usr/bin/env bash
# V-12: vodozemac's own test suite at a pinned version (the vendor-tests job, design §15.2 item 1,
# §16.2). The crates.io package carries the unit tests in src/ (169 in 0.11.0, 152 in 0.10.0) and
# its own Cargo.lock; its dev-dependencies build libolm (olm-sys, a CMake and C++ build) and
# nothing of that reaches a product graph.
#
#   v12-vendor-tests.sh <version> [work-dir]     e.g. v12-vendor-tests.sh 0.11.0
#
# Checks the .crate against the checksum the ghost lock and this spike's lock pin, extracts it, and
# runs `cargo test --locked` twice: default features, then --all-features. Needs network (the
# dev-dependencies are not in the product lock), cmake, a C++ compiler and the pinned toolchain.
# Expected .crate SHA-256 (crates.io checksums, as in Cargo.lock):
#   vodozemac 0.11.0  ba935af014ca0ae5fb468daa51da81a8a0df7daad23c052c878b7c690cdf2574 (tag commit db1b34820f3102307284e762f335b3f72c735bf0)
#   vodozemac 0.10.0  b98bf83c0992966775b8012f194b07b44928996163e5a05b741b43891571ae5b (tag commit bb39ec65357989f975e0d47f9fb35e0656180151)
set -euo pipefail
VERSION="${1:?usage: v12-vendor-tests.sh <version> [work-dir]}"
WORK="${2:-$(mktemp -d)}"
case "$VERSION" in
  0.11.0) SUM=ba935af014ca0ae5fb468daa51da81a8a0df7daad23c052c878b7c690cdf2574 ;;
  0.10.0) SUM=b98bf83c0992966775b8012f194b07b44928996163e5a05b741b43891571ae5b ;;
  *) echo "unpinned version $VERSION" >&2; exit 2 ;;
esac
command -v cmake >/dev/null || { echo "cmake is required (olm-sys builds libolm)" >&2; exit 2; }
CACHE="${CARGO_HOME:-$HOME/.cargo}/registry/cache"
CRATE="$(find "$CACHE" -name "vodozemac-$VERSION.crate" 2>/dev/null | head -1)"
if [ -z "$CRATE" ]; then
  # Fetch through cargo (checksum-verified against the index) with a throwaway manifest.
  mkdir -p "$WORK/fetch/src"
  printf '[package]\nname = "fetch"\nversion = "0.0.0"\nedition = "2021"\n[dependencies]\nvodozemac = "=%s"\n' "$VERSION" > "$WORK/fetch/Cargo.toml"
  : > "$WORK/fetch/src/lib.rs"
  cargo fetch --manifest-path "$WORK/fetch/Cargo.toml"
  CRATE="$(find "$CACHE" -name "vodozemac-$VERSION.crate" | head -1)"
fi
echo "$SUM  $CRATE" | sha256sum -c -
tar -xzf "$CRATE" -C "$WORK"
cd "$WORK/vodozemac-$VERSION"
cargo test --locked 2>&1 | tee "$WORK/default.log" | grep -E '^test result|FAILED|panicked' || true
cargo test --locked --all-features 2>&1 | tee "$WORK/all-features.log" | grep -E '^test result|FAILED|panicked' || true
grep -q 'test result: FAILED' "$WORK/default.log" "$WORK/all-features.log" && exit 1
grep -q '^test result: ok' "$WORK/default.log" && grep -q '^test result: ok' "$WORK/all-features.log"
