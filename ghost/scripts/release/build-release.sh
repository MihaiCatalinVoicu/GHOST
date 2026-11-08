#!/usr/bin/env bash
# build-release.sh <tag> [--out <dir>] — the deterministic core of recipe A (Phase 14 design §6,
# slice S4). Builds the release binaries from a clean checkout of <tag>, one cargo invocation per
# binary (design §6.4: a joint invocation would unify features across packages and differ from
# the operators' builds), and writes SHA256SUMS over the results plus the b_digest line the
# owner compares on an independent device (RK1 step 2, CR-M5).
#
# What this script deliberately is not (later slices): the three environments A/B/C, the
# Android half (build-native.sh, apksigner, zipalign) and the notices/SBOM/archive-index
# steps. Everything here is host-toolchain-only, so a mismatch investigation can run it on
# any checkout. The ghost-verify cross targets (§6.1 kinds 19-22, from the exported public
# tree) need cross toolchains and run only under GHOST_RELEASE_CROSS=1 — see step (3).
set -euo pipefail

TAG="${1:?usage: build-release.sh <tag> [--out <dir>]}"
OUT="${2:-$(pwd)/build-out}"
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

# The recipe itself must come from the tag, not from the caller's tree: a stale or edited
# working-tree copy would run a different recipe against the tag's sources (measured on
# 2026-11-08: a not-yet-synced working tree silently skipped the cross block; the debugging
# cost a container trace). Re-exec from the archive whenever the two differ.
SELF="$WORK/ghost/scripts/release/build-release.sh"
if ! cmp -s "$CALLER" "$SELF" 2>/dev/null; then
  exec bash "$SELF" "$TAG" ${OUT:+--out "$OUT"}
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

mkdir -p "$OUT/bin"
build_one() {
  local pkg="$1" name="$2"
  cargo build --release --locked -p "$pkg"
  # The release profile is stripped by definition (design §6.4); `install` adds nothing.
  install -m 0755 "$WORK/target/release/$name" "$OUT/bin/$name"
}

# One invocation per binary, in the design's order.
build_one ghost-relay-node ghost-relay
build_one ghost-issuer ghost-issuer
build_one ghost-issuer-ops ghost-issuer-ops
build_one ghost-release-ops ghost-release-ops
build_one ghost-verify ghost-verify

# (3) ghost-verify's public targets (design §6.1 kinds 19-22): export the public source tree
# (artifact kind 19) and build inside it, so the binaries are reproducible from what users
# read. Behind GHOST_RELEASE_CROSS until the builder image carries every toolchain piece:
# the musl rust-stds are pinned in infra/builder (pins.txt/Dockerfile, official static.rust-
# lang.org SHA-256s) and need an image rebuild; the x86_64-w64-mingw32 linker (mingw-w64) is
# declared in pins.txt but deliberately not pinned into the image yet — the Windows target
# fails loudly under the guard until that deeper slice lands.
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

# (4) The sums and the value job B prints (and the owner recomputes independently).
cd "$OUT"
sha256sum bin/* > SHA256SUMS
BDIGEST="$(sha256sum SHA256SUMS | cut -c1-16)"
echo "BUILD_OK tag=$TAG files=$(wc -l < SHA256SUMS) b_digest=$BDIGEST"
