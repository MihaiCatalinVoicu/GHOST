#!/usr/bin/env bash
# run-in-image.sh <tag> [--out <dir>] — recipe A (scripts/release/build-release.sh) inside
# the pinned builder image, gate G-D2. The checkout is read-only input at /repo, the
# toolchain comes only from the image (rust-toolchain.toml in the checkout pins the Rust
# channel), and the host cargo registry is mounted as an offline seed — build-release.sh
# sets CARGO_NET_OFFLINE=true, so no resolution can differ from the tag's Cargo.lock.
#
# Usage (from anywhere in the repo):
#   infra/builder/run-in-image.sh v1.0.0 --out ./build-A
#   sha256sum ./build-A/SHA256SUMS   # -> hand to the independent rebuild (RK1 step 2)
set -euo pipefail

TAG="${1:?usage: run-in-image.sh <tag> [--out <dir>]}"
OUT="$(pwd)/build-out-image"
[ "${2:-}" = "--out" ] && OUT="${3:?--out needs a directory}"

IMG="ghost-builder:24.04-1"
REPO="$(git rev-parse --show-toplevel)"
mkdir -p "$OUT"

exec docker run --rm \
  --user "$(id -u):$(id -g)" \
  -v "$REPO:/repo:ro" \
  -v "$OUT:/out" \
  -v "$HOME/.cargo/registry:/opt/cargo/registry" \
  -e RUSTUP_HOME=/opt/rustup \
  -e CARGO_HOME=/opt/cargo \
  -w /repo/ghost \
  "$IMG" \
  bash scripts/release/build-release.sh "$TAG" --out /out
