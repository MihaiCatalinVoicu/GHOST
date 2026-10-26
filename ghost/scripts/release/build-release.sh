#!/usr/bin/env bash
# build-release.sh <tag> [--out <dir>] — the deterministic core of recipe A (Phase 14 design §6,
# slice S4). Builds the release binaries from a clean checkout of <tag>, one cargo invocation per
# binary (design §6.4: a joint invocation would unify features across packages and differ from
# the operators' builds), and writes SHA256SUMS over the results plus the b_digest line the
# owner compares on an independent device (RK1 step 2, CR-M5).
#
# What this script deliberately is not (later slices): the pinned builder image (infra/builder/,
# G-D2), the three environments A/B/C, the Android half (build-native.sh, apksigner, zipalign)
# and the notices/SBOM/archive-index steps. Everything here is host-toolchain-only, so a
# mismatch investigation can run it on any checkout.
set -euo pipefail

TAG="${1:?usage: build-release.sh <tag> [--out <dir>]}"
OUT="${2:-$(pwd)/build-out}"
[ "${2:-}" = "--out" ] && OUT="${3:?--out needs a directory}"

REPO="$(git rev-parse --show-toplevel)"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# (1) A clean checkout: exactly the tag's bytes, no local state.
git -C "$REPO" archive "$TAG" | tar -x -C "$WORK"
cd "$WORK/ghost"

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

# (3) The sums and the value job B prints (and the owner recomputes independently).
cd "$OUT"
sha256sum bin/* > SHA256SUMS
BDIGEST="$(sha256sum SHA256SUMS | cut -c1-16)"
echo "BUILD_OK tag=$TAG files=$(wc -l < SHA256SUMS) b_digest=$BDIGEST"
