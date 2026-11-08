#!/usr/bin/env bash
# selfcheck.sh — S4 verification of the pinned builder image, run INSIDE the image
# (docs/design/faza14-distribution.md §6, gate G-D2). Two runs of the unified recipe A in the
# default mode (no cross toolchains) must produce byte-identical SHA256SUMS over the WHOLE
# output — §6.1's every path: the host binaries, the Android half (apk/, lib/, symbols/),
# the notices, the SBOMs and the recipe itself; this is the image-level half of the A/B
# equality (the other half is the independent machine, RK1 step 2). The Android half alone
# has its own selfcheck (selfcheck-android.sh, the --android-only mode); the ghost-verify
# cross targets are verified by running GHOST_RELEASE_CROSS=1 separately (today that run
# ends at the EXPECTED mingw exit-1).
#
# Expects: repo at /repo (read-only), writable /out, cargo registry seed at
# $CARGO_HOME/registry, env RUSTUP_HOME/CARGO_HOME set, tag refs/tags/builder-selfcheck
# already present in the mounted repo (created on the host — the mount is read-only).
set -euo pipefail
cd /repo/ghost
echo "=== selfcheck start $(date -u) $(git rev-parse --short HEAD)"

rm -rf /out/A /out/B
echo "--- recipe-A run 1"
bash scripts/release/build-release.sh builder-selfcheck --out /out/A
echo "--- recipe-A run 2"
bash scripts/release/build-release.sh builder-selfcheck --out /out/B

echo "--- compare"
if cmp -s /out/A/SHA256SUMS /out/B/SHA256SUMS; then
  echo "IMAGE_SELFCHECK_EQUAL files=$(wc -l < /out/A/SHA256SUMS)"
  echo "SUMS_DIGEST $(sha256sum /out/A/SHA256SUMS | cut -c1-16)"
  echo "=== selfcheck PASS $(date -u)"
else
  echo "IMAGE_SELFCHECK_DIFFER"
  diff /out/A/SHA256SUMS /out/B/SHA256SUMS || true
  echo "=== selfcheck FAIL $(date -u)"
  exit 1
fi
