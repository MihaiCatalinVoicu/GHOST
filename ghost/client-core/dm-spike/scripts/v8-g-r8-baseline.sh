#!/usr/bin/env bash
# V-8: the G-R8 baseline prototype. With size-probe/size-probe.patch applied (the DM stack linked
# into ghost-client-net through ghost-dm-probe), for each shipped triple:
#   1. the package set: `cargo tree -p ghost-dm-probe -e normal --target <triple>` with the DM
#      features;
#   2. the enabled features of each package as built into the shipped library:
#      `cargo tree -p ghost-client-net -e normal --target <triple> -f '{p}|{f}'` (resolver 2 gives
#      the build's feature resolution for that target);
#   3. examples/g_r8_scan over that set.
# Prints the merged, sorted site, directive, crate and note lines. No build of the library needed.
#   v8-g-r8-baseline.sh <work-dir> [features]   (default: ghost-dm-probe/v11,ghost-dm-probe/kem-trait)
set -euo pipefail
SPIKE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
GHOST_ROOT="$(cd "$SPIKE/../.." && pwd)"
WORK="${1:?usage: v8-g-r8-baseline.sh <work-dir> [features]}"
FEATURES="${2:-ghost-dm-probe/v11,ghost-dm-probe/kem-trait}"
mkdir -p "$WORK"
SCANNER_TARGET="${SCANNER_TARGET_DIR:-${CARGO_TARGET_DIR:?set CARGO_TARGET_DIR}/spike}"
(cd "$SPIKE" && CARGO_TARGET_DIR="$SCANNER_TARGET" cargo build --offline --release --example g_r8_scan 1>&2)
SCANNER=""
for candidate in "$SCANNER_TARGET"/release/examples/g_r8_scan.exe "$SCANNER_TARGET"/release/examples/g_r8_scan; do
  [ -f "$candidate" ] && SCANNER="$candidate" && break
done
[ -n "$SCANNER" ] || { echo "scanner not built" >&2; exit 1; }

cd "$GHOST_ROOT"
for triple in aarch64-linux-android x86_64-linux-android; do
  cargo tree --offline -p ghost-dm-probe -e normal --target "$triple" --prefix none -f '{p}' --features "$FEATURES" \
    | sed 's/ (\*)//; s/ (proc-macro)//' | sort -u > "$WORK/tree-$triple.txt"
  cargo tree --offline -p ghost-client-net -e normal --target "$triple" --prefix none -f '{p}|{f}' --features "$FEATURES" \
    | sort -u > "$WORK/features-$triple.txt"
  cargo tree --offline -p ghost-dm-probe -e normal,no-proc-macro --target "$triple" --prefix none -f '{p}' --features "$FEATURES" \
    | sed 's/ (\*)//' | sort -u > "$WORK/shipped-$triple.txt"
  "$SCANNER" "$GHOST_ROOT/Cargo.toml" "$triple" "$WORK/tree-$triple.txt" "$WORK/features-$triple.txt" \
    "$WORK/shipped-$triple.txt" > "$WORK/scan-$triple.txt"
done
sort -u "$WORK"/scan-*.txt
