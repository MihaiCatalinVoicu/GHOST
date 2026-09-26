#!/usr/bin/env bash
# V10-6: builds the det_world example with the process-global seeded getrandom backend and runs it
# twice, in two processes, per configuration; prints whether the outputs are byte-identical.
# Evidence tooling, not product code (docs/design/faza10-s0-evidence.md §6).
#   v10-06-determinism.sh [out-dir]      (CARGO_TARGET_DIR must be set; GHOST_SPIKE_DAY optional)
# Configurations: seed 01 with one rayon worker (expected: identical), seed 02 (differs from seed
# 01), rayon's default pool (expected: commits and state differ), one worker without the added_at
# day rewrite (expected: messages identical, stored rows different).
set -euo pipefail
SPIKE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="${1:-$(mktemp -d)}"
mkdir -p "$OUT"
T="${CARGO_TARGET_DIR:?set CARGO_TARGET_DIR}/det"
cd "$SPIKE"
CARGO_TARGET_DIR="$T" RUSTFLAGS='--cfg getrandom_backend="custom"' \
  cargo build --release --example det_world --features det -p ghost-mls-spike 1>&2
exe="$T/release/examples/det_world"
[ -x "$exe" ] || exe="$exe.exe"
run() { # tag, env, args...
  local tag="$1" env="$2"; shift 2
  env $env "$exe" "$@" > "$OUT/$tag-a.txt"
  env $env "$exe" "$@" > "$OUT/$tag-b.txt"
  if cmp -s "$OUT/$tag-a.txt" "$OUT/$tag-b.txt"; then echo "V10-6 $tag: two processes identical"; else echo "V10-6 $tag: two processes DIFFER ($(diff "$OUT/$tag-a.txt" "$OUT/$tag-b.txt" | grep -c '^<') lines)"; fi
}
run seed01-1worker "X=1" 01 1
run seed02-1worker "X=1" 02 1
run seed01-pool "X=1" 01 0
run seed01-1worker-nodayrewrite "GHOST_SPIKE_NO_DAY_REWRITE=1" 01 1
if cmp -s "$OUT/seed01-1worker-a.txt" "$OUT/seed02-1worker-a.txt"; then echo "V10-6 seeds 01 and 02: identical (unexpected)"; else echo "V10-6 seeds 01 and 02: differ"; fi
