#!/usr/bin/env bash
# V10-6 (Phase 10 design faza10-forum.md §12.1, §19.10; S0-7; slice S2a): the process-global seeded
# stream makes a scripted channel world reproducible. `client-core/mls/examples/det_world.rs` is
# built with `--cfg getrandom_backend="custom"` (ghost-host-rng serves every getrandom draw of the
# process from one ChaCha20 stream keyed by the seed) and run in two separate processes with the same
# seed: the outputs — every commit, Welcome, KeyPackage, post, sealed blob, change-set, epoch
# authenticator and every member's stored rows — must be byte-identical. A third run with another
# seed must differ (the seed, not a constant, drives the output), and every run must report the
# backend active (a build without the cfg would draw from the OS and still "run").
#
# S0-7's preconditions: (a) rayon at one worker — the example asserts it; (b) the `added_at` day
# rewrite — GhostKv; (c) one getrandom major in the linked graph — checked here over the example's
# graph (the crate's normal and dev edges, proc-macros excluded), and by rust-feature-policy.sh
# (G-R2) over the host library's.
#
# Usage: mls-determinism.sh [work-dir]      (CARGO_TARGET_DIR is honoured; the build uses its own
#                                            sub-directory so the cfg never reaches another build)
set -euo pipefail
GHOST="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
WORK="${1:-$(mktemp -d)}"
mkdir -p "$WORK"
cd "$GHOST"
export CARGO_TERM_COLOR=never
fail() { echo "mls-determinism: $*" >&2; exit 1; }

versions="$(cargo tree --locked -q -p ghost-client-mls -e normal,dev,no-proc-macro --target all --prefix none -f '{p}' \
  | awk '$1 == "getrandom" {print $2}' | sort -u)"
[ -n "$versions" ] || fail "no getrandom in the determinism world's graph (the check would pass vacuously)"
majors="$(sed -E 's/^v?([0-9]+\.[0-9]+).*/\1/' <<< "$versions" | sort -u)"
[ "$(grep -c . <<< "$majors")" = 1 ] || fail "more than one getrandom major in the graph: $(tr '\n' ' ' <<< "$versions") (S0-7 (c))"
echo "getrandom in the world's graph: $(tr '\n' ' ' <<< "$versions")"

target="${CARGO_TARGET_DIR:-$GHOST/target}"
target="${target%/}/mls-determinism"
RUSTFLAGS='--cfg getrandom_backend="custom"' CARGO_TARGET_DIR="$target" \
  cargo build --locked -q -p ghost-client-mls --example det_world
bin="$target/debug/examples/det_world"
[ -x "$bin" ] || [ ! -x "$bin.exe" ] || bin="$bin.exe"
[ -x "$bin" ] || fail "det_world was not built at $bin"

seed_a=000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
seed_b=ff0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
"$bin" "$seed_a" > "$WORK/run1.txt"
"$bin" "$seed_a" > "$WORK/run2.txt"
"$bin" "$seed_b" > "$WORK/run3.txt"
for r in run1 run2 run3; do
  grep -qx 'backend_active = true' "$WORK/$r.txt" || fail "$r: the seeded backend is not active (built without the cfg?)"
done
lines="$(grep -c . "$WORK/run1.txt")"
[ "$lines" -gt 50 ] || fail "run1 printed only $lines lines (the world did not run)"
if ! cmp -s "$WORK/run1.txt" "$WORK/run2.txt"; then
  diff "$WORK/run1.txt" "$WORK/run2.txt" | head -20 >&2 || true
  fail "two runs with one seed differ (V10-6)"
fi
cmp -s "$WORK/run1.txt" "$WORK/run3.txt" && fail "a run with another seed printed the same output (the seed does not drive it)"
echo "mls-determinism: two processes byte-identical over $lines lines ($(tail -1 "$WORK/run1.txt")); another seed differs"
