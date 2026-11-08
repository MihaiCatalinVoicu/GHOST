#!/usr/bin/env bash
# Gate G-D6 (Phase 14 design faza14-distribution.md §12.1; graphs.txt's ghost-client-update
# row; §11.3's mutants pattern): the update decision crate stays pure and its mutation-test
# switch stays out of every shipped graph.
#
#   1. Allowlist: rust-dependency-allowlist.txt names ghost-client-update exactly once (its
#      graph adds no external crate beyond what the client graph already holds — the
#      allowlist itself covers the external names; G-D6 pins the workspace-entry count).
#   2. The shipped client graph (ghost-client-net's, the shipped library): ghost-client-update
#      is present — the clause would hold vacuously over a crate the graph lost — and no
#      feature of its own is enabled there: `mutants` exists for ghost-dm-host only (§11.3;
#      G-R2's method, the cargo tree read). The crate's `default` is the empty list, so any
#      `feature "` line naming it is the mutant switch or a new one — either fails here.
#   3. Purity (graphs.txt's row; the G-R8 source-scan discipline): client-core/update's
#      sources contain no std::fs, std::net, std::time, SystemTime, Instant, println!,
#      eprintln!, dbg!, log:: or tracing:: — the crate decides, it never touches the disk,
#      the network, the clock or a log.
#
# Needs cargo and the lock (rule 2) — runs in rust-gates.sh, not the static list. Self-test
# hooks, honoured for fixture roots only (a GHOST_ROOT other than this repository's ghost/):
#   GHOST_D6_TREE=<file>  a saved `cargo tree` output for the shipped-graph clause (the
#                         fixtures cannot run cargo; the UpdateMutants nm-stub precedent);
#   GHOST_D6_SOURCES=<dir> the source root for the purity clause.
source "$(dirname "${BASH_SOURCE[0]}")/common.sh"
ROOT="$GHOST_ROOT"
REAL_ROOT="$(cd "$GATES_DIR/../.." && pwd -P)"
fixture_root=0
[ "$(cd "$ROOT" && pwd -P)" != "$REAL_ROOT" ] && fixture_root=1
if [ "$fixture_root" = 0 ]; then
  for hook in GHOST_D6_TREE GHOST_D6_SOURCES; do
    if [ -n "${!hook:-}" ]; then echo "$hook is a self-test hook for fixture roots only" >&2; exit 2; fi
  done
fi

# Rule 1: exactly one allowlist entry.
allowlist="$ROOT/client-core/rust-dependency-allowlist.txt"
[ -f "$allowlist" ] || { echo "G-D6: $allowlist missing" >&2; exit 2; }
entries="$(grep -cx 'ghost-client-update' "$allowlist" || true)"
[ "$entries" = 1 ] || fail "rust-dependency-allowlist.txt names ghost-client-update $entries times, and the design's clause is exactly one"

# Rule 2: the shipped client graph holds ghost-client-update with no feature of its own.
if [ -n "${GHOST_D6_TREE:-}" ]; then
  [ -f "$GHOST_D6_TREE" ] || { echo "G-D6: GHOST_D6_TREE not found" >&2; exit 2; }
  graph="$(cat "$GHOST_D6_TREE")"
else
  command -v cargo >/dev/null || { echo "cargo not found" >&2; exit 2; }
  if ! graph="$(cd "$ROOT" && cargo tree -p ghost-client-net --locked -e normal 2>&1)"; then
    printf '%s\n' "$graph" >&2
    fail "cargo tree for ghost-client-net failed (a failed query is never read as an empty graph)"
    finish update-rust-purity
    exit 1
  fi
fi
lines="$(grep -c 'ghost-client-update' <<< "$graph" || true)"
[ "$lines" -ge 1 ] || fail "ghost-client-update is absent from the shipped client graph (the clause would hold vacuously)"
feature_lines="$(grep -E 'ghost-client-update.*feature "' <<< "$graph" || true)"
[ -z "$feature_lines" ] || fail "a feature of ghost-client-update's own is enabled in the shipped graph: $(head -1 <<< "$feature_lines")"

# Rule 3: the purity scan over the crate's sources.
src_root="${GHOST_D6_SOURCES:-$ROOT/client-core/update/src}"
[ -d "$src_root" ] || { echo "G-D6: $src_root missing" >&2; exit 2; }
PURITY_RE='\b(std::fs|std::net|std::time|SystemTime|Instant)\b|(println!|eprintln!|dbg!)|\b(log|tracing)::'
while IFS= read -r f; do
  [ -n "$f" ] || continue
  hits="$(LC_ALL=C.UTF-8 grep -nE -- "$PURITY_RE" "$f" 2>/dev/null || true)"
  [ -z "$hits" ] || while IFS= read -r line; do fail "${f#"$ROOT"/}:$line"; done <<< "$hits"
done < <(find "$src_root" -type f -name '*.rs' -print 2>/dev/null | sort)

finish update-rust-purity
