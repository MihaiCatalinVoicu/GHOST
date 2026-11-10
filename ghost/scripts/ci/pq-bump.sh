#!/usr/bin/env bash
# pq-bump.sh — the local equivalent of the legacy .github/workflows/pq-bump.yml (Phase 9 design
# §2.8's bump checklist as a mutant gate: PQ1 and PQ5 hold PM-32; ADR-58: CI is local). The
# workflow's single step is the existing gate scripts/gates/pq-mutants.sh — eleven debug builds
# of one crate's test binary (the tree and ten mutants), sixteen PQ tests; here it is wrapped
# for the local convention: output teed to a kept report, exit status is the verdict.
#
# Usage: pq-bump.sh [--work <dir>]
set -uo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GHOST="$(cd "$DIR/../../" && pwd)"
WORK="$GHOST/t2-reports/pq-bump"
while [ $# -gt 0 ]; do
  case "$1" in
    --work) WORK="$2"; shift 2 ;;
    *) echo "pq-bump: unknown argument: $1" >&2; exit 2 ;;
  esac
done
mkdir -p "$WORK"

( cd "$GHOST" && bash scripts/gates/pq-mutants.sh ) 2>&1 | tee "$WORK/pq-bump.txt"
rc=${PIPESTATUS[0]}
[ "$rc" = 0 ] && echo "pq-bump: PASS (report: $WORK/pq-bump.txt)" || \
  echo "pq-bump: FAIL (report: $WORK/pq-bump.txt)" >&2
exit "$rc"
