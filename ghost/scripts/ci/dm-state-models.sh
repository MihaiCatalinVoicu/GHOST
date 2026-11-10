#!/usr/bin/env bash
# dm-state-models.sh — the local equivalent of the legacy .github/workflows/dm-state-models.yml
# (Phase 9 design §19.24 item 5: the EM-1/EM-2 exhaustives the PR run cannot afford; ADR-58: CI
# is local). `cargo test --locked --release -p ghost-client-dm --test state_models` with the
# raised bounds: GHOST_DM_EM_SENDS = 3 user sends per side (EM-1), GHOST_DM_EM_WIRE = 3 envelopes
# in flight (EM-2), GHOST_DM_EM_BUDGET = 4 000 000 states. The workflow's dispatch inputs become
# arguments here; 4 and above need a raised budget of their own (the workflow's description).
#
# Usage: dm-state-models.sh [--work <dir>] [--sends <n>] [--wire <n>] [--budget <n>]
# The verdict is the test run's exit status; the report is evidence (the state counts are printed
# for the record, never as the verdict).
set -uo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GHOST="$(cd "$DIR/../../" && pwd)"
WORK="$GHOST/t2-reports/dm-state-models"
SENDS=3; WIRE=3; BUDGET=4000000
while [ $# -gt 0 ]; do
  case "$1" in
    --work) WORK="$2"; shift 2 ;;
    --sends) SENDS="$2"; shift 2 ;;
    --wire) WIRE="$2"; shift 2 ;;
    --budget) BUDGET="$2"; shift 2 ;;
    *) echo "dm-state-models: unknown argument: $1" >&2; exit 2 ;;
  esac
done
mkdir -p "$WORK"

( cd "$GHOST" && \
  GHOST_DM_EM_SENDS="$SENDS" GHOST_DM_EM_WIRE="$WIRE" GHOST_DM_EM_BUDGET="$BUDGET" \
    cargo test --locked --release -p ghost-client-dm --test state_models -- --nocapture ) \
  2>&1 | tee "$WORK/dm-state-models.txt"
rc=${PIPESTATUS[0]}

grep -E "^(EM-1|EM-2|rules 3-5):" "$WORK/dm-state-models.txt" || true
if [ "$rc" = 0 ]; then
  echo "dm-state-models: PASS (EM-1 sends/side: $SENDS; EM-2 wire: $WIRE; report: $WORK/dm-state-models.txt)"
else
  echo "dm-state-models: FAIL (report: $WORK/dm-state-models.txt)" >&2
fi
exit "$rc"
