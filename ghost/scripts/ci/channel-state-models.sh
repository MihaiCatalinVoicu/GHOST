#!/usr/bin/env bash
# channel-state-models.sh — the local equivalent of the legacy
# .github/workflows/channel-state-models.yml (Phase 10 design faza10-forum.md §12.3, §19.34;
# ADR-58: CI is local). EM-3, the channel commit-arbitration state model, at its full bound:
# EM3_SCALE=full, EM3_BUDGET default 55 000 000 states, EM3_THREADS default 8, release profile
# with overflow checks on (the comment in the workflow: the PR bound runs in debug precisely for
# those checks), a 24 GB address-space ulimit, single-threaded test, report checked by
# ch-state-models-check.sh in its `full` mode.
#
# Usage: channel-state-models.sh [--work <dir>] [--budget <n>] [--threads <n>]
set -uo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GHOST="$(cd "$DIR/../../" && pwd)"
WORK="$GHOST/t2-reports/channel-state-models"
BUDGET=55000000; THREADS=8
while [ $# -gt 0 ]; do
  case "$1" in
    --work) WORK="$2"; shift 2 ;;
    --budget) BUDGET="$2"; shift 2 ;;
    --threads) THREADS="$2"; shift 2 ;;
    *) echo "channel-state-models: unknown argument: $1" >&2; exit 2 ;;
  esac
done
mkdir -p "$WORK"

( cd "$GHOST" && \
  [ "$(uname -s)" = Linux ] && ulimit -v 25165824 || true; \
  EM3_SCALE=full EM3_BUDGET="$BUDGET" EM3_THREADS="$THREADS" \
  CARGO_PROFILE_RELEASE_OVERFLOW_CHECKS=true \
    cargo test --locked --release -p ghost-client-mls-models --test state_models \
      -- --nocapture --test-threads 1 ) 2>&1 | tee "$WORK/channel-state-models.txt"
rc=${PIPESTATUS[0]}
if [ "$rc" = 0 ]; then
  bash "$GHOST/scripts/gates/ch-state-models-check.sh" "$WORK/channel-state-models.txt" full || rc=1
fi

grep -E "^EM-3 " "$WORK/channel-state-models.txt" || true
if [ "$rc" = 0 ]; then
  echo "channel-state-models: PASS (EM-3 full, budget $BUDGET; report: $WORK/channel-state-models.txt)"
else
  echo "channel-state-models: FAIL (report: $WORK/channel-state-models.txt)" >&2
fi
exit "$rc"
