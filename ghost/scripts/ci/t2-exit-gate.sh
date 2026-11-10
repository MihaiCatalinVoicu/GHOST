#!/usr/bin/env bash
# t2-exit-gate.sh — the local equivalent of the legacy .github/workflows/t2-exit-gate.yml (design
# §19.27/§19.31: T2 la scara porții + mutanții M1–M24; ADR-58: CI is local). Two jobs, the
# workflow's commands unchanged:
#
#   gate     — `cargo test --release --locked -p ghost-issuer --test t2_unlinkability t2_exit_gate
#              -- --ignored --exact --nocapture` per seed-pair index 0-9, with GHOST_T2_SCALE=gate
#              and GHOST_T2_SEEDS=<index>; each pair's report is judged by t2-report-check.sh gate
#              (a PASS line per check plus the final "T2 RESULT: PASS").
#   mutants  — `cargo test --release --locked -p ghost-issuer --test t2_mutants -- --ignored
#              --nocapture`, judged by t2-report-check.sh mutants.
#   all      — gate, then mutants (the workflow's two jobs; a failing pair stops the gate half,
#              exactly like fail-fast: false + the per-pair report check failing that pair's job —
#              here the summary at the end names every failing pair).
#
# Usage: t2-exit-gate.sh [gate|mutants|all] [--work <dir>] [--from <index>]
#   --work   report/marker directory (default: <repo>/t2-reports)
# Sequential and resumable: done-markers per pair hold the cargo exit code, so a rerun with
# --from skips finished pairs. Exit 0 only when everything run passed every check.
set -uo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GHOST="$(cd "$DIR/../../" && pwd)"

cmd="all"; WORK="$GHOST/t2-reports"; FROM=0
while [ $# -gt 0 ]; do
  case "$1" in
    gate|mutants|all) cmd="$1"; shift ;;
    --work) WORK="$2"; shift 2 ;;
    --from) FROM="$2"; shift 2 ;;
    *) echo "t2-exit-gate: unknown argument: $1" >&2; exit 2 ;;
  esac
done

export GHOST_T2_SCALE=gate
export GHOST_T2_TMP="${GHOST_T2_TMP:-/dev/shm}"
mkdir -p "$WORK/pairs"
rc=0
fails=()

run_pair() { # index
  local i="$1"
  local report="$WORK/pairs/t2-gate-$i.txt"
  if [ -f "$WORK/pairs/pair-$i.done" ]; then
    local m; m="$(cat "$WORK/pairs/pair-$i.done")"
    echo "t2-exit-gate: pair $i already done (marker $m), skipping"
    [ "$m" = 0 ] || { rc=1; fails+=("pair $i (marker)"); }
    return
  fi
  echo "t2-exit-gate: pair $i (T2 at gate scale)"
  ( cd "$GHOST" && \
    GHOST_T2_SEEDS=$i GHOST_T2_REPORT="$report" GHOST_T2_TRUTH="$WORK/truth" \
      cargo test --release --locked -p ghost-issuer --test t2_unlinkability t2_exit_gate \
      -- --ignored --exact --nocapture ) > "$WORK/pairs/pair-$i.log" 2>&1
  local crc=$?
  echo "$crc" > "$WORK/pairs/pair-$i.done"
  if [ "$crc" -ne 0 ]; then rc=1; fails+=("pair $i (cargo)"); return; fi
  bash "$GHOST/scripts/gates/t2-report-check.sh" "$report" gate >> "$WORK/pairs/pair-$i.log" 2>&1 || \
    { rc=1; fails+=("pair $i (report check)"); }
}

run_mutants() {
  local report="$WORK/t2-mutants.txt"
  if [ -f "$WORK/mutants.done" ]; then
    local m; m="$(cat "$WORK/mutants.done")"
    echo "t2-exit-gate: mutants already done (marker $m), skipping"
    [ "$m" = 0 ] || { rc=1; fails+=("mutants (marker)"); }
    return
  fi
  echo "t2-exit-gate: mutants M1-M24 (release)"
  ( cd "$GHOST" && \
    GHOST_T2_TMP="${GHOST_T2_TMP:-/dev/shm}" \
      cargo test --release --locked -p ghost-issuer --test t2_mutants -- --ignored --nocapture ) \
    > "$report" 2>&1
  local crc=$?
  echo "$crc" > "$WORK/mutants.done"
  if [ "$crc" -ne 0 ]; then rc=1; fails+=("mutants (cargo)"); return; fi
  bash "$GHOST/scripts/gates/t2-report-check.sh" "$report" mutants >> "$report" 2>&1 || \
    { rc=1; fails+=("mutants (report check)"); }
}

case "$cmd" in
  gate)   for i in $(seq "$FROM" 9); do run_pair "$i"; done ;;
  mutants) run_mutants ;;
  all)    for i in $(seq "$FROM" 9); do run_pair "$i"; done
          run_mutants ;;
esac

if [ "$rc" = 0 ]; then
  echo "t2-exit-gate: PASS ($cmd)"
else
  echo "t2-exit-gate: FAIL ($cmd): ${fails[*]}" >&2
fi
exit "$rc"
