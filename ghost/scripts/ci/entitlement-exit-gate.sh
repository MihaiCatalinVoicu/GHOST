#!/usr/bin/env bash
# entitlement-exit-gate.sh — the local equivalent of the legacy
# .github/workflows/entitlement-exit-gate.yml (ADR-58: CI is local). The gate's shard job,
# unchanged: `./gradlew :entitlement:testDebugUnitTest --rerun` with the exhaustive harness over
# 20 000 seeded worlds, sharded SHARD/SHARDS, then the workflow's inline report check on
# entitlement/build/harness/report.txt (this shard's seeded-worlds line, the crash line with
# injected == caught, 24 E-A..E-J enumeration lines in both journal modes, 4 E-R lines, the
# 18-run mutant line, 18 DETECTED, 3 NI-K lines). Locally one shard runs at a time; loop the
# shards, or run one with --shard.
#
# Usage: entitlement-exit-gate.sh [--shard <i>] [--shards <n>] [--seeds <n>] [--all]
#   --shard/--shards  run one shard (default: shard 0 of 12, like one matrix leg)
#   --all             every shard 0..SHARDS-1 sequentially, resumable (done-markers)
set -uo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GHOST="$(cd "$DIR/../../" && pwd)"
ANDROID="$GHOST/android"
WORK="$ANDROID/entitlement/build/harness"
SHARD=0; SHARDS=12; SEEDS=20000; ALL=0
while [ $# -gt 0 ]; do
  case "$1" in
    --shard) SHARD="$2"; shift 2 ;;
    --shards) SHARDS="$2"; shift 2 ;;
    --seeds) SEEDS="$2"; shift 2 ;;
    --all) ALL=1; shift ;;
    *) echo "entitlement-exit-gate: unknown argument: $1" >&2; exit 2 ;;
  esac
done
mkdir -p "$WORK"

check_report() { # shard — the workflow's inline check, ::error:: lines kept as plain messages
  local s="$1" report="$WORK/report.txt" fail=0
  [ -f "$report" ] || { echo "entitlement-exit-gate: no harness report at $report" >&2; return 1; }
  need() { if ! grep -Eq "$1" "$report" 2>/dev/null; then echo "harness report: no $2" >&2; fail=1; fi; }
  count() {
    local n; n="$(grep -Ec "$1" "$report" 2>/dev/null || true)"
    if [ "$n" != "$2" ]; then echo "harness report: ${n:-0} $3, expected $2" >&2; fail=1; fi
  }
  local seeds; seeds=$(( (SEEDS - 1 - s) / SHARDS + 1 ))
  need "^entitlement seeded worlds: $seeds seeds, " "seeded-worlds line for this shard's $seeds seeds"
  local crashes; crashes="$(sed -n 's/^entitlement crashes injected=\([0-9]*\) caught=\([0-9]*\)$/\1 \2/p' "$report" 2>/dev/null || true)"
  if [ -z "$crashes" ] || [ "${crashes% *}" != "${crashes#* }" ]; then
    echo "harness report: no crash line, or injected and caught crashes differ" >&2; fail=1
  fi
  count '^E-[A-J][^ ]* (DELETE|WAL): K=[1-9]' 24 "enumeration lines (E-A ... E-J in both journal modes)"
  count '^E-R[^ ]* (DELETE|WAL): K=[1-9]' 4 "enumeration lines (E-R/funded and E-R/funded-plain in both journal modes)"
  need '^entitlement mutants: 18 run ' "mutant line (18 run)"
  count ' DETECTED: ' 18 "detected mutants"
  count '^NI-K ' 3 "NI-K lines"
  return "$fail"
}

run_shard() { # index
  local s="$1"
  if [ -f "$WORK/.shard-$s.done" ]; then
    echo "entitlement-exit-gate: shard $s already done (marker $(cat "$WORK/.shard-$s.done")), skipping"
    return "$(cat "$WORK/.shard-$s.done")"
  fi
  # The report path is fixed by the harness; keep per-shard copies for the record.
  rm -f "$WORK/report.txt"
  echo "entitlement-exit-gate: shard $s/$SHARDS (exhaustive, $SEEDS seeded worlds)"
  ( cd "$ANDROID" && ./gradlew --no-daemon :entitlement:testDebugUnitTest --rerun \
      -Dghost.entitlement.seeds="$SEEDS" -Dghost.entitlement.exhaustive=full \
      -Dghost.entitlement.shard="$s/$SHARDS" ) > "$WORK/shard-$s.log" 2>&1
  local grc=$?
  if [ "$grc" -ne 0 ]; then
    echo "$grc" > "$WORK/.shard-$s.done"
    echo "entitlement-exit-gate: shard $s FAIL (harness; log: $WORK/shard-$s.log)" >&2
    return 1
  fi
  cp "$WORK/report.txt" "$WORK/report-$s.txt" 2>/dev/null || true
  check_report "$s" >> "$WORK/shard-$s.log" 2>&1
  local crc=$?
  echo "$crc" > "$WORK/.shard-$s.done"
  [ "$crc" -eq 0 ] && echo "entitlement-exit-gate: shard $s PASS" || \
    echo "entitlement-exit-gate: shard $s FAIL (report check; log: $WORK/shard-$s.log)" >&2
  return "$crc"
}

rc=0
if [ "$ALL" = 1 ]; then
  for s in $(seq 0 $((SHARDS - 1))); do run_shard "$s" || rc=1; done
else
  run_shard "$SHARD" || rc=1
fi
exit "$rc"
