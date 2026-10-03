#!/usr/bin/env bash
# The EM-3 report check (Phase 10 design faza10-forum.md §12.3, §19.34): an EM-3 run may pass only
# with a complete report of its scale.
#   ch-state-models-check.sh <report> pr|full
# <report> is the output of `cargo test -p ghost-client-mls-models --test state_models -- --nocapture
# --test-threads 1` (channel-state-models.yml writes it at the full bound; the pull-request bound is
# the rust job's run). The check requires:
#   - a line for every control scenario of the scale, with states explored and every reachability
#     query reached ("reach R/R", R > 0), and the controls' total naming the scale and the count;
#   - every registered mutant killed by its named property, and the mutants' total;
#   - the arithmetic line, every finding's reproduction and correction lines (F-1 … F-5) and the
#     corrections' rerun with 0 failures;
#   - libtest's final "test result: ok" with every test passed, and no FAILED, SURVIVED or NOT killed.
# A missing report, a missing line or a failure fails the check (exit 1); usage errors exit 2.
# The report is read once and matched with bash builtins (no process per item).
set -euo pipefail
report="${1:-}"
scale="${2:-}"
[ -n "$report" ] && [ -n "$scale" ] || { echo "usage: ch-state-models-check.sh <report> pr|full" >&2; exit 2; }
case "$scale" in pr|full) ;; *) echo "unknown scale: $scale" >&2; exit 2 ;; esac
fail=0
bad() { echo "CH-STATE-MODELS-FAIL: $*" >&2; fail=1; }
[ -f "$report" ] || { echo "CH-STATE-MODELS-FAIL: no report at $report" >&2; exit 1; }
mapfile -t lines < "$report"
lines=("${lines[@]%$'\r'}")
# The first line matching the extended regular expression $1, in $hit.
match() {
  local l
  for l in "${lines[@]}"; do
    if [[ $l =~ $1 ]]; then hit="$l"; return 0; fi
  done
  return 1
}
hit=""

# The control scenarios (scenarios::controls); SC-SPAM-CURRENT runs at the full bound only.
controls=(SC-CONC SC-LATE SC-GRIND SC-JOIN SC-REMOVE SC-GOV SC-FLOOD SC-INDET SC-JUNK SC-CLOCKS SC-ADV
  SC-CATCHUP SC-FORK SC-OWNER SC-SILENT SC-PARTITION SC-SPAM-DRAIN SC-REPLAY)
[ "$scale" = pr ] || controls+=(SC-SPAM-CURRENT)
# The registered mutants (tests/state_models.rs, MUTANTS).
mutants=(Rank255Proposals PostCommitRank SwapWithoutEvidence LocalHistory NoSwapOfLowerRank NewSigner
  LifetimeByClock LifetimePending HashOnly NoSuccessors NoWindow OwnUnverified NoStoreHourAnchor
  ClearIndeterminate NoListingPass OwnAnchorAtPass WelcomeAtPass NotSticky Rank255Blocks FreshWork NoSkip
  DropLoserWork CountDraining NoBranchDeath NoStale NoPartition NoHold NoRate NoRotation
  PreCommitGeneration RejoinNoFreshness)
findings=("F-1 (a) reproduced" "F-1 (b) reproduced" "F-1 corrected" "F-2 (a) reproduced"
  "F-2 (b) reproduced" "F-2 (a) closed by settle beacons" "F-2 (b) remains with settle beacons"
  "F-3 (a) reproduced" "F-3 (b) reproduced" "F-3 corrected" "F-4 reproduced" "F-5 reproduced"
  "F-5 corrected")
tests=9

for c in "${controls[@]}"; do
  if ! match "^EM-3 ${c} [^:]*: "; then
    bad "no line for the control $c"
    continue
  fi
  if ! [[ $hit =~ :\ ([0-9]+)\ states,\ .*\ reach\ ([0-9]+)/([0-9]+), ]]; then
    bad "$c: ${hit:0:120}"
    continue
  fi
  states="${BASH_REMATCH[1]}" got="${BASH_REMATCH[2]}" want="${BASH_REMATCH[3]}"
  [ "$states" -gt 1 ] || bad "$c explored $states state"
  [ "$want" -gt 0 ] || bad "$c names no reachability query"
  [ "$got" = "$want" ] || bad "$c reached $got of its $want flows"
done
n="${#controls[@]}"
match "^EM-3 controls \(${scale}\): ${n} scenarios, [0-9]+ states" \
  || bad "no 'EM-3 controls (${scale}): ${n} scenarios' line (the report is not of the ${scale} scale, or a control is missing)"

for m in "${mutants[@]}"; do
  match "^EM-3 mutant ${m} \[[^]]*\]: killed by P-[A-Z0-9-]+ in " || bad "the mutant $m was not killed"
done
n="${#mutants[@]}"
match "^EM-3 mutants \(${scale}\): ${n} run, ${n} killed$" || bad "no 'EM-3 mutants (${scale}): ${n} run, ${n} killed' line"

match '^EM-3 arithmetic: 7 checks hold$' || bad "no 'EM-3 arithmetic: 7 checks hold' line"
for f in "${findings[@]}"; do
  found=0
  for l in "${lines[@]}"; do
    if [[ $l == "EM-3 finding ${f}"* ]]; then found=1; break; fi
  done
  [ "$found" = 1 ] || bad "no line 'EM-3 finding ${f}'"
done
n="${#controls[@]}"
match "^EM-3 corrections: ${n} controls rerun .*, 0 failures$" \
  || bad "no 'EM-3 corrections: ${n} controls rerun …, 0 failures' line"

if match '^EM-3 .*(: FAILED|: SURVIVED |: NOT killed by )'; then
  bad "the report names a failed control or a surviving mutant"
fi
match "^test result: ok\. ${tests} passed; 0 failed" || bad "no 'test result: ok. ${tests} passed; 0 failed'"
[ "$fail" = 0 ] || exit 1
echo "[ch-state-models-check] OK ($scale)"
