#!/usr/bin/env bash
# The EM-3 report check (Phase 10 design faza10-forum.md §12.3, §19.34, §19.34.1): an EM-3 run may
# pass only with a complete report of its scale.
#   ch-state-models-check.sh <report> pr|full
# <report> is the output of `cargo test -p ghost-client-mls-models --test state_models -- --nocapture
# --test-threads 1` (ci.yml's rust job writes it at the pull-request bound, channel-state-models.yml
# at the full bound). The check requires:
#   - a line for every control scenario of the scale, with at least its pinned number of states (a
#     scenario that quietly shrank fails), every reachability query reached ("reach R/R", R > 0),
#     every terminal property it checks live in some quiescent state ("live P-X N/T", N > 0; P-DETECT's
#     clauses, obligations a correct run discharges, are exempt) and the bounds it reached, and the
#     controls' and the bounds' totals naming the scale;
#   - every registered mutant killed by its named check site, and the mutants' total;
#   - every check site first broken by a registered run ("0 by none");
#   - the arithmetic line, every finding's reproduction and correction lines and the corrections'
#     rerun with 0 failures (at the full bound with F-2's beacons and MM-2's rerun too);
#   - libtest's final "test result: ok" with every test passed, and no FAILED, SURVIVED or NOT killed.
# A missing report, a missing line or a failure fails the check (exit 1); usage errors exit 2.
# The report is read once and matched with bash builtins (no process per item); CRLF line ends are
# accepted.
set -euo pipefail
report="${1:-}"
scale="${2:-}"
[ -n "$report" ] && [ -n "$scale" ] || { echo "usage: ch-state-models-check.sh <report> pr|full" >&2; exit 2; }
case "$scale" in pr|full) ;; *) echo "unknown scale: $scale" >&2; exit 2 ;; esac
fail=0
bad() { echo "CH-STATE-MODELS-FAIL: $*" >&2; fail=1; }
[ -f "$report" ] || { echo "CH-STATE-MODELS-FAIL: no report at $report" >&2; exit 1; }
mapfile -t lines < "$report"
# One element at a time: an array-wide ${lines[@]%$'\r'} keeps the CR under Git Bash 5.3.
for i in "${!lines[@]}"; do lines[i]="${lines[i]%$'\r'}"; done
# The first line matching the extended regular expression $1, in $hit.
match() {
  local l
  for l in "${lines[@]}"; do
    if [[ $l =~ $1 ]]; then hit="$l"; return 0; fi
  done
  return 1
}
hit=""

# The control scenarios (scenarios::controls) with the states each explored when this check was
# last pinned (§19.34.1's table): a run may explore more, never fewer. SC-SPAM-CURRENT runs at the
# full bound only.
declare -A floor_pr=(
  [SC-CONC]=136293 [SC-LATE]=80827 [SC-GRIND]=49896 [SC-JOIN]=107852 [SC-REMOVE]=74755
  [SC-GOV]=3927 [SC-FLOOD]=77270 [SC-INDET]=110435 [SC-JUNK]=1561 [SC-CLOCKS]=126347
  [SC-ADV]=2807 [SC-CATCHUP]=368 [SC-FORK]=154318 [SC-MISSED]=154318 [SC-OWNER]=464
  [SC-SILENT]=42546 [SC-PARTITION]=203590 [SC-SPAM-DRAIN]=476 [SC-REPLAY]=146639
)
declare -A floor_full=(
  [SC-CONC]=4224040 [SC-LATE]=8731748 [SC-GRIND]=5813581 [SC-JOIN]=6291679 [SC-REMOVE]=360375
  [SC-GOV]=3927 [SC-FLOOD]=1413342 [SC-INDET]=171131 [SC-JUNK]=19746 [SC-CLOCKS]=126347
  [SC-ADV]=2807 [SC-CATCHUP]=3568 [SC-FORK]=24458759 [SC-MISSED]=154318 [SC-OWNER]=464
  [SC-SILENT]=189386 [SC-PARTITION]=277365 [SC-SPAM-DRAIN]=595 [SC-REPLAY]=698239
  [SC-SPAM-CURRENT]=14615329
)
controls=(SC-CONC SC-LATE SC-GRIND SC-JOIN SC-REMOVE SC-GOV SC-FLOOD SC-INDET SC-JUNK SC-CLOCKS SC-ADV
  SC-CATCHUP SC-FORK SC-MISSED SC-OWNER SC-SILENT SC-PARTITION SC-SPAM-DRAIN SC-REPLAY)
[ "$scale" = pr ] || controls+=(SC-SPAM-CURRENT)
# The registered mutants (tests/state_models.rs, MUTANTS).
mutants=(Rank255Proposals PostCommitRank Rank255NeverCandidate SwapWithoutEvidence LocalHistory
  NoSwapOfLowerRank NewSigner LifetimeByClock LifetimePending HashOnly NoSuccessors NoWindow OwnUnverified
  NoStoreHourAnchor ClearIndeterminate NoListingPass OwnAnchorAtPass UnverifiedOwnNoCandidate WelcomeAtPass
  NotSticky Rank255Blocks FreshWork NoSkip DropLoserWork CountDraining NoBranchDeath RecountProgress NoStale
  NoPartition RecountStale NoHold NoRate NoRotation PreCommitGeneration RejoinRotates NoAdmission
  RejoinNoFreshness)
findings=("F-1 (a) reproduced" "F-1 (b) reproduced" "F-1 (c) reproduced" "F-1 corrected"
  "F-2 (a) reproduced" "F-2 (b) reproduced" "F-2 (c) reproduced" "F-2 (a) closed by settle beacons"
  "F-2 (b) remains with settle beacons" "F-2 (c) remains with settle beacons"
  "F-3 (a) reproduced" "F-3 (b) reproduced" "F-3 (a) as first worded fails" "F-3 corrected"
  "F-4 reproduced" "F-4 consequence" "F-4 fetched-copy reading clean"
  "F-5 reproduced" "F-5 corrected")
[ "$scale" = pr ] || findings+=("F-5 leaves MM-2 equivalent")
tests=10

for c in "${controls[@]}"; do
  if ! match "^EM-3 ${c} [^:]*: "; then
    bad "no line for the control $c"
    continue
  fi
  if ! [[ $hit =~ :\ ([0-9]+)\ states,\ .*\ reach\ ([0-9]+)/([0-9]+),\ live\ (.*),\ bounds\ epochs\ [0-9]+/[0-9]+, ]]; then
    bad "$c: ${hit:0:120}"
    continue
  fi
  states="${BASH_REMATCH[1]}" got="${BASH_REMATCH[2]}" want="${BASH_REMATCH[3]}" live="${BASH_REMATCH[4]}"
  if [ "$scale" = pr ]; then pinned="${floor_pr[$c]}"; else pinned="${floor_full[$c]}"; fi
  [ "$states" -gt 1 ] || bad "$c explored $states state"
  [ "$states" -ge "$pinned" ] || bad "$c explored $states states, fewer than the $pinned pinned"
  [ "$want" -gt 0 ] || bad "$c names no reachability query"
  [ "$got" = "$want" ] || bad "$c reached $got of its $want flows"
  # Every terminal property but P-DETECT's clauses had its premise somewhere.
  rest="$live"
  while [[ $rest =~ ^(P-[A-Za-z0-9/-]+)\ ([0-9]+)/([0-9]+)\ ?(.*)$ ]]; do
    name="${BASH_REMATCH[1]}" n="${BASH_REMATCH[2]}" rest="${BASH_REMATCH[4]}"
    if [ "$n" = 0 ] && [[ $name != P-DETECT/* ]]; then bad "$c: $name never had its premise"; fi
  done
  [ -z "$rest" ] || [ "$rest" = none ] || bad "$c: unreadable live list '$rest'"
done
n="${#controls[@]}"
match "^EM-3 controls \(${scale}\): ${n} scenarios, [0-9]+ states" \
  || bad "no 'EM-3 controls (${scale}): ${n} scenarios' line (the report is not of the ${scale} scale, or a control is missing)"
match "^EM-3 bounds \(${scale}\): at most [0-9]+ epoch transitions" || bad "no 'EM-3 bounds (${scale})' line"

for m in "${mutants[@]}"; do
  match "^EM-3 mutant ${m} \[[^]]*\]: killed by P-[A-Za-z0-9/-]+ in " || bad "the mutant $m was not killed"
done
n="${#mutants[@]}"
match "^EM-3 mutants \(${scale}\): ${n} run, ${n} killed$" || bad "no 'EM-3 mutants (${scale}): ${n} run, ${n} killed' line"
match '^EM-3 sites: [0-9]+ check sites, .*, 0 by none$' || bad "no 'EM-3 sites: … 0 by none' line"

match '^EM-3 arithmetic: 7 checks hold$' || bad "no 'EM-3 arithmetic: 7 checks hold' line"
for f in "${findings[@]}"; do
  found=0
  for l in "${lines[@]}"; do
    if [[ $l == "EM-3 finding ${f}"* ]]; then found=1; break; fi
  done
  [ "$found" = 1 ] || bad "no line 'EM-3 finding ${f}'"
done
n="${#controls[@]}"
if [ "$scale" = pr ]; then
  match "^EM-3 corrections: ${n} controls rerun .* \(pr\), 0 failures$" \
    || bad "no 'EM-3 corrections: ${n} controls rerun …, 0 failures' line"
else
  match "^EM-3 corrections: ${n} controls rerun .* \(full\), 19 with F-2's beacons too \(pr\), 0 failures among them, 0 failures$" \
    || bad "no 'EM-3 corrections: ${n} controls rerun …, 19 with F-2's beacons too (pr), … 0 failures' line"
fi

if match '^EM-3 .*(: FAILED|: SURVIVED |: NOT killed by )'; then
  bad "the report names a failed control or a surviving mutant"
fi
match "^test result: ok\. ${tests} passed; 0 failed" || bad "no 'test result: ok. ${tests} passed; 0 failed'"
[ "$fail" = 0 ] || exit 1
echo "[ch-state-models-check] OK ($scale)"
