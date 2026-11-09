#!/usr/bin/env bash
# The update gate-job report check (Phase 14 design faza14-distribution.md §12.1 G-D7, §11.2 the
# NI-U twins, §11.3 the mutants), built on the `dm-report-check.sh` rule: **a report is evidence
# only if something refuses an incomplete one, and a report never claims more than it measured.**
#
#   update-report-check.sh <report> gate    the gate job's fragment (`:update:testDebugUnitTest
#                                           -Dghost.update.gate=1`, 50 clients x 120 days): the
#                                           mutant count with both sides equal, one line per
#                                           registered killable mutant, the NI-U1..NI-U4 twin
#                                           lines equal, the named worlds' lines, the throughput
#                                           line, and the drill lines (the named worlds sampled
#                                           green inside the gate run, the twins re-run at the
#                                           gate's day count);
#   update-report-check.sh <report> pr      the same consistency lines at the PR scale (the
#                                           default suite writes the same fragment): the drill
#                                           lines are not required, and the last throughput line
#                                           must not be a gate-scale claim.
#
# The fragment (`android/update/build/update-mutants/report.txt`) is written by `MutantReportTest`
# from what the run recorded, and `report()` appends a line only if it is not already there, so a
# fragment can hold lines of several runs; the LAST `update gate scale:` throughput line is read
# as the most recent run's, which is what the `gate` kind pins (a PR-scale last run cannot pass
# as the gate job's report — the dm-report-check scale rule).
#
# "Refuses a report claiming more than it measured", concretely: the headline's two numbers must
# be equal and equal to the count of `<id>: detected` lines; every killable mutant of the pinned
# registry must account for itself with exactly one line (a mutant with no line is a claim, the
# dm-report-check rule); a line for an id outside the registry, a duplicate, a `skipped` row (the
# host library predates the mutant — the fragment's own skip message says to rebuild ghost-dm-
# host, which the gate job must do, not paper over) or any `NOT DETECTED` is refused; the twin
# lines must say `equal`; the throughput line must show the world did something (a run that
# scheduled no job proves nothing); at the gate scale the drill lines must be present.
#
# The killable registry is pinned here, not read from the Kotlin sources, exactly as
# dm-report-check pins its mutant list: it grows per slice and this gate's list and count comment
# grow with it. 30 killable rows as of slice S6f — 27 MC-D rows of `MutantKills` (MC-D4 is not
# wired — the duplicate-counting site sits in ghost-client-release, outside the update crate's
# selector; MC-D13 and MC-D15 are wired but their kills need a layer the JVM byte seam does not
# reach) plus the 3 killable PM-D rows of `PmMutantKills`. The remaining design rows are held by
# the twins (PM-D1/2/6/8/11/12), the byte seam (PM-D3/4/5/10), the crafted suite (MC-D27's second
# kill) and G-D11 (NI-U5), each of which the fragment accounts for in a pinned line.
set -euo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GHOST_ROOT="${GHOST_ROOT:-$(cd "$DIR/../.." && pwd)}"

report="${1:-}"
kind="${2:-}"
[ -n "$report" ] && [ -n "$kind" ] || { echo "usage: update-report-check.sh <report> gate|pr" >&2; exit 2; }
case "$kind" in gate|pr) ;; *) echo "unknown report kind: $kind" >&2; exit 2 ;; esac
[ -f "$report" ] || { echo "UPDATE-REPORT-FAIL: no report at $report" >&2; exit 1; }

fail=0
bad() { echo "UPDATE-REPORT-FAIL: $*" >&2; fail=1; }

# --- the mutant block ---------------------------------------------------------------------------
# The pinned killable registry (slice S6f): 27 MC-D + 3 PM-D rows.
killable="MC-D1 MC-D2 MC-D3 MC-D5 MC-D6 MC-D7 MC-D8 MC-D9 MC-D10 MC-D11 MC-D12 MC-D14 MC-D16 \
MC-D17 MC-D18 MC-D20 MC-D21 MC-D22 MC-D23 MC-D25 MC-D26 MC-D27 MC-D28 MC-D29 MC-D30 MC-D31 MC-D32 \
PM-D7 PM-D9 PM-D13"
killable_count=30

# The headline: both numbers equal (a report claiming more detected than ran is refused), pinned
# to the killable registry (a run whose host library skipped rows measured less than the registry
# holds — rebuild ghost-dm-host, do not paper over it).
grep -qxF "update mutants: $killable_count run, $killable_count detected" "$report" \
  || bad "the mutant line is not 'update mutants: $killable_count run, $killable_count detected'"
headline="$(sed -nE 's/^update mutants: ([0-9]+) run, ([0-9]+) detected$/\1 \2/p' "$report" | sed -n '1p')"
if [ -n "$headline" ]; then
  [ "${headline% *}" = "${headline#* }" ] || bad "the headline claims ${headline#* } detected over ${headline% *} run: more detected than measured"
fi

# Exactly one accounting line per registered mutant: detected, and never skipped (the host
# library predates the mutant), NOT DETECTED, duplicated, or unknown to the registry.
for id in $killable; do
  n="$(grep -cE "^${id}: (detected|skipped)" "$report" || true)"
  [ "$n" = 1 ] || bad "$id: $n accounting lines, and the registry holds exactly one row for it"
  grep -qxF "${id}: detected" "$report" || bad "$id is not detected (a skipped or NOT DETECTED row is a host library or kill regression, never gate evidence)"
done
stray="$(grep -oE '^(MC-D|PM-D)[0-9]+: (detected|skipped|NOT DETECTED)' "$report" | sed -E 's/: .*//' | sort -u || true)"
while IFS= read -r id; do
  [ -n "$id" ] || continue
  case " $killable " in
    *" $id "*) ;;
    *) bad "$id has a report line but is not in the killable registry: a kill no selector runs" ;;
  esac
done <<< "$stray"
detected_lines="$(grep -cE '^(MC-D|PM-D)[0-9]+: detected$' "$report" || true)"
[ "$detected_lines" = "$killable_count" ] || bad "$detected_lines detected lines for the headline's $killable_count run: the count and the lines disagree"

# The rows this slice does not kill, each accounted in a pinned line (the writer hard-codes them;
# their wording may evolve, their presence and prefix may not).
accounted='MC-D4: not wired — '
grep -qF -- "$accounted" "$report" || bad "no accounting line for MC-D4 (not wired: the duplicate-counting site is outside the update crate's selector)"
grep -qF 'MC-D13: wired in ghost-client-net'"'"'s fetch; ' "$report" || bad "no accounting line for MC-D13 (wired in ghost-client-net's fetch; the JVM byte seam cannot drive it)"
grep -qF 'MC-D15: wired; ' "$report" || bad "no accounting line for MC-D15 (wired; the arms sit behind the whole-file hash)"
grep -qF 'MC-D27: wired; the kill needs a v3.1-lineage APK (the crafted suite)' "$report" \
  || bad "no accounting line for MC-D27's second kill (the crafted suite)"
grep -qF 'PM-D1/PM-D2/PM-D6/PM-D8/PM-D11/PM-D12: killed in the NI-U twins (the job model of slice S6d)' "$report" \
  || bad "no accounting line for the PM rows the NI-U twins kill"
grep -qF 'PM-D3/PM-D4/PM-D5/PM-D10: seam-held (request headers, the root path and an out-of-set onion never cross the byte seam)' "$report" \
  || bad "no accounting line for the seam-held PM rows"
grep -qF 'NI-U5: wire-held' "$report" || bad "no NI-U5 accounting line (G-D11's wire transcript)"

# --- the NI-U twins (§11.2) ---------------------------------------------------------------------
for twin in NI-U1 NI-U2 NI-U3 NI-U4; do
  grep -qxF "${twin}: equal" "$report" || bad "${twin} is not reported equal"
done
grep -qxF 'NI-U4-anchor-change: mirror choice differs by design (L10-D22), nothing else' "$report" \
  || bad "no NI-U4-anchor-change line (the roots' anchor-mirror choice differs by design, and the line pins that it is the only difference)"

# --- the named worlds ---------------------------------------------------------------------------
grep -qxF 'root-swap world: ROOT_UNLOGGED, no state change' "$report" || bad "no root-swap world line"
grep -qxF 'recovery-epoch world: new epoch from the embedded chain; the recovery half follows only it; v(n+6) reaches only the old half' "$report" \
  || bad "no recovery-epoch world line"
grep -qxF 'revocation world: removed-key manifest BAD_SIGNATURE at any sequence; the old root'"'"'s manifest holds no authority; a manifest under the new root resumes normality' "$report" \
  || bad "no revocation world line"

# --- the throughput line, and the drill lines at the gate scale ----------------------------------
throughput_re='^update gate scale: [0-9]+ worlds x [0-9]+ clients x [0-9]+ days, [0-9]+ jobs, [0-9]+ update runs, [0-9]+ hostile-aborted runs, [0-9]+ hostile-mode cycles, wall [0-9]+ms \(this machine\)$'
n="$(grep -cE "$throughput_re" "$report" || true)"
[ "$n" -ge 1 ] || bad "no 'update gate scale:' throughput line of the documented shape"
last="$(grep -E "$throughput_re" "$report" | tail -1)"
jobs="$(printf '%s\n' "$last" | sed -nE 's/^update gate scale: [0-9]+ worlds x [0-9]+ clients x [0-9]+ days, ([0-9]+) jobs,.*/\1/p')"
runs="$(printf '%s\n' "$last" | sed -nE 's/^update gate scale: [0-9]+ worlds x [0-9]+ clients x [0-9]+ days, [0-9]+ jobs, ([0-9]+) update runs,.*/\1/p')"
worlds="$(printf '%s\n' "$last" | sed -nE 's/^update gate scale: ([0-9]+) worlds .*/\1/p')"
[ -n "$jobs" ] && [ "$jobs" -gt 0 ] 2>/dev/null || bad "the throughput line names no jobs: a world that scheduled nothing proves nothing (the empty-sample rule)"
[ -n "$runs" ] && [ "$runs" -gt 0 ] 2>/dev/null || bad "the throughput line names no update runs"
if [ "$kind" = gate ]; then
  # The last throughput line is the most recent run's; the gate job's world count is at least the
  # gate-mode default of 4 (the CI drill runs 50): a 1-world last run is a PR-scale fragment and
  # cannot pass as the gate job's report.
  [ -n "$worlds" ] && [ "$worlds" -ge 4 ] 2>/dev/null \
    || bad "the last throughput line names ${worlds:-no} worlds; the gate job runs at least 4 (the CI drill 50): a PR-scale fragment is not the gate job's report"
  grep -qxF 'update gate scale: named worlds sampled green (stolen-release-key, recovery-epoch, root-swap, revocation)' "$report" \
    || bad "no drill line naming the four worlds sampled green inside the gate run"
  grep -qE '^update gate scale: twins NI-U1\.\.NI-U4 equal at [0-9]+ days$' "$report" \
    || bad "no drill line re-running the NI-U1..NI-U4 twins at the gate's day count"
fi

[ "$fail" = 0 ] || exit 1
echo "[update-report-check] OK ($kind)"
