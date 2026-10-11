#!/usr/bin/env bash
# The channel gates' report check (Phase 10 design §13.1's `ch-report-check.sh` row), built on the
# `dm-report-check.sh` pattern: **a report is evidence only if something refuses an incomplete one.**
#
#   ch-report-check.sh <report> gate    the channel-exit-gate / channel-privacy-gate run: every
#                                       line the suites of `:messaging`'s channel package write to
#                                       `build/reports/channel/report.txt` — the SCN-M20 scenario
#                                       per pinned seed, its owner-restore and FORK variants, the
#                                       T38/T39 oracle lines, the size bounds, the privacy world
#                                       with JC-1 … JC-7 as expected, the NI-CH1 … NI-CH5 twins
#                                       equal up to their declared differences, the HIGH-mode
#                                       send-delay line with its distinct-delayed-op count, and
#                                       the mutant count of §12.9's registry
#                                       (run, detected, none not detected);
#   ch-report-check.sh <report> pr      the `android` job's run: one seed of the scenario, the
#                                       privacy lines at PR scale, no gate-scale requirements.
#
# What is required, and what is refused. Every line must be a PASS line over a non-zero sample (a
# search over nothing, a twin over no clients, a world that stored no posts is a failure, the DM
# suites' rule); every zero the design asserts (T38's later epochs and generations, T39's pre-join
# opens, JC-1 … JC-7's matches) must appear literally; any `FAIL` line anywhere fails the check.
# The scenario lines must carry the pinned seeds (S10's `0x5eed_c101..c103`); the privacy world
# line must name 60 clients, 12 channels and 28 days (§12.7's PR scale); the mutant count must
# equal the registered count pinned at S11's exit in §12.9. A report that claims more than its run
# measured — a line of the wrong scale, a zero where a floor is named, a missing killer — fails.
#
# What this deliberately does not check (§15 item 10a's honesty): the scenario runs STANDARD
# only (HIGH mode's send delays are the privacy world's own line, which names its distinct
# delayed-op count); the crash singles' event counts (F-S10-6 keeps both M20 crash singles
# `@Ignore`d — the
# lines are required only once the singles are green); the T2 world's channel funders (§7.9 is
# Rust in `ghost/issuer`, reported with the sweep's state, §19.23); and the 28-day-age half of
# the rotation rule (F-S11-2, §19.51). Raising any of these is exactly what should fail this
# script until the tests behind them exist.
set -euo pipefail

report="${1:-}"
kind="${2:-}"
kinds="gate|pr"
[ -n "$report" ] && [ -n "$kind" ] || { echo "usage: ch-report-check.sh <report> $kinds" >&2; exit 2; }
case "$kind" in gate|pr) ;; *) echo "unknown report kind: $kind" >&2; exit 2 ;; esac

# The §12.9 registry count pinned at S11's exit (§19.51): MM-1 … MM-57 minus MM-27/40/47
# (withdrawn) and MM-54 (equivalent, not counted) = 53; MM-PW1 … MM-PW5; PC-1 … PC-19;
# RV-C1 … RV-C4; ME-C1 … ME-C14: 95 registered, every one run and detected or equivalent.
MUTANTS=95

fail=0
bad() { echo "CH-REPORT-FAIL: $*" >&2; fail=1; }
[ -f "$report" ] || { echo "CH-REPORT-FAIL: no report at $report" >&2; exit 1; }

# No FAIL line anywhere: a suite that failed does not leave a report behind it.
if grep -qE 'channel .*: FAIL' "$report"; then
  bad "a channel line reports FAIL"
fi

# The scenario: one line per pinned seed, every count non-zero (§12.5's scale row).
seeds_re='0x5eed_c10[123]'
m20="$(grep -E "^channel SCN-M20: PASS seed $seeds_re base:" "$report" || true)"
[ -n "$m20" ] || bad "no SCN-M20 base line"
m20_count="$(grep -cE "^channel SCN-M20: PASS seed $seeds_re base:" "$report" || true)"
[ "$m20_count" -ge 1 ] || bad "no SCN-M20 base line"
while IFS= read -r line; do
  case "$line" in
    *"20 clients"*) ;;
    *) bad "the SCN-M20 line does not name 20 clients: $line" ;;
  esac
  for field in 'posts' 'epochs' 'generations' 'seizure subjects' 'joiners'; do
    grep -qE "[1-9][0-9]* $field" <<<"$line" || bad "the SCN-M20 line names no $field: $line"
  done
  grep -qE 't41 checks [1-9]' <<<"$line" || bad "the SCN-M20 line names no t41 checks: $line"
  grep -qE '[1-9][0-9]* seizure subjects, [1-9][0-9]* joiners' <<<"$line" || bad "the SCN-M20 line's subjects or joiners are zero: $line"
done <<<"$m20"

# The variants and the oracle and size lines (one each at least, zeros where the design asserts them).
grep -qE "^channel SCN-M20: PASS seed $seeds_re owner_restore: " "$report" || bad "no owner-restore variant line"
fork="$(grep -E '^channel SCN-M20 fork: PASS' "$report" | head -1 || true)"
[ -n "$fork" ] || bad "no FORK variant line"
grep -qE '[1-9][0-9]* members split_suspected, [1-9][0-9]* rejoined' <<<"$fork" || bad "the FORK line's counts are zero: $fork"

t38="$(grep -E '^channel T38 .*: PASS' "$report" || true)"
[ -n "$t38" ] || bad "no T38 oracle line"
t38_count="$(grep -cE '^channel T38 .*: PASS' "$report" || true)"
[ "$t38_count" -ge 4 ] || bad "fewer than 4 T38 subjects ($t38_count)"
while IFS= read -r line; do
  grep -q 'later epochs 0, later generations 0' <<<"$line" || bad "a T38 line does not assert the zeros: $line"
done <<<"$t38"
grep -qE '^channel T39 joiner: PASS [1-9][0-9]* joiners with history: [1-9][0-9]* blobs, 0 opened before the join' "$report" \
  || bad "no T39 line with its pre-join zero"
grep -qE '^channel sizes: PASS [1-9][0-9]* commits within the floor, [1-9][0-9]* Welcomes under the cap' "$report" \
  || bad "no size-bounds line"

# The privacy world (§12.7): the exact searches, the world line at PR scale, the twins, HIGH mode.
for jc in 1 2 3 4 5 6 7; do
  grep -qE "^channel JC-$jc: PASS" "$report" || bad "no JC-$jc line or not a PASS"
done
world="$(grep -E '^channel privacy world: PASS' "$report" | head -1 || true)"
[ -n "$world" ] || bad "no privacy world line"
grep -qE '60 clients, 12 channels, 28 days' <<<"$world" || bad "the privacy world is not at §12.7's PR scale: $world"
for field in 'posts' 'commits' 'generations' 'removals' 'admissions'; do
  grep -qE "[1-9][0-9]* $field" <<<"$world" || bad "the privacy world line names no $field: $world"
done
for twin in NI-CH1 NI-CH2 NI-CH3 NI-CH4 NI-CH5; do
  grep -qE "^channel $twin: PASS" "$report" || bad "no $twin line or not a PASS"
done
high="$(grep -E '^channel JC-6: PASS .*HIGH mode' "$report" | head -1 || true)"
[ -n "$high" ] || bad "no HIGH-mode JC-6 line"
grep -qE '[1-9][0-9]* distinct delayed ops' <<<"$high" || bad "the HIGH-mode line names no distinct delayed ops: $high"

# The mutant count: the registered count, run and detected, none not detected.
grep -qE "^channel mutants: $MUTANTS run, $MUTANTS detected" "$report" \
  || bad "the mutant line is not 'channel mutants: $MUTANTS run, $MUTANTS detected'"
if grep -qE '^channel mutant .*NOT DETECTED' "$report"; then
  bad "a registered channel mutant was not detected"
fi

# The scale, so a gate run cannot report a PR run's numbers.
if [ "$kind" = gate ]; then
  [ "$m20_count" -ge 3 ] || bad "the gate report does not hold all three pinned seeds ($m20_count)"
else
  [ "$m20_count" -ge 1 ] || bad "no SCN-M20 seed in the PR report"
fi

[ "$fail" = 0 ] || exit 1
echo "[ch-report-check] OK ($kind)"
