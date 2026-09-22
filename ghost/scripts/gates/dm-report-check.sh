#!/usr/bin/env bash
# The DM exit-gate report check (Phase 9 design §15.3, §15.4, §15.6, §15.7; slice S10), built on the
# `t2-report-check.sh` pattern: **a report is evidence only if something refuses an incomplete one.**
#
#   dm-report-check.sh <report> gate    the `messaging-exit-gate.yml` run: every implemented crash
#                                       scenario and suite case with a non-empty enumeration, the
#                                       seeded-world lines, the `SQLITE_FULL` line, the mutant count
#                                       and one line per mutant, and the gate scale in the header;
#   dm-report-check.sh <report> pr      the same lines at the PR scale.
#
# A missing report, a missing line, a zero count or a scale that does not match the requested kind
# fails the check (exit 1); usage errors exit 2.
#
# **What this deliberately does not check.** §15.7's own gate line is `dm mutants: 97 run, 97
# detected` and §15.3's enumeration is every event of twelve scenarios. Slice S10 implements seven
# scenarios, four suite cases and seven mutants, so the numbers pinned here are the numbers a run
# actually measures. Raising them is the next slice's job and is exactly what should fail this
# script until the tests behind them exist: a gate that asserted the design's numbers while running
# a subset would pass on evidence nobody produced, which is the one failure mode a report-checked
# gate must not have. §22.15 of the design lists what is still owed, scenario by scenario and
# mutant by mutant.
set -euo pipefail

report="${1:-}"
kind="${2:-}"
[ -n "$report" ] && [ -n "$kind" ] || { echo "usage: dm-report-check.sh <report> gate|pr" >&2; exit 2; }
case "$kind" in gate|pr) ;; *) echo "unknown report kind: $kind" >&2; exit 2 ;; esac

fail=0
bad() { echo "DM-REPORT-FAIL: $*" >&2; fail=1; }
[ -f "$report" ] || { echo "DM-REPORT-FAIL: no report at $report" >&2; exit 1; }

# The scenarios and suite cases slice S10 implements. Each must have a crash-class line, and that
# line must report at least one single crash: an enumeration of zero crash points is a scenario that
# ran once without faults, which is not a crash enumeration.
scenarios=(SCN-A SCN-B SCN-D SCN-F SCN-G SCN-J SCN-L RP6 RP9 CB-reject-replay EP-read-expiry)
timeout_total=0
for scenario in "${scenarios[@]}"; do
  line="$(grep -E "^dm crash classes: ${scenario} " "$report" || true)"
  if [ -z "$line" ]; then
    bad "no crash-class line for $scenario"
    continue
  fi
  singles="$(printf '%s\n' "$line" | sed -nE 's/.*, ([0-9]+) singles,.*/\1/p')"
  events="$(printf '%s\n' "$line" | sed -nE 's/^dm crash classes: [^ ]+ ([0-9]+) events,.*/\1/p')"
  timeouts="$(printf '%s\n' "$line" | sed -nE 's/.*, ([0-9]+) timeouts over.*/\1/p')"
  relay="$(printf '%s\n' "$line" | sed -nE 's/.*timeouts over ([0-9]+) relay events$/\1/p')"
  [ -n "$singles" ] && [ "$singles" -gt 0 ] 2>/dev/null || bad "$scenario enumerated 0 crash points"
  [ -n "$events" ] && [ "$events" -gt 0 ] 2>/dev/null || bad "$scenario recorded 0 events"
  # The relay-event denominator: "N timeouts" is unreadable without it, and a scenario whose relay
  # phases stopped raising events would report 0 timeouts and look sampled rather than broken.
  if [ -z "$relay" ] || [ "$relay" -le 0 ] 2>/dev/null; then
    bad "$scenario reported no relay events, so its timeout runs have no denominator"
  fi
  [ -n "$timeouts" ] || bad "$scenario has no timeout count"
  timeout_total=$(( timeout_total + ${timeouts:-0} ))
  if [ "$kind" = gate ]; then
    # The gate scale is "crash at **every** event", so the singles of every line have to equal its
    # events. Without this the header alone decided the scale, and `-Dghost.dm.crash=full
    # -Dghost.dm.sample=13` printed "gate (every event)" over a 1-in-13 enumeration.
    if [ "$singles" != "$events" ]; then
      bad "$scenario sampled: $singles singles over $events events, and the gate crashes at every one"
    fi
    # And "every relay event also runs as timeout after apply", which at that scale means all of
    # them. The workflow header sells this run as part of what the gate proves and nothing checked
    # it: eleven lines reading "0 timeouts" passed.
    if [ "$timeouts" != "$relay" ]; then
      bad "$scenario ran $timeouts timeout-after-apply runs over $relay relay events"
    fi
  fi
done

# At the PR scale the relay-event index is sampled too, so a single scenario may legitimately run no
# timeout at all — but the suite as a whole may not, or the fault is not being injected anywhere.
if [ "$kind" = pr ] && [ "$timeout_total" -le 0 ] 2>/dev/null; then
  bad "no timeout-after-apply run anywhere in the report"
fi

# §15.3's doubles: "Double crashes (the second during recovery) for SCN-A, SCN-B, SCN-F and SCN-I."
# SCN-I is not implemented. SCN-J is here as well as the three §15.3 names, because §15.3's sentence
# about it is "single and **double** SQL crashes never reach the threshold".
for scenario in SCN-A SCN-B SCN-F SCN-J; do
  doubles="$(grep -E "^dm crash classes: ${scenario} " "$report" | sed -nE 's/.*, ([0-9]+) doubles,.*/\1/p' || true)"
  [ -n "$doubles" ] && [ "$doubles" -gt 0 ] 2>/dev/null || bad "$scenario ran no double crashes"
done

# SCN-J's `SQLITE_FULL` half, which is a different fault from a crash and has its own line.
full="$(grep -E '^dm storage-full: SCN-J [0-9]+ statements injected$' "$report" | sed -nE 's/.* ([0-9]+) statements.*/\1/p' || true)"
[ -n "$full" ] && [ "$full" -gt 0 ] 2>/dev/null || bad "SCN-J injected no SQLITE_FULL"

# §15.4's seeded worlds, both loops. The faulted loop must say how many seeds drew a fault, and a
# loop in which none did tested nothing — the same rule as "refuses a PASS on an empty sample".
seeds="$(grep -E '^dm seeded worlds: [0-9]+ seeds, 0 failures$' "$report" | sed -nE 's/^dm seeded worlds: ([0-9]+) .*/\1/p' || true)"
[ -n "$seeds" ] && [ "$seeds" -gt 0 ] 2>/dev/null || bad "no seeded-world line, or 0 seeds"
drew="$(grep -E '^dm seeded worlds \(faulted\): [0-9]+ seeds, [0-9]+ drew a fault, 0 failures$' "$report" | sed -nE 's/.*, ([0-9]+) drew a fault.*/\1/p' || true)"
[ -n "$drew" ] && [ "$drew" -gt 0 ] 2>/dev/null || bad "no faulted seeded-world line, or no seed drew a fault"

# §15.5's suite cases.
grep -qE '^dm suite cases: [1-9][0-9]* run, 0 failures$' "$report" || bad "no suite-case line, or 0 cases"

# §15.7's mutants: the count, and one line per mutant naming the case that kills it. A registered
# mutant with no named killer is not registered, it is a claim (§15.7, `Mutants.kt`, `t2_mutants.rs`).
#
# The count and the lines are written from the kills the run **recorded** (`DmKills`), not from the
# registry, so a mutant whose kill test is ignored or deleted lowers the numerator and prints
# "NOT DETECTED" — which is what the two rules below then refuse. Before that, `@Ignore` on a kill
# left this whole block byte-identical and green.
grep -qxF 'dm mutants: 7 run, 7 detected' "$report" || bad "the mutant line is not 'dm mutants: 7 run, 7 detected'"
for mutant in MC-1 MC-5 "MC-7'" MC-10 MC-12 MC-16 ME-16; do
  grep -qE "^dm mutant ${mutant}: detected by .+" "$report" || bad "no detection line for mutant $mutant"
done
if grep -qE '^dm mutant .*NOT DETECTED' "$report"; then
  bad "a registered mutant was not detected by any run"
fi

# The scale, so a gate run cannot report a PR run's numbers.
if [ "$kind" = gate ]; then
  grep -qE '^scale: gate \(every event\), seeds [0-9]+$' "$report" || bad "the report is not of the gate scale"
else
  grep -qE '^scale: pr \(every [0-9]+th event\), seeds [0-9]+$' "$report" || bad "the report is not of the pr scale"
fi

[ "$fail" = 0 ] || exit 1
echo "[dm-report-check] OK ($kind)"
