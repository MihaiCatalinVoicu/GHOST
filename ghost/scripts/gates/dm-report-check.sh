#!/usr/bin/env bash
# The DM exit-gate report check (Phase 9 design §15.3, §15.4, §15.6, §15.7; slices S10, S10b and
# S11), built on the `t2-report-check.sh` pattern: **a report is evidence only if something refuses
# an incomplete one.**
#
#   dm-report-check.sh <report> gate    the `messaging-exit-gate.yml` run: every implemented crash
#                                       scenario and suite case with a non-empty enumeration, the
#                                       seeded-world lines, the `SQLITE_FULL` line, the mutant count
#                                       and one line per mutant, and the gate scale in the header;
#   dm-report-check.sh <report> pr      the same lines at the PR scale.
#
# The privacy report of slice S11 (§15.6; `build/reports/dm/privacy.txt`, written by the tests of
# `org.ghost.messaging.dmworld`) has three kinds, because `dm-privacy-gate.yml` splits its run:
#
#   privacy-gate    one matrix job's worlds at the gate scale (N = 600, 42 days): per seed pair the
#                   world line of that scale, JD1–JD7 and JD9 (not JD8, not JD10) at `PASS 0` over a
#                   non-zero denominator, S-DM3 at PASS with n >= 100, 0 namespaces named by the
#                   dictionary and an exact control that the statistic rejects, and the T35 line of a
#                   provenance build with 0 seal calls thrown;
#   privacy-suite   the scale-independent job: NI-DM1 with its four twins, NI-DM2 with its fifteen
#                   (slice S11b), NI-DM3, JD7's WITHHOLD_ALL_BUNDLES variant with the bound reached
#                   (S11b), the T34 seizure line with both controls complete, the T34 one-reply
#                   line, and the privacy mutant count with one detection line per mutant;
#   privacy-pr      both halves in one report at the PR scale (N = 120, 14 days), which is what the
#                   `android` job of ci.yml writes.
#
# A missing report, a missing line, a zero count or a scale that does not match the requested kind
# fails the check (exit 1); usage errors exit 2.
#
# **What this deliberately does not check.** §15.7's own gate line is `dm mutants: 97 run, 97
# detected` and §15.3's enumeration is every event of twelve scenarios. Slices S10, S10b and S10c
# implement ten of the twelve and a part of an eleventh — SCN-H, whose line covers sixteen weeks of
# generations and a late first flight and not its other clauses (§22.19 names them) — plus SCN-G's
# week-boundary half as a line of its own, four suite cases and eleven mutants, so the numbers
# pinned here are the numbers a run actually measures. SCN-C (S10c) makes no mutant reachable and
# adds none (§22.23). SCN-E (§22.25) is the twelfth, on the entitlement world, and its crash
# coverage is **sampled, not every event**: its lines are `dm crash sample:` lines, held to their own
# rules below and never to the every-event rule of the `dm crash classes:` lines; it adds MC-14 and
# MC-15, and MC-22 stays out of reach (it needs an engine seam, §22.25). The suite cases of §22.27
# add three functional-suite sub-cases under the enumeration, KC12, RS2 and RP7, and the two mutants
# the first two make reachable, MC-21 and MC-24: fifteen (RP7's MC-9 needs a seam, §22.27).
# Raising them is the next slice's job and is exactly what should fail this script until the tests
# behind them exist: a gate that asserted the design's numbers while running a subset would pass on
# evidence nobody produced, which is the one failure mode a report-checked gate must not have.
# §22.15 and §22.19 of the design list what is still owed, scenario by scenario and mutant by
# mutant. The privacy half follows the same rule: it does not
# require JD8, JD10, NI-DM4 … NI-DM7, S-DM1, S-DM2, S-DM4 and their recorded baselines, the
# AD-7-with-token line, the EM-1/EM-2 lines, the `pq-model` status line, JD5's membership-expiry
# clause, T26's model-relay open check or 28 of the 40 privacy mutants (nor PM-5's exact-seconds
# half), because nothing in this branch produces them; §22.16 names each (items 10–15 and 20), and
# §22.21 what slice S11b added (NI-DM2 with its one declared open defect, the JD7
# WITHHOLD_ALL_BUNDLES variant, PM-5's day-rounding half and PM-31, and NI-DM2 as PM-4's second
# killer).
set -euo pipefail

report="${1:-}"
kind="${2:-}"
kinds="gate|pr|privacy-pr|privacy-gate|privacy-suite"
[ -n "$report" ] && [ -n "$kind" ] || { echo "usage: dm-report-check.sh <report> $kinds" >&2; exit 2; }
case "$kind" in gate|pr|privacy-pr|privacy-gate|privacy-suite) ;; *) echo "unknown report kind: $kind" >&2; exit 2 ;; esac

fail=0
bad() { echo "DM-REPORT-FAIL: $*" >&2; fail=1; }
[ -f "$report" ] || { echo "DM-REPORT-FAIL: no report at $report" >&2; exit 1; }

# ---------------------------------------------------------------------------------------------------
# The privacy report (slice S11).
# ---------------------------------------------------------------------------------------------------

# The per-world half: one line of each kind per seed pair the header names.
privacy_worlds() {
  local scale="$1" clients="$2" days="$3" pairs worlds join n
  grep -qE "^scale: ${scale}, seed pairs [1-9][0-9]*, STANDARD\$" "$report" \
    || bad "the report is not of the expected scale (${scale})"
  pairs="$(sed -nE "s/^scale: ${scale}, seed pairs ([0-9]+), STANDARD\$/\\1/p" "$report" | head -1)"
  pairs="${pairs:-0}"
  # One world line per seed pair, a world that did something, and a world **of the header's scale**:
  # the header alone would let a PR-scale world be reported under a gate header.
  worlds="$(grep -cE "^dm privacy world: N=${clients}, ${days} days, [1-9][0-9]* edges accepted of [0-9]+ planned, [1-9][0-9]* user sends, [1-9][0-9]* stores, " "$report" || true)"
  [ "$pairs" -gt 0 ] 2>/dev/null || bad "the header names no seed pair"
  [ "$worlds" = "$pairs" ] || bad "$worlds non-empty world lines of N=${clients} over ${days} days for $pairs seed pairs"
  if grep -E '^dm privacy world: ' "$report" | grep -qvE "^dm privacy world: N=${clients}, ${days} days, "; then
    bad "a world line of another scale than the header's (N=${clients}, ${days} days)"
  fi
  # The joins: a PASS with zero matches over a non-zero denominator, once per seed pair, and no FAIL.
  for join in JD1 JD2 JD3 JD4 JD5 JD6 JD7 JD9; do
    n="$(grep -cE "^dm ${join}: PASS 0 over [1-9][0-9]*; " "$report" || true)"
    [ "$n" = "$pairs" ] || bad "$join: $n PASS lines over a non-empty sample for $pairs seed pairs"
    if grep -qE "^dm ${join}: FAIL" "$report"; then bad "$join failed"; fi
  done
  # JD5 says which TIMER_SET path it covered: the pending path (a TIMER_SET queued for EST-READY's
  # flush) is NI-DM2's declared open defect, and a line without the split would read as covering it.
  n="$(grep -cE "^dm JD5: PASS 0 over [1-9][0-9]*; .*, [0-9]+ TIMER_SETs against R-T3's larger bucket \([0-9]+ set over a session, [0-9]+ queued for EST-READY's flush: " "$report" || true)"
  [ "$n" = "$pairs" ] || bad "JD5: $n lines that say which TIMER_SET path they covered for $pairs seed pairs"
  # S-DM3 (gating): PASS, the n >= 100 floor, no namespace of the view named by the dictionary (the
  # only part of the statistic the world decides, §22.16), and the colluders' control exact,
  # non-empty and rejected by the statistic (the interval test can fail when the attacker knows).
  n="$(grep -cE '^dm S-DM3: PASS K=[0-9]+ of n=[1-9][0-9]{2,} namespaces \(N=[0-9]+ identities, 0 named by the dictionary over [1-9][0-9]* view namespaces\), .*control: [0-9]+ colluders. cards map [1-9][0-9]* of [0-9]+ expected namespaces, [0-9]+ correct, K=[0-9]+ outside the interval' "$report" || true)"
  [ "$n" = "$pairs" ] || bad "S-DM3: $n PASS lines with n >= 100, nothing named by the dictionary and a non-empty exact control outside the interval for $pairs seed pairs"
  if grep -qE '^dm S-DM3: FAIL' "$report"; then bad "S-DM3 failed, fell below its floor, named a namespace or its control was not exact"; fi
  # T35: only a provenance build earns the line; a plain build's NOT RUN is a failure here. The line
  # counts seal calls and the seals they returned, and no call may have thrown.
  n="$(grep -cE '^dm T35: PASS provenance build; [1-9][0-9]* seals under the assertion of [1-9][0-9]* seal calls \(.*\), 0 threw; PQ-R8 exception ' "$report" || true)"
  [ "$n" = "$pairs" ] || bad "T35: $n PASS lines of a provenance build with 0 seal calls thrown for $pairs seed pairs"
  if grep -qE '^dm T35: (FAIL|NOT RUN)' "$report"; then bad "T35 did not run on a provenance build, or failed"; fi
}

# The scale-independent half: the twins, the seizure world and the mutants.
privacy_suite() {
  local mutant t34 pair got of intro want
  grep -qE "^dm NI-DM1: PASS 4 twins \(VALID, MALFORMED, PROBE, REQUEST\) equal over [1-9][0-9]* events of B's view across a week boundary, each with B's GET of the substituted blob" "$report" \
    || bad "no NI-DM1 PASS over the four twins across a week boundary, each with the substituted GET"
  if grep -qE '^dm NI-DM1: FAIL' "$report"; then bad "NI-DM1 failed"; fi
  grep -qE "^dm NI-DM3: PASS k=2 vs k'=4 contacts \(2 idle cards added\): C's view equal over [1-9][0-9]* events from the scan session on, across a week boundary" "$report" \
    || bad "no NI-DM3 PASS with its two idle contacts added, from the scan session on"
  if grep -qE '^dm NI-DM3: FAIL' "$report"; then bad "NI-DM3 failed"; fi
  # NI-DM2 (the S11b slice, §22.21): the fifteen twins at the eight body lengths, 59 of their 60
  # messages gating with a non-zero number of comparisons (the stores, and the store second where no
  # establishment decides it), and M sealed in **every** mode and of **every** kind the twins name —
  # so a run whose twins never left one state (and so compared a message with itself) cannot pass.
  # The line must **end** with the one declared open defect, pinned word for word: exactly one, the
  # TTL of the intro TIMER_SET and nothing else (NiDm2 fails a declared defect that differs in any
  # other field, or no longer differs), so no second "declared" difference can ride on a PASS and a
  # partial fix cannot pass as the declared defect.
  grep -qE "^dm NI-DM2: PASS 15 twins at 8 body lengths \(0, 17, 2220, 2221, 3000, 14508, 14509, 15000\); 59 of their 60 messages gate: A's stores of M into B's inbox equal at each length over [1-9][0-9]* comparisons, and at the same second after t0 over [1-9][0-9]* comparisons among the [1-9][0-9]* messages whose state needs no establishment \(an intro's or a reset's store waits for the bundle, whose timing is the relay's, §21\.7 point 6\); M sealed \{INTRO=[1-9][0-9]*, PAIR=[1-9][0-9]*, PROVISIONAL=[1-9][0-9]*\}, kinds \{CONTROL=[1-9][0-9]*, QUOTED=[1-9][0-9]*, REACTION=[1-9][0-9]*, TEXT=[1-9][0-9]*, TIMER_SET=[1-9][0-9]*\}, TLVs that rode \{[^}]*\}; sizes by length \{[^}]*\}; 1 declared open defect, not gated, reproduced exactly as declared: INTRO/TIMER_SET at 0 stores ttl=86400 where the other twins store ttl=604800, every other field equal, at 3 relays — R-T3 on the pending path: SendStep's EST-READY flush takes the TTL of the new timer, not the larger of the old and the new \(§22.21\)\$" "$report" \
    || bad "no NI-DM2 PASS over the fifteen twins at the eight lengths, 59 of 60 messages gating, with M sealed in every mode and of every kind, ending with exactly the one declared open defect (the intro TIMER_SET's TTL)"
  if grep -qE '^dm NI-DM2: FAIL' "$report"; then bad "NI-DM2 failed"; fi
  # JD7's WITHHOLD_ALL_BUNDLES variant (§21.7 point 6): no read outside an attempt window, and a world
  # that put the bound to the test — an establishment that reached its third window with a later
  # session of the reader where a fourth attempt would fall — plus the two harness guards (bundles
  # withheld from lists, none fetched), so the variant is never a pass over a world in which the
  # bound never bound.
  grep -qE '^dm JD7 WITHHOLD_ALL_BUNDLES: PASS 0 over [1-9][0-9]*; .*; [1-9][0-9]* establishments reached their third attempt window, [1-9][0-9]* of them followed by a relay session of the reader at least 6 h after it closed and before the pair.s next establishment \(where an unbounded engine makes a fourth attempt\); harness guards: [1-9][0-9]* bundle lists answered empty over a live bundle, 0 bundle GETs' "$report" \
    || bad "no JD7 WITHHOLD_ALL_BUNDLES PASS in which an establishment reached its third window with room for a fourth attempt, with bundles withheld and none fetched"
  if grep -qE '^dm JD7 WITHHOLD_ALL_BUNDLES: FAIL' "$report"; then bad "the JD7 WITHHOLD_ALL_BUNDLES variant failed"; fi
  # T34: a non-empty expired-week sample with nothing recognised or opened, and **every** control
  # complete — each "N of M" with N = M and M > 0 — so a "0" is never the output of an attempt that
  # does not work (a control of "1 of 515" is refused, not accepted).
  t34="$(grep -E '^dm T34: PASS seized c[0-9]+, c[0-9]+ at day 70; expired-week pair blobs [1-9][0-9]*, 0 recognised and 0 opened by retained keys \(.*\), 0 recognised by derived keys \(.*\); control ' "$report" | head -1 || true)"
  if [ -z "$t34" ]; then
    bad "no T34 PASS over a non-empty expired-week sample with nothing recognised or opened"
  else
    for pair in \
      "$(printf '%s\n' "$t34" | sed -nE 's/.*; control ([0-9]+) of ([0-9]+) current in-direction.*/\1 \2/p')" \
      "$(printf '%s\n' "$t34" | sed -nE 's/.*, ([0-9]+) of ([0-9]+) current-week out-direction recognised.*/\1 \2/p')" \
      "$(printf '%s\n' "$t34" | sed -nE 's/.*, day-[0-9]+ control ([0-9]+) of ([0-9]+) opened.*/\1 \2/p')"; do
      read -r got of <<<"${pair:-x y}"
      if [ "$got" != "$of" ] || ! [ "${of:-0}" -gt 0 ] 2>/dev/null; then bad "a T34 control is incomplete or empty ($got of $of)"; fi
    done
    printf '%s\n' "$t34" | grep -qE '; prov_env [0-9]+ retained, [1-9][0-9]* due erased, 0 past the rule; provisional blobs [0-9]+, 0 of [1-9][0-9]* of due sessions opened' \
      || bad "T34's provisional half is missing, empty or opened a blob of a due session"
    intro="$(printf '%s\n' "$t34" | sed -nE 's/.*; intro ([0-9]+) of [0-9]+ opened, ([0-9]+) expected.*/\1 \2/p')"
    read -r got want <<<"${intro:-x y}"
    [ "$got" = "$want" ] || bad "T34's intro half opened $got where $want were expected"
  fi
  if grep -qE '^dm T34: FAIL' "$report"; then bad "T34 failed"; fi
  grep -qE '^dm T34 one-reply: PASS dumped at day 125: 2 of 2 sessions due by prov_anchor_minute \+ 119 d, 2 of 2 provably held prov_env, 0 keep it' "$report" \
    || bad "no T34 one-reply PASS with both sessions due and erased"
  if grep -qE '^dm T34 one-reply: FAIL' "$report"; then bad "the T34 one-reply variant failed"; fi
  # The privacy mutants: the count this slice registers, one detection line each, none undetected.
  # Both numbers are written from what the run recorded (`PrivacyKills`): a mutant is "run" when a
  # mutated world ran for every check its entry names, and "detected" when every one killed it.
  grep -qxF 'dm privacy mutants: 12 run, 12 detected' "$report" || bad "the privacy mutant line is not 'dm privacy mutants: 12 run, 12 detected'"
  for mutant in PM-2 PM-3 PM-4 PM-5 PM-6 PM-8 PM-13 PM-19 PM-24 PM-31 PM-36 PM-39; do
    grep -qE "^dm privacy mutant ${mutant}: detected by .+" "$report" || bad "no detection line for privacy mutant $mutant"
  done
  # PM-4 is detected by both checks §15.7 names since S11b (§22.21), and the report must say so.
  grep -qxF 'dm privacy mutant PM-4: detected by JD4 (SMALL world), NI-DM2 (twin worlds)' "$report" \
    || bad "PM-4 is not detected by both JD4 and NI-DM2"
  # PM-5 is half of §15.7's entry (the day rounding; the exact-seconds half is not built), and its
  # line must say so, so "12 detected" never reads as more than was built.
  grep -qxF 'dm privacy mutant PM-5: detected by JD5 (SMALL world); the day-rounding half only; the exact-seconds half is not built' "$report" \
    || bad "PM-5's detection line does not say that only its day-rounding half is built"
  if grep -qE '^dm privacy mutant .*NOT DETECTED' "$report"; then bad "a registered privacy mutant was not detected by every check it names"; fi
}

case "$kind" in
  privacy-gate) privacy_worlds 'gate \(N = 600, 42 days\)' 600 42 ;;
  privacy-pr) privacy_worlds 'pr \(N = 120, 14 days\)' 120 14; privacy_suite ;;
  privacy-suite)
    grep -qE '^scale: (pr|gate) \(N = [0-9]+, [0-9]+ days\), seed pairs [0-9]+, STANDARD$' "$report" || bad "no privacy report header"
    privacy_suite
    ;;
esac
case "$kind" in
  privacy-*)
    [ "$fail" = 0 ] || exit 1
    echo "[dm-report-check] OK ($kind)"
    exit 0
    ;;
esac


# The scenarios and suite cases slices S10, S10b and S10c implement (S10b added SCN-H, SCN-I, SCN-K
# and SCN-G's week-boundary retry as `SCN-G-week`, §22.19; S10c added SCN-C, §22.23). Each must have
# a crash-class line, and that line must report at least one single crash: an enumeration of zero
# crash points is a scenario that ran once without faults, which is not a crash enumeration.
scenarios=(SCN-A SCN-B SCN-C SCN-D SCN-F SCN-G SCN-G-week SCN-H SCN-I SCN-J SCN-K SCN-L)
# §15.5's sub-cases under the enumeration: S10's four, and KC12, RS2 and RP7 since §22.27.
scenarios+=(RP6 RP9 CB-reject-replay EP-read-expiry KC12 RS2 RP7)
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
  # The denominator is **stores** — the relay's after-apply events, the one place a "timeout after
  # apply" exists. It was relay events, three per store, and the gate rule below then pinned a
  # count in which two runs of every three injected nothing (S10b review).
  stores="$(printf '%s\n' "$line" | sed -nE 's/.*timeouts over ([0-9]+) stores$/\1/p')"
  [ -n "$singles" ] && [ "$singles" -gt 0 ] 2>/dev/null || bad "$scenario enumerated 0 crash points"
  [ -n "$events" ] && [ "$events" -gt 0 ] 2>/dev/null || bad "$scenario recorded 0 events"
  # "N timeouts" is unreadable without its denominator, and a scenario whose relay stopped raising
  # store events would report 0 timeouts and look sampled rather than broken.
  if [ -z "$stores" ] || [ "$stores" -le 0 ] 2>/dev/null; then
    bad "$scenario reported no stores, so its timeout runs have no denominator"
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
    # And "every relay event also runs as timeout after apply", which at that scale means every
    # store. The workflow header sells this run as part of what the gate proves and nothing checked
    # it: eleven lines reading "0 timeouts" passed.
    if [ "$timeouts" != "$stores" ]; then
      bad "$scenario ran $timeouts timeout-after-apply runs over $stores stores"
    fi
  else
    # At the PR scale the stores are sampled by their ordinal, and the first store of every
    # scenario is on the grid: a line with no timeout is a sampling that stopped reaching it.
    [ -n "$timeouts" ] && [ "$timeouts" -gt 0 ] 2>/dev/null || bad "$scenario ran no timeout-after-apply run"
  fi
done

# And the suite as a whole, which the per-line rule implies and which stays as its own message.
if [ "$kind" = pr ] && [ "$timeout_total" -le 0 ] 2>/dev/null; then
  bad "no timeout-after-apply run anywhere in the report"
fi

# SCN-E (§22.25): the offline recipient and its LOSE_KEYS variant, on the entitlement world, each run
# with each client armed in turn. Its crash coverage is SAMPLED, not every event — a run of about
# 1.6 million events of alice costs about a minute, and the classified enumeration that would make
# every event affordable needs deterministic native randomness this tree does not have (§22.22 item
# 7) — so its lines are `dm crash sample:` lines and say so in their own words, the header says the
# scale line is not theirs, and the every-event rule above is never applied to them nor may one of
# them pass as a `dm crash classes:` line. What is held here, per line: a non-empty recording; the
# number of phases the script has (six for OFFLINE, three for LOSE_KEYS — the review found a line
# of one phase accepted, §22.25 item 14); exactly the scale's density per phase (one on a PR, eight
# in the gate) and singles = density × phases; and the store faults per phase — each picked store
# run once as a timeout and once as a crash after apply, and in every phase exactly min(density,
# that phase's stores) of them (one on a PR, three in the gate), summing to the line's totals.
grep -qxF 'coverage: the scale is the density of the dm crash classes lines; the dm crash sample lines (SCN-E) are sampled, not every event' "$report" \
  || bad "the header does not say that its scale is not the SCN-E lines', which are sampled"
per_phase=1
stores_per_phase=1
if [ "$kind" = gate ]; then
  per_phase=8
  stores_per_phase=3
fi
for pair in "SCN-E bob|6" "SCN-E alice|6" "SCN-E/LOSE_KEYS bob|3" "SCN-E/LOSE_KEYS alice|3"; do
  subject="${pair%%|*}"
  want_phases="${pair#*|}"
  line="$(grep -E "^dm crash sample: ${subject} " "$report" | head -1 || true)"
  if [ -z "$line" ]; then
    bad "no crash-sample line for $subject"
    continue
  fi
  if ! printf '%s\n' "$line" | grep -qE "^dm crash sample: ${subject} [0-9]+ events, [0-9]+ singles over [0-9]+ phases \\([0-9]+ per phase\\), [0-9]+ timeouts and [0-9]+ crashes after apply at [0-9]+ of [0-9]+ stores \\(per phase [0-9]+/[0-9]+( [0-9]+/[0-9]+)*\\); sampled, not every event\$"; then
    bad "$subject's line is not of the sample form, or does not say that its enumeration is sampled, not every event"
    continue
  fi
  events="$(printf '%s\n' "$line" | sed -nE 's/^dm crash sample: [^ ]+ [a-z]+ ([0-9]+) events,.*/\1/p')"
  singles="$(printf '%s\n' "$line" | sed -nE 's/.* events, ([0-9]+) singles over .*/\1/p')"
  phases="$(printf '%s\n' "$line" | sed -nE 's/.* singles over ([0-9]+) phases .*/\1/p')"
  printed="$(printf '%s\n' "$line" | sed -nE 's/.* phases \(([0-9]+) per phase\).*/\1/p')"
  timeouts="$(printf '%s\n' "$line" | sed -nE 's/.* per phase\), ([0-9]+) timeouts and .*/\1/p')"
  crashes="$(printf '%s\n' "$line" | sed -nE 's/.* timeouts and ([0-9]+) crashes after apply .*/\1/p')"
  faulted="$(printf '%s\n' "$line" | sed -nE 's/.* crashes after apply at ([0-9]+) of [0-9]+ stores .*/\1/p')"
  stores="$(printf '%s\n' "$line" | sed -nE 's/.* crashes after apply at [0-9]+ of ([0-9]+) stores .*/\1/p')"
  split="$(printf '%s\n' "$line" | sed -nE 's/.* stores \(per phase ([0-9/ ]+)\); sampled, not every event$/\1/p')"
  [ "$events" -gt 0 ] 2>/dev/null || bad "$subject recorded 0 events"
  [ "$phases" = "$want_phases" ] || bad "$subject sampled over $phases phases, and its script has $want_phases"
  [ "$printed" = "$per_phase" ] || bad "$subject sampled $printed crash points per phase, and the $kind scale samples $per_phase"
  [ "$singles" = "$(( per_phase * want_phases ))" ] || bad "$subject sampled $singles crash points, not $per_phase in each of $want_phases phases"
  [ "$stores" -gt 0 ] 2>/dev/null || bad "$subject reported no stores, so its store faults have no denominator"
  [ "$faulted" -gt 0 ] 2>/dev/null || bad "$subject faulted no store"
  [ "$timeouts" = "$faulted" ] || bad "$subject ran $timeouts timeouts at $faulted faulted stores"
  [ "$crashes" = "$faulted" ] || bad "$subject ran $crashes crashes after apply at $faulted faulted stores"
  n=0
  sum_faulted=0
  sum_stores=0
  for part in $split; do
    got="${part%%/*}"
    of="${part#*/}"
    want=$(( of < stores_per_phase ? of : stores_per_phase ))
    [ "$got" = "$want" ] || bad "$subject faulted $got of the $of stores of its phase $(( n + 1 )), and the $kind scale faults $want"
    n=$(( n + 1 ))
    sum_faulted=$(( sum_faulted + got ))
    sum_stores=$(( sum_stores + of ))
  done
  [ "$n" = "$want_phases" ] || bad "$subject's store faults are split over $n phases, and its script has $want_phases"
  [ "$sum_faulted" = "$faulted" ] && [ "$sum_stores" = "$stores" ] \
    || bad "$subject's per-phase store faults ($split) do not add up to $faulted of $stores"
done
if grep -qE '^dm crash classes: SCN-E' "$report"; then
  bad "an SCN-E line claims the every-event enumeration it does not run (§22.25)"
fi

# §15.3's doubles: "Double crashes (the second during recovery) for SCN-A, SCN-B, SCN-F and SCN-I."
# All four are implemented since S10b. SCN-J is here as well as the four §15.3 names, because §15.3's
# sentence about it is "single and **double** SQL crashes never reach the threshold".
for scenario in SCN-A SCN-B SCN-F SCN-I SCN-J; do
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

# §15.5's suite cases: seven since §22.27 — S10's four and KC12, RS2 and RP7. Pinned, not "at least
# one" (§22.27's review): a report of the four cases before this slice passed the old rule.
grep -qxF 'dm suite cases: 7 run, 0 failures' "$report" || bad "the suite-case line is not 'dm suite cases: 7 run, 0 failures'"

# §15.7's mutants: the count, and one line per mutant naming the case that kills it. A registered
# mutant with no named killer is not registered, it is a claim (§15.7, `Mutants.kt`, `t2_mutants.rs`).
#
# The count and the lines are written from the kills the run **recorded** (`DmKills`), not from the
# registry, so a mutant whose kill test is ignored or deleted lowers the numerator and prints
# "NOT DETECTED" — which is what the two rules below then refuse. Before that, `@Ignore` on a kill
# left this whole block byte-identical and green.
#
# Eleven since S10b: MC-18 and MC-26, which SCN-I makes reachable, MC-28, which SCN-H does, and
# MC-33, which SCN-G-week does; each is killed fault-free and at crash points spread over its
# scenario, beside the unmutated scenario crashed at the same points (§22.19). Thirteen since SCN-E
# (§22.25): MC-14 and MC-15, which SCN-E/LOSE_KEYS makes reachable, under the same rule with its
# crash points in the window where the mutant acts — from the loss to the fault-free failure — and
# not over the whole run, where the review found them all in the establishment (§22.25 item 14).
# Fifteen since the suite cases of §22.27: MC-21, which RS2 makes reachable, and MC-24, which KC12
# does, each killed fault-free and at six crash points inside the transaction the mutant first
# changes after the scenario's mark — measured from the mutated run, from its first rewritten
# statement to the transaction's last event. The first version spread the points from the mark to
# the end of the run, and its review found MC-21's all after the mutant's only commit and five of
# MC-24's before its first rewritten read (§22.27 item 11).
grep -qxF 'dm mutants: 15 run, 15 detected' "$report" \
  || bad "the mutant line is not 'dm mutants: 15 run, 15 detected'"
# Each line ends with the **rule** its kill was held to, written by the test that applied it from
# the numbers it measured (`DmKills`). Without it the line was the registry's own sentence, and
# moving one of S10b's kills back to the fault-free-only rule left the report — and this check —
# byte-identical (S10b review). So the rule is pinned per mutant: MC-1 killed only under a crash in
# its split window; S10b's four fault-free **and** at every one of six crash points; the rest
# fault-free, each beside a clean control.
rule_ff='fault-free, beside a clean control'
rule_crash='invisible fault-free, killed under a crash in its split window, beside a clean run at the same point'
rule_s10b='fault-free and at 6 of 6 crash points, each beside a clean run'
rule_scne='fault-free and at 6 of 6 crash points between the loss and its fault-free failure, each beside a clean run'
# §22.27's two, inside the transaction each first changes: MC-21's (the recipient's first SWEEP after
# the absence) spans 46 events and takes six points spread over it; MC-24's (the RECV of the second
# identity's first flight) spans two — the rewritten read and the statement the schema refuses — and
# is crashed at both, every event it has.
rule_mc21='fault-free and at 6 of 6 crash points inside the transaction it first changes, each beside a clean run'
rule_mc24='fault-free and at 2 of 2 crash points inside the transaction it first changes, each beside a clean run'
for pair in "MC-1|$rule_crash" "MC-5|$rule_ff" "MC-7'|$rule_ff" "MC-10|$rule_ff" "MC-12|$rule_ff" \
  "MC-14|$rule_scne" "MC-15|$rule_scne" \
  "MC-16|$rule_ff" "MC-18|$rule_s10b" "MC-21|$rule_mc21" "MC-24|$rule_mc24" \
  "MC-26|$rule_s10b" "MC-28|$rule_s10b" "MC-33|$rule_s10b" \
  "ME-16|$rule_ff"; do
  mutant="${pair%%|*}"
  rule="${pair#*|}"
  line="$(grep -E "^dm mutant ${mutant}: " "$report" | head -1 || true)"
  if ! printf '%s\n' "$line" | grep -qE "^dm mutant ${mutant}: detected by .+"; then
    bad "no detection line for mutant $mutant"
  elif [ "${line##*; kill rule: }" != "$rule" ]; then
    bad "mutant $mutant was not killed under its rule ($rule)"
  fi
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
