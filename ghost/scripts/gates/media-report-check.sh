#!/usr/bin/env bash
# The media exit-gate report check (Phase 11 design faza11-media.md §16.1 G-M9; slice S9), built on
# the dm-report-check.sh pattern: **a report is evidence only if something refuses an incomplete
# one.**
#
#   media-report-check.sh <exit-report> gate|pr
#       the `media-exit-gate` run's report (the suites of `org.ghost.messaging.media` and the media
#       crate, file `-Dghost.media.report`, default build/reports/media/exit.txt): per SCN-M
#       scenario a line with its crash-point count and a non-empty enumeration, the seeded-worlds
#       line, the gate-scale privacy world's JM1–JM7 = 0 lines (JM1 with its exemption list
#       counted; the gate line names the 5 seed pairs), the NI-M1–NI-M7 twin lines equal up to
#       their declared differences, the T25-media (EP-M) line and the seizure line (0 opened,
#       the live control opens), and the mutant close-out: the measured JVM+S1 split
#       (`media mutants: 9 run, 9 detected` + `media S1 mutants: N run, N detected`, N bounded
#       by the tree's patches, none surviving) or, for old reports, `media mutants: 43 run,
#       43 detected`;
#   media-report-check.sh --emulator <emulator-report>
#       the `media-emulator` job's report (§15.7 EXIF-zero and §15.8, per API level) with
#       `media emulator mutants: 7 run, 7 detected`.
#
# Every count is checked against what was measured (the dm-report-check.sh rule): a number larger
# than the pin is not a stronger result, it is a different claim — the pins are the design's
# (1 000 seeded worlds and N = 300 × 28 days × 5 seed pairs at the gate) or measured caps passed in
# the environment (GHOST_MEDIA_REPORT_MAX_SEEDED_WORLDS, GHOST_MEDIA_REPORT_MAX_WALL_MINUTES). A
# missing report, line or a FAIL fails the check (exit 1); usage errors exit 2.
set -euo pipefail

usage() { echo "usage: media-report-check.sh <exit-report> gate|pr | media-report-check.sh --emulator <emulator-report>" >&2; exit 2; }
emulator=0
report=""
kind=""
while [ "$#" -gt 0 ]; do
  case "$1" in
    --emulator) emulator=1; shift; [ "$#" -gt 0 ] || usage; report="$1"; shift ;;
    *) [ -z "$report" ] || usage; report="$1"; shift; [ "$#" -gt 0 ] || usage; kind="$1"; shift ;;
  esac
done
[ -n "$report" ] || usage
fail=0
bad() { echo "MEDIA-REPORT-FAIL: $*" >&2; fail=1; }
[ -f "$report" ] || { echo "MEDIA-REPORT-FAIL: no report at $report" >&2; exit 1; }

if [ "$emulator" = 1 ]; then
  # §15.7/§15.8's job report: one EXIF-zero line per API level, the no-plaintext-cache line, the
  # decoder-isolation line, and the emulator mutants' close-out.
  if ! grep -qE '^GHOST media emulator' "$report"; then bad "not a media emulator report"; fi
  for level in 29 35 37; do
    grep -qE "^api $level: EXIF-zero" "$report" || bad "no EXIF-zero line for api $level (§15.7)"
  done
  grep -qE '^no-plaintext-cache: PASS' "$report" || bad "no no-plaintext-cache PASS line (§15.8)"
  grep -qE '^decoder isolation: PASS' "$report" || bad "no decoder-isolation PASS line (§15.8 item 6)"
  # The mutant close-out: exactly the design's 7, none surviving — and every close-out line is
  # read (a report carrying a second, inflated line is not rescued by a first honest one).
  if ! grep -qE '^media emulator mutants: 7 run, 7 detected$' "$report"; then
    bad "no exact 'media emulator mutants: 7 run, 7 detected' line"
  fi
  while read -r run det; do
    [ "$run" -le 7 ] || bad "the report claims $run emulator mutants run, more than the design's 7"
    [ "$det" -le "$run" ] || bad "the report claims $det detected of $run run"
  done < <(sed -nE 's/^media emulator mutants: ([0-9]+) run, ([0-9]+) detected$/\1 \2/p' "$report")
  [ "$fail" = 0 ] || exit 1
  echo "[media-report-check] OK (emulator)"
  exit 0
fi

case "$kind" in
  gate|pr) ;;
  *) usage ;;
esac

# The exit report itself.
if ! grep -qE '^GHOST media exit gate' "$report"; then bad "not a media exit-gate report"; fi
# A check line that reports FAIL fails the run, whatever else the report claims (the counts above
# stay the authority; this catches a check that answered FAIL without the patterns above matching).
grep -qE '^(JM[1-7]|NI-M[1-7]|SCN-M[A-F]|T25 media \(EP-M\)): FAIL' "$report" && bad "a check line reports FAIL"

# Per SCN-M scenario: a line naming the scenario with its crash-point count, a positive count (an
# enumeration over 0 points tested nothing), and no FAIL.
scns="SCN-MA SCN-MB SCN-MC SCN-MD SCN-ME SCN-MF"
for s in $scns; do
  grep -qE "^$s: [0-9]+ crash points" "$report" || bad "no crash-enumeration line for $s"
  if grep -qE "^$s: 0 crash points" "$report"; then bad "$s enumerated 0 crash points"; fi
  grep -qE "^$s: .*invariants hold" "$report" || bad "$s does not say its invariants hold"
done

# Seeded worlds: the design's pin at the gate, the measured cap elsewhere.
max_seeded="${GHOST_MEDIA_REPORT_MAX_SEEDED_WORLDS:-1000}"
if [ "$kind" = gate ]; then
  grep -qE '^seeded worlds: 1000 run, 0 failures$' "$report" || bad "no exact 'seeded worlds: 1000 run, 0 failures' line"
else
  seeded="$(sed -nE 's/^seeded worlds: ([0-9]+) run, 0 failures$/\1/p' "$report" | sed -n '1p')"
  [ -n "$seeded" ] || bad "no seeded-worlds line of the form 'seeded worlds: N run, 0 failures'"
  [ "$seeded" -le "$max_seeded" ] || bad "the PR report claims $seeded seeded worlds, above the $max_seeded pin"
fi

# The privacy world: every JM check at 0 with a non-zero denominator named in the line (the
# in-suite floors are the authority; a line over 0 objects/stores/calls in the report is the
# vacuity the suites refuse, and the gate refuses it here too — finding 5's tightening).
for i in 1 2 3 4 5 6 7; do
  grep -qE "^JM$i: PASS 0 .*over [1-9][0-9]* " "$report" || \
    bad "no 'JM$i: PASS 0 … over <non-zero> …' line (a zero denominator is the JC-5 vacuity)"
done
grep -qE '^JM1: PASS 0 .*(exemptions: [0-9]+ counted|exemptions: none)' "$report" || \
  bad "JM1's line does not count its exemptions (the LM exemptions, design §15.6)"
for i in 1 2 3 4 5 6 7; do
  grep -qE "^NI-M$i: equal" "$report" || bad "no 'NI-M$i: equal …' line"
done
# NI-M3's, NI-M5's and NI-M7's lines must carry the declared-difference clauses of §15.6 (the
# sender-pair session co-occurrence, the first-page list schedule and the TTL scalar respectively).
grep -qE '^NI-M3: equal .*sender pair' "$report" || bad "NI-M3's line does not name the sender-pair declared difference"
grep -qE '^NI-M5: equal .*first-page' "$report" || bad "NI-M5's line does not name the first-page list-schedule clause"
grep -qE '^NI-M7: equal up to the TTL scalar' "$report" || bad "NI-M7's line does not name the TTL-scalar declared difference"
# The gate scale is the design's; the world must have run at it.
if [ "$kind" = gate ]; then
  grep -qF 'N = 300, 28 days' "$report" || bad "the report is not of the gate scale (N = 300, 28 days)"
  grep -qE '5 seed pairs' "$report" || bad "the gate-scale line does not name the 5 seed pairs"
else
  grep -qF 'N = 60, 14 days' "$report" || bad "the PR report is not of the PR scale (N = 60, 14 days)"
fi

# T25-media and the seizure check.
grep -qE '^T25 media \(EP-M\): PASS' "$report" || bad "no T25-media (EP-M) PASS line"
grep -qE '^seizure: 0 opened' "$report" || bad "no seizure line with 0 opened"
grep -qE '^seizure: .*control: [1-9][0-9]* live objects open' "$report" || \
  bad "the seizure line names no live control that opened"

# The JVM/Rust mutant close-out: none surviving, and every close-out line is read (a second,
# inflated line is not rescued by a first honest one). Two honest shapes are accepted, with the
# measured-split form (2026-11-09) the one a real run writes: the JVM privacy-world close-out
# (`media mutants: N run, N detected`) plus the Rust S1 crate set (`media S1 mutants: M run,
# M detected`) — the suite's own lines name the design's §22.12 pending list (the key-slot/binding
# kills and the emulator seven) — or, for old reports, the design's single aggregate 43 line.
jvm_close="$(sed -nE 's/^media mutants: ([0-9]+) run, ([0-9]+) detected.*$/\1 \2/p' "$report" | { grep -v '^43 43$' || true; } | sed -n '1p')"
s1_close="$(sed -nE 's/^media S1 mutants: ([0-9]+) run, ([0-9]+) detected$/\1 \2/p' "$report" | sed -n '1p')"
legacy_close="$(sed -nE 's/^media mutants: 43 run, 43 detected$/43 43/p' "$report" | sed -n '1p')"
if [ -z "$jvm_close" ] && [ -z "$legacy_close" ]; then
  bad "no JVM mutant close-out line ('media mutants: N run, N detected')"
fi
# The JVM privacy-world registry is a fixed set (MediaMutantDetectionTest): any other count is
# a different claim, not a stronger one — the overclaim drill of exit-mutants-overclaim.txt.
if [ -n "$jvm_close" ] && [ "$jvm_close" != "9 9" ]; then
  bad "the JVM close-out claims $jvm_close, not the registered 9 run, 9 detected"
fi
if [ -n "$jvm_close" ] && [ -z "$s1_close" ]; then
  bad "the JVM mutant close-out names the Rust S1 set as pending, but the report has no 'media S1 mutants:' line"
fi
# The S1 close-out cannot claim more mutants than the patches that exist (tree-derived bound).
MRC_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
s1_patches=0
[ -d "$MRC_ROOT/client-core/media/mutants" ] && \
  s1_patches=$(find "$MRC_ROOT/client-core/media/mutants" -maxdepth 1 -name '*.patch' 2>/dev/null | wc -l | tr -d ' ')
if [ -n "$s1_close" ]; then
  s1_run="${s1_close%% *}"
  [ "$s1_run" -le "$s1_patches" ] || \
    bad "the S1 close-out claims $s1_run mutants run, more than the $s1_patches patches that exist"
fi
for var in jvm_close s1_close legacy_close; do
  eval "pair=\"\$$var\""
  [ -z "$pair" ] && continue
  run="${pair%% *}"; det="${pair##* }"
  [ "$run" -ge 1 ] || bad "the report claims $run mutants run (an empty close-out proves nothing)"
  [ "$det" -eq "$run" ] || bad "the report claims $det detected of $run run (a surviving mutant fails the gate)"
done
# An aggregate line beyond the accepted shapes is still read: no invented totals.
while read -r line_run line_det; do
  ok=0
  [ -n "$jvm_close" ] && [ "$line_run $line_det" = "$jvm_close" ] && ok=1
  [ -n "$s1_close" ] && [ "$line_run $line_det" = "$s1_close" ] && ok=1
  [ -n "$legacy_close" ] && [ "$line_run $line_det" = "$legacy_close" ] && ok=1
  [ "$ok" = 1 ] || bad "an unrecognised mutant close-out line claims $line_run run, $line_det detected"
done < <(sed -nE 's/^(media( S1)? mutants): ([0-9]+) run, ([0-9]+) detected.*$/\3 \4/p' "$report")

[ "$fail" = 0 ] || exit 1
echo "[media-report-check] OK ($kind)"
