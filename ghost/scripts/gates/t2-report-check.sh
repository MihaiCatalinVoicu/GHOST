#!/usr/bin/env bash
# The T2 report check (Phase 8 design §13.4, §13.6): a T2 job may pass only with a complete report.
#   t2-report-check.sh <report> gate|pr    a variant report (tests/t2_unlinkability.rs): a PASS line
#                                          for every check of §13.4 and §19.16, the variant's scale,
#                                          and the final "T2 RESULT: PASS";
#   t2-report-check.sh <report> mutants    the output of tests/t2_mutants.rs: all 23 privacy mutants
#                                          (M1–M21 with M2b, M5a and M5b) detected.
# A missing report, a missing line or a FAIL fails the check (exit 1); usage errors exit 2.
set -euo pipefail
report="${1:-}"
kind="${2:-}"
[ -n "$report" ] && [ -n "$kind" ] || { echo "usage: t2-report-check.sh <report> gate|pr|mutants" >&2; exit 2; }
fail=0
bad() { echo "T2-REPORT-FAIL: $*" >&2; fail=1; }
[ -f "$report" ] || { echo "T2-REPORT-FAIL: no report at $report" >&2; exit 1; }
case "$kind" in
  gate|pr)
    checks=(J1 J2 J3 J4 J5 J6 J7 J8 J9 J10 T2b T2c completeness S1 S2 S3a S3b S3d S4 \
      "S4 lying issuer" "J9 lying issuer" NI-1 "NI-1 across cells" NI-2 NI-3 NI-1d)
    for c in "${checks[@]}"; do
      grep -qE "^${c}: PASS( |$)" "$report" || bad "no PASS line for $c"
      if grep -qE "^${c}: FAIL( |$)" "$report"; then bad "$c failed"; fi
    done
    if [ "$kind" = gate ]; then scale='N = 2000 packs, 84 days'; else scale='N = 300 packs, 21 days'; fi
    grep -qF "$scale" "$report" || bad "the report is not of the $kind scale ($scale)"
    grep -qE '^S3c \(reported' "$report" || bad "no S3c line (quiet-gap bits are always reported)"
    grep -qxF 'T2 RESULT: PASS' "$report" || bad "no final 'T2 RESULT: PASS'"
    ;;
  mutants)
    n="$(grep -cE '^test m[0-9]+[a-z]?_[a-z0-9_]+ \.\.\. ok$' "$report" || true)"
    [ "$n" = 23 ] || bad "$n of 23 mutants detected"
    grep -qE '^test result: ok\. 23 passed; 0 failed' "$report" || bad "no 'test result: ok. 23 passed; 0 failed'"
    ;;
  *) echo "unknown report kind: $kind" >&2; exit 2 ;;
esac
[ "$fail" = 0 ] || exit 1
echo "[t2-report-check] OK ($kind)"
