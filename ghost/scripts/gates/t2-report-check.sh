#!/usr/bin/env bash
# The T2 report check (Phase 8 design §13.4, §13.6): a T2 job may pass only with a complete report.
#   t2-report-check.sh <report> gate|pr    a variant report (tests/t2_unlinkability.rs): a PASS line
#                                          for every check of §13.4, §19.16 and §19.31 (A1, the
#                                          FR-6′.7 amount uniformity), the variant's scale, the
#                                          reported S3c and E30 lines (E30 with a held session,
#                                          §19.26), the population line's `dm_owner_namespaces`
#                                          field — three per owner since Phase 11's S4-owner slice
#                                          (Phase 11 design §5.2's T2 bullet), some registered,
#                                          registrations answered OK and none failed — and
#                                          the final "T2 RESULT: PASS";
#   t2-report-check.sh <report> mutants    the output of tests/t2_mutants.rs: all 26 privacy mutants
#                                          (M1–M24 with M2b, M5a and M5b) detected.
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
    checks=(population J1 J2 J3 J4 J5 J6 J7 J8 J9 J10 T2b T2c completeness A1 S1 S2 S3a S3b S3d S4 \
      "S4 lying issuer" "J9 lying issuer" NI-1 "NI-1 across cells" NI-2 NI-3 NI-1d)
    for c in "${checks[@]}"; do
      grep -qE "^${c}: PASS( |$)" "$report" || bad "no PASS line for $c"
      if grep -qE "^${c}: FAIL( |$)" "$report"; then bad "$c failed"; fi
    done
    # A statistical or twin check that passed on an empty sample tested nothing (the harness
    # fails below its floors; a report that says otherwise is not evidence).
    if grep -qE '^(S1|S2): PASS n=0 |^S3[abd]: PASS .*n=0 |^S4( lying issuer)?: PASS .* over 0 |^NI-1d: PASS 0 drop|^NI-1 across cells: PASS 0 flows|^NI-1: PASS .*; 0 finalizations' "$report"; then
      bad "a check passed on an empty sample"
    fi
    # Phase 9 design §4.9 point 3, extended by Phase 11 design §5.2's T2 bullet (S4-owner): the
    # population line counts the DM owner namespaces — three per activated client, the owners
    # counted from the client list and not by the step that adds the namespaces — how many of
    # them a relay registered, and the registrations the relays answered OK, WRONG_PERIOD or not
    # at all. A population that names none, registered nothing, is not three per owner, or whose
    # loopback failed a registration, did not model them.
    dm_field="$(sed -nE 's/^population: PASS .*dm_owner_namespaces ([0-9]+) \(3 per activated client: ([0-9]+) owners, ([0-9]+) namespaces registered at a relay; ([0-9]+) registrations ok, ([0-9]+) wrong_period, ([0-9]+) failed\).*/\1 \2 \3 \4 \6/p' "$report" | head -1)"
    if [ -z "$dm_field" ]; then
      bad "the population line names no dm_owner_namespaces with its owners and registrations (Phase 9 design §4.9, Phase 11 §5.2)"
    else
      read -r dm_ns dm_owners dm_registered dm_ok dm_failed <<<"$dm_field"
      [ "$dm_owners" -gt 0 ] || bad "the population line counts no DM owner"
      [ "$dm_ns" -eq $(( 3 * dm_owners )) ] || bad "$dm_ns DM owner namespaces for $dm_owners owners, not three per activated client (Phase 11 design §5.2)"
      [ "$dm_registered" -gt 0 ] || bad "no DM owner namespace was registered at a relay"
      [ "$dm_ok" -gt 0 ] || bad "the population line counts DM owner namespaces with no registration answered OK"
      [ "$dm_failed" -eq 0 ] || bad "$dm_failed DM registrations failed on the loopback"
    fi
    # A1 (FR-6′.7, design §19.31) states every invoice amount and every transfer to an invoice's
    # subaddress: a PASS over no XMR invoice answer or no transfer tested nothing.
    if grep -qE '^A1: PASS 0 XMR invoice answers|^A1: PASS .*; 0 wallet transfers' "$report"; then
      bad "A1 passed with no XMR invoice answer or no wallet transfer"
    fi
    # NI-2 and NI-3 test the refresh rule only through drop reads their relays moved (design §19.26).
    if grep -qE '^NI-[23]: PASS .*\(0 by an hour or more' "$report"; then
      bad "NI-2 or NI-3 passed with no drop read moved by an hour or more"
    fi
    # They compare the issuer and wallet views as a whole, with no exemption (design §19.29): a
    # PASS line must say so.
    for c in NI-2 NI-3; do
      if grep -qE "^${c}: PASS( |$)" "$report" && ! grep -qE "^${c}: PASS .*no exemption" "$report"; then
        bad "$c passed without identical views and no exemption"
      fi
    done
    if [ "$kind" = gate ]; then scale='N = 2000 packs, 84 days'; else scale='N = 300 packs, 21 days'; fi
    grep -qF "$scale" "$report" || bad "the report is not of the $kind scale ($scale)"
    grep -qE '^S3c \(reported' "$report" || bad "no S3c line (quiet-gap bits are always reported)"
    # E30, the Q29 redeem hold (design §12.6, §19.26): its measurement is always reported, and a
    # world in which no background session was held measured nothing.
    grep -qE '^E30 \(reported' "$report" || bad "no E30 line (the redeem hold is always reported)"
    if grep -qE '^E30 \(reported.*, 0 held past their lanes' "$report"; then
      bad "E30 measured no held session"
    fi
    grep -qxF 'T2 RESULT: PASS' "$report" || bad "no final 'T2 RESULT: PASS'"
    ;;
  mutants)
    # A detected mutant is libtest's "test <name> ... ok" at the start of a line, counted once per
    # name. The line may run on: with --nocapture another test's output can land between libtest's
    # "ok" and its newline (design §19.31, point 5).
    n="$(grep -oE '^test m[0-9]+[a-z]?_[a-z0-9_]+ \.\.\. ok' "$report" | sort -u | grep -c . || true)"
    [ "$n" = 26 ] || bad "$n of 26 mutants detected"
    grep -qE '^test result: ok\. 26 passed; 0 failed' "$report" || bad "no 'test result: ok. 26 passed; 0 failed'"
    ;;
  *) echo "unknown report kind: $kind" >&2; exit 2 ;;
esac
[ "$fail" = 0 ] || exit 1
echo "[t2-report-check] OK ($kind)"
