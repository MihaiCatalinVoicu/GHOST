#!/usr/bin/env bash
# The `cargo` of the pq-mutants self-test (scripts/gates/self-test.sh; Phase 9 design §22.20): it
# answers the two calls scripts/gates/pq-mutants.sh makes from a state file of a scratch git tree,
# which each mutant patch of the self-test rewrites, so the gate's decisions are proven without
# compiling anything.
#
#   `test ... --no-run`     builds, unless the state is `nobuild`;
#   `test ... -- <filter>`  prints libtest lines for two tests, t::a and t::b:
#       clean       the unpatched tree; GHOST_PQ_FAKE_CLEAN=pass (default), fail, missing (t::b not
#                   run) or ignored (a third test ignored);
#       survive     both pass;
#       kill-a      t::a fails;
#       kill-ab     t::a (a should-panic test) and t::b fail;
#       noname      the run fails without a failing test line.
set -uo pipefail
state="$(tr -d '\r\n' < "$GHOST_PQ_FAKE_STATE")"
case " $* " in
  *" --no-run "*)
    if [ "$state" = nobuild ]; then echo "error: could not compile ghost-client-dm" >&2; exit 101; fi
    exit 0
    ;;
esac
result() { # $1 = passed, $2 = failed, $3 = ignored
  local verdict=ok
  [ "$2" = 0 ] || verdict=FAILED
  echo "test result: $verdict. $1 passed; $2 failed; $3 ignored; 0 measured; 170 filtered out"
}
case "$state" in
  clean)
    case "${GHOST_PQ_FAKE_CLEAN:-pass}" in
      pass) echo "test t::a ... ok"; echo "test t::b ... ok"; result 2 0 0; exit 0 ;;
      fail) echo "test t::a ... ok"; echo "test t::b ... FAILED"; result 1 1 0; exit 101 ;;
      missing) echo "test t::a ... ok"; result 1 0 0; exit 0 ;;
      ignored) echo "test t::a ... ok"; echo "test t::b ... ok"; echo "test t::c ... ignored"; result 2 0 1; exit 0 ;;
    esac
    ;;
  survive) echo "test t::a ... ok"; echo "test t::b ... ok"; result 2 0 0; exit 0 ;;
  kill-a) echo "test t::a ... FAILED"; echo "test t::b ... ok"; result 1 1 0; exit 101 ;;
  kill-ab) echo "test t::a - should panic ... FAILED"; echo "test t::b ... FAILED"; result 0 2 0; exit 101 ;;
  noname) echo "error: test failed, to rerun pass \`-p ghost-client-dm --lib\`" >&2; exit 101 ;;
esac
echo "fake-cargo: unknown state '$state'" >&2
exit 2
