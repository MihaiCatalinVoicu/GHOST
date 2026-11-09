#!/usr/bin/env bash
# Gate (Phase 9 design §15.5 PQ1 and PQ5, RG-5, §15.7 PM-32; forward notes §22.20): the PQ1 and PQ5
# tests of `ghost-client-dm` (`client-core/dm/src/pq_bump.rs`) pass on the tree, and every mutant of
# `client-core/dm/mutants/` makes the tests it names fail.
#
# Why a mutant gate: PM-32, "the intro inner layer sealed without the X-Wing KEM", is what T35's
# provenance tags cannot see (§22.16 item 18: `k_in` is never a `SealKey`), and PQ1 and PQ5 are what
# holds it. A PQ test that stops failing on PM-32 would pass on a client without post-quantum intros,
# so each of PM-32's shapes is kept as a source patch and run here. Each patch carries, before its
# diff, one `# kills: <test path>` line per test that must fail with it applied.
#
# The tests are built with `jni-bridge`, so `jni.rs`'s own `openIntro` body — the one the host
# library the JVM worlds load runs, under PQ1's assertion — is compiled and tested here too.
#
# For each patch, in the checkout, one at a time:
#   - it applies exactly (`git apply --check`, no fuzz): a patch that no longer applies is a mutant
#     nobody runs, and fails the gate until it is regenerated;
#   - with it applied the test binary builds: a mutant that does not compile kills nothing;
#   - the PQ tests fail, and every test its header names is among the failures;
#   - the shared world's own test (WORLD below) still **passes**: every PQ test reads one scripted
#     world, and a patch that broke it would fail them all for a reason that is not its own — the
#     gate would credit it with kills it never earned;
#   - it is reverted before the next one, and on any exit; a revert that fails stops the gate
#     with a failure, since every later patch would apply to a mutated tree.
# The unpatched run must pass, 0 failed and 0 ignored, and run every test any header names and WORLD.
#
# It changes files under client-core/dm while it runs (and reverts them): run it in a CI checkout or
# a clean worktree, never beside an editor saving into the same files.
# Hooks (scripts/gates/self-test.sh): GHOST_PQ_MUTANTS_DIR (the patches), GHOST_PQ_MUTANTS_REPO (the
# git work tree they apply to), GHOST_PQ_CARGO (the cargo it runs; a fake in the self-test),
# GHOST_PQ_WORLD (the world's test).
source "$(dirname "${BASH_SOURCE[0]}")/common.sh"
CARGO="${GHOST_PQ_CARGO:-cargo}"
command -v "$CARGO" >/dev/null || { echo "cargo not found" >&2; exit 2; }
command -v git >/dev/null || { echo "git not found" >&2; exit 2; }
DIR="${GHOST_PQ_MUTANTS_DIR:-$GHOST_ROOT/client-core/dm/mutants}"
REPO="${GHOST_PQ_MUTANTS_REPO:-$(git -C "$GHOST_ROOT" rev-parse --show-toplevel)}"
WORLD="${GHOST_PQ_WORLD:-pq_bump::pq_world_every_honest_flight_opens_and_every_root_arrives}"
FILTERS=(pq1_ pq5_ pq_world_)
work="$(mktemp -d)"
applied=""
restore() { # reverts the applied patch; a revert that fails is a gate failure
  [ -n "$applied" ] || return 0
  local patch="$applied"
  applied=""
  if ! git -C "$REPO" apply -R "$patch"; then
    fail "could not revert $(basename "$patch"); restore the tree by hand"
    return 1
  fi
}
on_exit() {
  local status=$?
  restore || status=1
  rm -rf "$work"
  exit "$status"
}
trap on_exit EXIT
# Every revert inside the loop: on failure, stop here (finish exits 1, FAILURES > 0).
revert() { restore || finish pq-mutants; }
cd "$GHOST_ROOT"

run_tests() { # $1 = output file; cargo's status
  "$CARGO" test -p ghost-client-dm --lib --locked --features jni-bridge -- "${FILTERS[@]}" 2>&1 \
    | tr -d '\r' >"$1"
  return "${PIPESTATUS[0]}"
}
# libtest prints `test <path> ... ok|FAILED`, or `test <path> - should panic ... ok|FAILED`.
results() { # $1 = output file, $2 = ok|FAILED
  sed -nE "s/^test ([^ ]+)( - should panic)? \\.\\.\\. $2\$/\\1/p" "$1" | sort -u
}
has() { grep -qxF "$2" <<< "$1"; }

shopt -s nullglob
patches=("$DIR"/*.patch)
shopt -u nullglob
[ "${#patches[@]}" -gt 0 ] || { fail "no mutant patch in $DIR"; finish pq-mutants; }
declared=""
for patch in "${patches[@]}"; do
  declared+="$(sed -nE 's/^# kills: ([A-Za-z0-9_:]+)[[:space:]]*$/\1/p' "$patch")"$'\n'
done
declared="$(printf '%s' "$declared" | grep -v '^$' | sort -u || true)"
has "$declared" "$WORLD" && fail "a mutant names $WORLD, the world every mutant must leave passing"

# The tree as it is: every PQ test passes, none is ignored, and every test a header names ran.
if ! run_tests "$work/clean"; then
  fail "the PQ1 and PQ5 tests fail on the unpatched tree"
  tail -30 "$work/clean" >&2
  finish pq-mutants
fi
grep -qE '^test result: ok\. [1-9][0-9]* passed; 0 failed; 0 ignored;' "$work/clean" \
  || fail "the unpatched run did not pass with 0 ignored: $(grep -E '^test result:' "$work/clean" | sed -n '1p')"
passed="$(results "$work/clean" ok)"
has "$passed" "$WORLD" || fail "the unpatched run did not run and pass the world's test $WORLD"
while IFS= read -r test; do
  [ -n "$test" ] || continue
  has "$passed" "$test" || fail "a mutant names $test, which the unpatched run did not run and pass"
done <<< "$declared"
echo "[pq-mutants] unpatched: $(printf '%s\n' "$passed" | grep -c .) PQ1 and PQ5 tests passed"

for patch in "${patches[@]}"; do
  name="$(basename "$patch")"
  kills="$(sed -nE 's/^# kills: ([A-Za-z0-9_:]+)[[:space:]]*$/\1/p' "$patch" | sort -u)"
  if [ -z "$kills" ]; then fail "$name names no test it kills (# kills: lines)"; continue; fi
  if ! git -C "$REPO" apply --check "$patch" 2>"$work/apply"; then
    fail "$name does not apply to the tree: $(head -3 "$work/apply" | tr '\n' ' ')"
    continue
  fi
  git -C "$REPO" apply "$patch"
  applied="$patch"
  if ! "$CARGO" test -p ghost-client-dm --lib --locked --features jni-bridge --no-run >"$work/build" 2>&1; then
    fail "$name does not build, so it kills nothing"
    tail -20 "$work/build" >&2
    revert
    continue
  fi
  if run_tests "$work/run"; then
    fail "$name survived: every PQ1 and PQ5 test passed with it applied"
    revert
    continue
  fi
  failed="$(results "$work/run" FAILED)"
  if [ -z "$failed" ]; then
    fail "$name: the run failed without a failing test"
    tail -20 "$work/run" >&2
    revert
    continue
  fi
  if ! has "$(results "$work/run" ok)" "$WORLD"; then
    fail "$name breaks the shared world ($WORLD did not pass), so its kills say nothing"
    revert
    continue
  fi
  while IFS= read -r test; do
    has "$failed" "$test" || fail "$name: $test did not fail"
  done <<< "$kills"
  echo "[pq-mutants] $name killed by $(printf '%s\n' "$failed" | grep -c .) test(s): $(printf '%s ' $failed)"
  revert
done
finish pq-mutants
