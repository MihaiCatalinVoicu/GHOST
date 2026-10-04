#!/usr/bin/env bash
# The mutants of slice S1's media crate (Phase 11 design faza11-media.md §15.9's method, §22.2 row 18).
# Each client-core/media/mutants/<id>.patch breaks one invariant of `ghost-client-media`; this script
# applies it (patch -p1 from ghost/), runs the crate's tests (`cargo test --locked -p
# ghost-client-media --no-fail-fast`), lists every failing test as <test binary>::<test>, and reverts
# the patch. A mutant is detected when at least one test fails (a `test … FAILED` line) or a test
# binary crashes (cargo's "process didn't exit successfully" with a signal or a Windows exception
# status); it survives when the tests pass. The design's registry numbers (PM-M…, MC-M…) are slice
# S9's; these are S1's own (ms01 …), each naming the design mutant whose shape it has where there is
# one.
#
# Anything else says nothing about the tests and fails the run: a mutant whose build fails (a compile
# error, or the machine out of disk space) is NOT BUILT; a run that fails without a failing test or a
# crash (cargo refusing the lock file, a missing input, a test harness that never started) is NOT
# RUN (the review of S1: a stale Cargo.lock had been counted as "detected").
#
# Usage: media-mutants.sh [<id> …] (default: every patch). Prints one line per mutant and
# `media S1 mutants: <run> run, <detected> detected`; exits 1 when a mutant survives, 2 when a patch
# does not apply or revert or a mutant is not built or not run. Run from anywhere; it changes only
# the crate's sources, and restores them. CARGO_TARGET_DIR is honoured; with MEDIA_MUTANTS_LOG_DIR set,
# each mutant's whole cargo output is kept there as <id>.log.
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"
patches=()
if [ "$#" -eq 0 ]; then
  patches=(client-core/media/mutants/*.patch)
else
  for id in "$@"; do
    [ -f "client-core/media/mutants/$id.patch" ] || { echo "$id: no such mutant" >&2; exit 2; }
    patches+=("client-core/media/mutants/$id.patch")
  done
fi
run=0
detected=0
survivors=""
unbuilt=""
unrun=""
for p in "${patches[@]}"; do
  id="$(basename "$p" .patch)"
  patch -p1 -s < "$p" || { echo "$id: does not apply" >&2; exit 2; }
  out="$(cargo test --locked -p ghost-client-media --no-fail-fast 2>&1)"
  status=$?
  patch -p1 -R -s < "$p" || { echo "$id: does not revert" >&2; exit 2; }
  [ -z "${MEDIA_MUTANTS_LOG_DIR:-}" ] || printf '%s\n' "$out" > "$MEDIA_MUTANTS_LOG_DIR/$id.log"
  run=$((run + 1))
  killers="$(awk '
    /Running (unittests )?[^ ]+/ { for (i = 1; i <= NF; i++) if ($i == "Running") { b = $(i + 1); if (b == "unittests") b = $(i + 2) } gsub(/\\/, "/", b); sub(/^tests\//, "", b); sub(/\.rs$/, "", b); bin = b }
    /^test .* \.\.\. FAILED$/ { sub(/^test /, ""); sub(/ \.\.\. FAILED$/, ""); print bin "::" $0 }
  ' <<< "$out" | sort -u | tr '\n' ' ')"
  crash="$(grep -m1 -E "process didn't exit successfully: .*\((signal: [0-9]+|exit (code|status): 0xc[0-9a-fA-F]{7})" <<< "$out" || true)"
  if grep -qE '^error: (could not compile|failed to build archive|failed to write|the compiler unexpectedly panicked)' <<< "$out"; then
    unbuilt+="$id "
    echo "$id: NOT BUILT ($(grep -m1 -E '^error' <<< "$out"))"
  elif [ "$status" -ne 0 ] && [ -n "$killers" ]; then
    detected=$((detected + 1))
    echo "$id: detected by $killers"
  elif [ "$status" -ne 0 ] && [ -n "$crash" ]; then
    detected=$((detected + 1))
    echo "$id: detected (a test binary crashed: $crash)"
  elif [ "$status" -ne 0 ]; then
    unrun+="$id "
    echo "$id: NOT RUN (no failing test and no crash: $(grep -m1 -E '^error' <<< "$out" || echo "cargo exited $status"))"
  else
    survivors+="$id "
    echo "$id: SURVIVED"
  fi
done
echo "media S1 mutants: $run run, $detected detected"
[ -z "$unbuilt" ] || { echo "not built: $unbuilt" >&2; exit 2; }
[ -z "$unrun" ] || { echo "not run: $unrun" >&2; exit 2; }
[ -z "$survivors" ] || { echo "surviving: $survivors" >&2; exit 1; }
