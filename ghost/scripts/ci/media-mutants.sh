#!/usr/bin/env bash
# The mutants of slice S1's media crate (Phase 11 design faza11-media.md §15.9's method; the S1 brief:
# "mutants of your own for the crate's invariants, which tests kill which"). Each
# client-core/media/mutants/<id>.patch breaks one invariant of `ghost-client-media`; this script applies
# it (patch -p1 from ghost/), runs the crate's tests (`cargo test --locked -p ghost-client-media
# --no-fail-fast`), lists every failing test as <test binary>::<test>, and reverts the patch. A mutant
# is detected when at least one test fails; it survives otherwise. The design's registry numbers
# (PM-M…, MC-M…) are slice S9's; these are S1's own (ms01 …), each naming the design mutant whose shape
# it has where there is one.
#
# A mutant whose build fails (a compile error, or the machine out of disk space) is neither detected
# nor surviving: it says nothing about the tests, so it is reported as NOT BUILT and fails the run.
#
# Usage: media-mutants.sh [<id> …] (default: every patch). Prints one line per mutant and
# `media S1 mutants: <run> run, <detected> detected`; exits 1 when a mutant survives, 2 when a patch
# does not apply or revert or a mutant does not build. Run from anywhere; it changes only the crate's
# sources, and restores them. CARGO_TARGET_DIR is honoured; with MEDIA_MUTANTS_LOG_DIR set, each
# mutant's whole cargo output is kept there as <id>.log.
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
  if grep -qE '^error: (could not compile|failed to build archive|failed to write|the compiler unexpectedly panicked)' <<< "$out"; then
    unbuilt+="$id "
    echo "$id: NOT BUILT ($(grep -m1 -E '^error' <<< "$out"))"
  elif [ "$status" -ne 0 ]; then
    detected=$((detected + 1))
    if [ -n "$killers" ]; then
      echo "$id: detected by $killers"
    else
      echo "$id: detected (a test binary did not finish: $(grep -m1 -E '^error' <<< "$out"))"
    fi
  else
    survivors+="$id "
    echo "$id: SURVIVED"
  fi
done
echo "media S1 mutants: $run run, $detected detected"
[ -z "$unbuilt" ] || { echo "not built: $unbuilt" >&2; exit 2; }
[ -z "$survivors" ] || { echo "surviving: $survivors" >&2; exit 1; }
