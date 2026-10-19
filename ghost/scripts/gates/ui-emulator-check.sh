#!/usr/bin/env bash
# The UI emulator report check (Phase 13 design faza13-ux.md §12.3, §13.2; on the
# dm-emulator-check.sh pattern): **a report is evidence only if something refuses an incomplete one.**
#
#   ui-emulator-check.sh <report-dir> <api> [<api> ...]
#
# `<report-dir>/api<N>/` is what the ui-emulator run writes for API level N: the emulator's own
# `sdk=`/`abi=` lines (`device.txt`) and the raw `am instrument -r -w` output of each UI suite
# (`suite-<name>.txt`, one per suite of §12.3 that this phase's slices have landed). For every API
# level named here:
#   - a missing directory or suite file is **not run**, and not run is red (Q44: signed local runs
#     of the same scripts count, a missing run never does);
#   - the emulator is that API level on x86_64;
#   - every suite finished with `INSTRUMENTATION_CODE: -1` (RESULT_OK), 0 failed and 0 skipped:
#     a skipped device test is a green tick over nothing;
#   - the test count of every suite equals the count pinned in
#     `test-harness/gates/ui-emulator-counts.txt` (`<name> <count>`): a suite that silently lost
#     tests leaves this check green otherwise, which is the failure mode the pin exists for. The
#     file is filled by the slices that land the suites (S1's smoke first); an API level whose
#     suite set is empty is not run, and not run is red.
#
# Exit 0 pass, 1 fail, 2 usage. Self-test: scripts/gates/self-test.sh with the fixtures in
# test-harness/gates/ui-emulator/.
set -euo pipefail
GATES_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GHOST_ROOT="${GHOST_ROOT:-$(cd "$GATES_DIR/../.." && pwd)}"
COUNTS="$GHOST_ROOT/test-harness/gates/ui-emulator-counts.txt"

dir="${1:-}"
[ -n "$dir" ] && [ $# -ge 2 ] || { echo "usage: ui-emulator-check.sh <report-dir> <api> [<api> ...]" >&2; exit 2; }
shift
for api in "$@"; do
  case "$api" in ''|*[!0-9]*) echo "not an API level: $api" >&2; exit 2 ;; esac
done

fail=0
bad() { echo "UI-EMULATOR-FAIL: $*" >&2; fail=1; }

# The expected suite set and counts, from the pinned file.
declare -A EXPECT=()
while IFS=' ' read -r name count; do
  case "$name" in ''|\#*) continue ;; esac
  EXPECT[$name]="$count"
done < "$COUNTS"
[ "${#EXPECT[@]}" -gt 0 ] || bad "ui-emulator-counts.txt defines no suites (not run is red)"

for api in "$@"; do
  d="$dir/api$api"
  [ -d "$d" ] || { bad "api$api: no report directory (not run is red)"; continue; }
  grep -q "sdk=$api" "$d/device.txt" 2>/dev/null || bad "api$api: device.txt missing or not this level"
  grep -q 'abi=x86_64' "$d/device.txt" 2>/dev/null || bad "api$api: not an x86_64 image"
  for name in "${!EXPECT[@]}"; do
    f="$d/suite-$name.txt"
    [ -f "$f" ] || { bad "api$api: suite $name has no report (not run is red)"; continue; }
    grep -q 'INSTRUMENTATION_CODE: -1' "$f" || bad "api$api: suite $name did not finish RESULT_OK"
    # The raw `am instrument -r` stream reports each passed test with an
    # INSTRUMENTATION_STATUS_CODE: 1 block; a failure or a skip arrives as -2 or -3. The OK
    # line carries the total. The legacy "Tests run:" JUnit summary is what this check
    # expected blind at S0b - the device prints no such line.
    runs=$(tr -d '\r' < "$f" | grep -c 'INSTRUMENTATION_STATUS_CODE: 1')
    [ "$runs" = "${EXPECT[$name]}" ] || bad "api$api: suite $name must report exactly ${EXPECT[$name]} passing tests, saw $runs"
    if tr -d '\r' < "$f" | grep -qE 'INSTRUMENTATION_STATUS_CODE: -[23]'; then
      bad "api$api: suite $name has a failure or a skipped test"
    fi
  done
done

[ "$fail" -eq 0 ] && echo "[ui-emulator-check] OK"
exit "$fail"
