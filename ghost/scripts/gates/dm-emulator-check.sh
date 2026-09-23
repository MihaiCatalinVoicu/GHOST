#!/usr/bin/env bash
# The emulator report check (Phase 9 design §15.9, §22.8.10 point 6; slice S12), on the
# `dm-report-check.sh` pattern: **a report is evidence only if something refuses an incomplete one.**
#
#   dm-emulator-check.sh <report-dir> <api> [<api> ...]
#
# `<report-dir>/api<N>/` is what `scripts/device/dm-emulator-run.sh` writes for API level N: the
# emulator's own `sdk=`/`abi=` lines (`device.txt`) and the raw `am instrument -r -w` output of each
# suite. For every API level named here:
#   - a missing directory or suite file is **not run**, and not run is red (§15.9 "Status": a run
#     that cannot start the emulator reports not run, never green);
#   - the emulator is that API level on `x86_64` (§15.9 "Runner");
#   - every suite finished with `INSTRUMENTATION_CODE: -1` (RESULT_OK), never crashed, and its
#     summary line says exactly the number of tests this slice runs, **0 failed and 0 skipped**
#     (`org.ghost.device.DeviceRunner`): a skipped device test is a green tick over nothing;
#   - every report line the suites promise is there:
#       crypto-bridge  `dm-equivalence: N cases, N identical, control detected`, with N the number
#                      of cases in `protocol/test-vectors/dm_equivalence.txt` (§15.9 item 7: the
#                      comparator ran over every case, and its control was detected);
#       messaging      the SQLCipher v3 -> v4 -> v5 migration, SCN-A, SCN-B, SCN-F with the WAL at
#                      0 bytes, the alarm scheduled and cancelled, and SCN-D's key change with a
#                      logcat scan over at least one canary (§15.9 items 2, 5 and 6);
#       app-smoke      the release smoke test: the shipped library in the R8-shrunk APK, one
#                      in-process Olm session, no transport (§15.9 item 3).
#
# The equivalence line is checked here and not in `dm-report-check.sh`, which checks the JVM exit
# gate's report: the two reports come from different jobs, and a check that read both would pass
# one job on the other's evidence.
#
# **The numbers are the ones this slice runs.** Six messaging tests, one equivalence test, one smoke
# test; adding a device test raises the number here in the same change, which is the point: a test
# that silently stopped running would otherwise leave this check green.
#
# Exit 0 pass, 1 fail, 2 usage. Self-test: scripts/gates/self-test.sh with the fixtures in
# test-harness/gates/dm-emulator/.
set -euo pipefail
GATES_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GHOST_ROOT="${GHOST_ROOT:-$(cd "$GATES_DIR/../.." && pwd)}"
CASES="${GHOST_DM_EQUIVALENCE_CASES:-$GHOST_ROOT/protocol/test-vectors/dm_equivalence.txt}"

dir="${1:-}"
[ -n "$dir" ] && [ $# -ge 2 ] || { echo "usage: dm-emulator-check.sh <report-dir> <api> [<api> ...]" >&2; exit 2; }
shift
for api in "$@"; do
  case "$api" in ''|*[!0-9]*) echo "not an API level: $api" >&2; exit 2 ;; esac
done

fail=0
bad() { echo "DM-EMULATOR-FAIL: $*" >&2; fail=1; }

[ -s "$CASES" ] || { echo "DM-EMULATOR-FAIL: no case file at $CASES" >&2; exit 1; }
cases="$(grep -cvE '^[[:space:]]*(#|$)' "$CASES" || true)"
[ "$cases" -gt 0 ] || { echo "DM-EMULATOR-FAIL: the case file $CASES holds no case" >&2; exit 1; }

# The report lines of one suite file: `am instrument -r` prints the result bundle's `stream` as
# `INSTRUMENTATION_RESULT: stream=<first line>` followed by the rest of its lines, raw.
lines() { sed -e 's/\r$//' -e 's/^INSTRUMENTATION_RESULT: stream=//' "$1"; }

suite() { # api name expected-tests required-pattern...
  local api="$1" name="$2" expected="$3" file
  shift 3
  file="$dir/api$api/$name.txt"
  if [ ! -s "$file" ]; then
    bad "API $api $name: not run (no output at $file)"
    return
  fi
  local code
  code="$(sed -e 's/\r$//' "$file" | sed -nE 's/^INSTRUMENTATION_CODE: (-?[0-9]+)$/\1/p' | tail -n 1)"
  [ "$code" = "-1" ] || bad "API $api $name: the instrumentation finished with code '${code:-none}', not -1 (RESULT_OK)"
  if grep -qE '^INSTRUMENTATION_(FAILED|ABORTED)|shortMsg=Process crashed' "$file"; then
    bad "API $api $name: the instrumentation crashed or failed to start"
  fi
  local summary
  summary="$(lines "$file" | grep -E '^device tests: [0-9]+ run, [0-9]+ failed, [0-9]+ skipped$' | tail -n 1 || true)"
  if [ -z "$summary" ]; then
    bad "API $api $name: no summary line (device tests: R run, F failed, S skipped)"
  elif [ "$summary" != "device tests: $expected run, 0 failed, 0 skipped" ]; then
    bad "API $api $name: '$summary', expected $expected run, 0 failed, 0 skipped"
  fi
  local pattern
  for pattern in "$@"; do
    lines "$file" | grep -qE "$pattern" || bad "API $api $name: no line matching '$pattern'"
  done
  [ "$fail" = 0 ] && echo "API $api $name: $summary"
  return 0
}

for api in "$@"; do
  if [ ! -d "$dir/api$api" ]; then
    bad "API $api: not run (no report directory $dir/api$api)"
    continue
  fi
  device="$dir/api$api/device.txt"
  if [ ! -s "$device" ]; then
    bad "API $api: not run (no device.txt: the emulator was never reached)"
  else
    sdk="$(sed -nE 's/^sdk=([0-9]+)\r?$/\1/p' "$device")"
    abi="$(sed -nE 's/^abi=([A-Za-z0-9_-]+)\r?$/\1/p' "$device")"
    [ "$sdk" = "$api" ] || bad "API $api: the emulator reported API '${sdk:-none}'"
    [ "$abi" = x86_64 ] || bad "API $api: the emulator's ABI is '${abi:-none}', not x86_64"
  fi
  suite "$api" crypto-bridge 1 \
    "^dm-equivalence: $cases cases, $cases identical, control detected\$"
  suite "$api" messaging 6 \
    '^dm-device: sqlcipher v3 -> v4 -> v5 ok$' \
    '^dm-device: SCN-A ' \
    '^dm-device: SCN-B ' \
    '^dm-device: SCN-F .*WAL 0 bytes$' \
    '^dm-device: alarm scheduled and cancelled$' \
    '^dm-device: SCN-D key change held and released; logcat holds no canary \([1-9][0-9]* canaries\)$'
  suite "$api" app-smoke 1 \
    '^dm-smoke: release library, one in-process Olm session, no transport$'
done

if [ "$fail" != 0 ]; then
  echo "[dm-emulator-check] FAILED" >&2
  exit 1
fi
echo "dm-equivalence: $cases cases per API level, identical, control detected"
echo "[dm-emulator-check] OK (API $*)"
