#!/usr/bin/env bash
# Runs one probe of the S0 spike on the emulator and stores its report.
#   scripts/probe.sh <api> <probe> [-e key value ...]
# Output: results/api<api>/<probe>[-<TAG>].txt (the instrumentation result stream). Set TAG to
# distinguish several runs of one probe. ADB_SERIAL defaults to emulator-5576.
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
api="$1"; probe="$2"; shift 2
serial="${ADB_SERIAL:-emulator-5576}"
out="$here/results/api$api"
mkdir -p "$out"
name="$probe${TAG:+-$TAG}"
adb -s "$serial" shell am instrument -w -r -e probe "$probe" "$@" org.ghost.spike.media/.SpikeRunner \
  | tr -d '\r' \
  | awk '/^INSTRUMENTATION_RESULT: stream=/{f=1; sub(/^INSTRUMENTATION_RESULT: stream=/,""); print; next} /^INSTRUMENTATION_(CODE|RESULT)/{f=0} f{print}' \
  > "$out/$name.txt"
echo "== $out/$name.txt ($(wc -l < "$out/$name.txt") lines)"
grep -E "^probe " "$out/$name.txt" || echo "(no probe verdict line: instrumentation crashed?)"
