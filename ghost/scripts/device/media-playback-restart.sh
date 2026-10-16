#!/usr/bin/env bash
# §15.8 item 3's host-driven two-part restart run (Phase 11 design faza11-media.md §15.8
# item 3; slice S7): part one (an instrumentation method) seals the golden, opens a reader,
# "plays" to a recorded position and writes its state to the test app's files directory; the
# host kills the app's process (`adb shell am force-stop`); part two (a second
# instrumentation run, a new process) reopens the object from the persisted key_env and the
# content-addressed ciphertext files and serves the recorded position's bytes. Instrumentation
# dies with the process, which is why the run is host-driven.
#
#   media-playback-restart.sh <out-dir>
#
# Writes <out-dir>/part1.txt, kill.txt and part2.txt (the complete `am instrument` outputs).
# The check is the judge: it also requires the `media-restart:` report lines. Exit 0 when both
# parts finished RESULT_OK and the kill landed between them; 1 otherwise; 2 on usage error.
set -uo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
out="${1:-}"
[ -n "$out" ] || { echo "usage: media-playback-restart.sh <out-dir>" >&2; exit 2; }
adb="${GHOST_ADB:-adb}"
android="${GHOST_ANDROID:-$DIR/../../android}"
pkg="org.ghost.messaging.test"
runner="org.ghost.messaging.device.MessagingDeviceRunner"
apk="$android/messaging/build/outputs/apk/androidTest/debug/messaging-debug-androidTest.apk"
rc=0

mkdir -p "$out"
"$adb" wait-for-device
if [ ! -f "$apk" ]; then
  echo "media-restart: $apk was not built" >&2
  exit 1
fi
"$adb" install -r -t "$apk" > /dev/null || { echo "media-restart: install failed" >&2; exit 1; }

# Part one: seal, open, record.
"$adb" shell am instrument -r -w -e class org.ghost.messaging.media.MediaPlaybackRestartTest#partOneRecordsState \
  "$pkg/$runner" > "$out/part1.txt" 2>&1
tr -d '\r' < "$out/part1.txt" | grep -E '^(media-restart|device tests:|INSTRUMENTATION_CODE:)' | sed 's/^/media-restart: part1: /'
if ! tr -d '\r' < "$out/part1.txt" | grep -qx 'INSTRUMENTATION_CODE: -1'; then
  echo "media-restart: part one did not finish RESULT_OK" >&2
  rc=1
fi

# The host kills the process between the parts.
"$adb" shell am force-stop "$pkg"
echo "force-stopped $pkg between the parts" > "$out/kill.txt"

# Part two: a new process resumes from the recorded state.
"$adb" shell am instrument -r -w -e class org.ghost.messaging.media.MediaPlaybackRestartTest#partTwoResumesFromTheRecordedPosition \
  "$pkg/$runner" > "$out/part2.txt" 2>&1
tr -d '\r' < "$out/part2.txt" | grep -E '^(media-restart|device tests:|INSTRUMENTATION_CODE:)' | sed 's/^/media-restart: part2: /'
if ! tr -d '\r' < "$out/part2.txt" | grep -qx 'INSTRUMENTATION_CODE: -1'; then
  echo "media-restart: part two did not finish RESULT_OK" >&2
  rc=1
fi
if ! tr -d '\r' < "$out/part2.txt" | grep -q '^media-restart: part two resumed'; then
  echo "media-restart: part two did not report the resume" >&2
  rc=1
fi
exit $rc
