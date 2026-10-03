#!/usr/bin/env bash
# V-M20 (task snapshots): shows ViewerActivity's pattern (magenta/lime stripes, a cyan square) in
# four variants, sends the task to the background, and pulls whatever the system persisted under
# /data/system_ce/0/snapshots (adb root, userdebug emulator image). The pixels are then counted by
# scripts/count-pattern.ps1 (System.Drawing): a snapshot that holds media shows the pattern colours.
#   scripts/vm20-snapshots.sh <api>
# Never run while a probe instrumentation is running (it force-stops the probe app).
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
api="$1"
serial="${ADB_SERIAL:-emulator-5576}"
out="$here/results/api$api/vm20"
mkdir -p "$out"
a() { MSYS_NO_PATHCONV=1 adb -s "$serial" "$@"; }
a root >/dev/null 2>&1 || true
sleep 2
for variant in plain secure norecents secure_norecents; do
  secure=false; norecents=false
  case "$variant" in
    secure) secure=true ;;
    norecents) norecents=true ;;
    secure_norecents) secure=true; norecents=true ;;
  esac
  a shell am force-stop org.ghost.spike.media
  a shell "rm -f /data/system_ce/0/snapshots/*" || true
  a shell am start -W -n org.ghost.spike.media/.ViewerActivity --ez secure "$secure" --ez noRecents "$norecents" >/dev/null
  sleep 4
  a shell screencap -p /data/local/tmp/vm20-screen.png
  a pull /data/local/tmp/vm20-screen.png "$(cygpath -w "$out/$variant-screen.png")" >/dev/null
  a shell input keyevent KEYCODE_HOME
  sleep 5
  a shell input keyevent KEYCODE_APP_SWITCH
  sleep 4
  a shell screencap -p /data/local/tmp/vm20-recents.png
  a pull /data/local/tmp/vm20-recents.png "$(cygpath -w "$out/$variant-recents.png")" >/dev/null
  a shell input keyevent KEYCODE_HOME
  sleep 2
  {
    echo "== variant=$variant secure=$secure noRecents=$norecents"
    a shell "ls -la /data/system_ce/0/snapshots/" | tr -d '\r'
  } | tee "$out/$variant-listing.txt"
  for f in $(a shell "ls /data/system_ce/0/snapshots/" | tr -d '\r'); do
    a pull "/data/system_ce/0/snapshots/$f" "$(cygpath -w "$out/$variant-$f")" >/dev/null
  done
done
a shell am force-stop org.ghost.spike.media
echo "pulled into $out"
