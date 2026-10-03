#!/usr/bin/env bash
# V-M20 (OS-written crash residues): forces a native crash of a fresh `:mdec` instance whose
# registers point into a 512 KiB buffer filled with 'GHOST-S0-PLAINTEXT-CANARY-' (mode 1), then
#  - lists and pulls what appeared under /data/tombstones and /data/system/dropbox (adb root),
#  - takes an `adb bugreport` (no root needed) and searches every entry of the zip,
# and counts the canary (raw ASCII, and inside gzip members) in each file. The question is the
# design's L9-M8: do a crashed decoder's tombstone and dropbox entries hold plaintext of its
# request, and does a bug report carry them.
#   scripts/vm20-crash.sh <api> [mode]      (mode 1 native, 2 Java uncaught, 3 SIGSEGV by kill)
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
api="$1"; mode="${2:-1}"
serial="${ADB_SERIAL:-emulator-5576}"
work="$here/work/api$api/crash"; res="$here/results/api$api"
mkdir -p "$work" "$res"
a() { MSYS_NO_PATHCONV=1 adb -s "$serial" "$@"; }
a root >/dev/null 2>&1 || true
sleep 2
canary='GHOST-S0-PLAINTEXT-CANARY-'
count() { # file -> "raw=N gunzipped=M"
  local raw gz=0
  raw="$(grep -a -o "$canary" "$1" | wc -l || true)"
  if gzip -t "$1" 2>/dev/null; then gz="$(gzip -dc "$1" | grep -a -o "$canary" | wc -l || true)"; fi
  echo "raw=$raw gunzipped=$gz"
}
a shell "touch /data/local/tmp/vm20crash.marker"; sleep 1
TAG="mode$mode" bash "$here/scripts/probe.sh" "$api" crash -e mode "$mode"
sleep 8
{
  echo "# V-M20 (API $api, mode $mode): files under /data/tombstones and /data/system/dropbox newer than the crash"
  a shell "find /data/tombstones /data/system/dropbox -newer /data/local/tmp/vm20crash.marker -type f" | tr -d '\r' > "$work/new-mode$mode.txt" || true
  while read -r f; do
    [ -n "$f" ] || continue
    local_name="mode$mode-$(basename "$f")"
    a pull "$f" "$(cygpath -w "$work/$local_name")" >/dev/null
    echo "$f: $(wc -c < "$work/$local_name") B $(count "$work/$local_name")"
  done < "$work/new-mode$mode.txt"
  echo "# adb bugreport (taken after the crash, no root needed)"
  rm -f "$work/bugreport-mode$mode.zip"
  a bugreport "$(cygpath -w "$work/bugreport-mode$mode.zip")" >/dev/null 2>&1 || true
  if [ -s "$work/bugreport-mode$mode.zip" ]; then
    echo "bugreport: $(wc -c < "$work/bugreport-mode$mode.zip") B, $(unzip -Z1 "$work/bugreport-mode$mode.zip" | wc -l) entries"
    rm -rf "$work/br$mode"; mkdir -p "$work/br$mode"
    unzip -q -o "$work/bugreport-mode$mode.zip" -d "$work/br$mode"
    find "$work/br$mode" -type f | while read -r f; do
      c="$(count "$f")"
      case "$c" in "raw=0 gunzipped=0") ;; *) echo "  ${f#$work/br$mode/}: $(wc -c < "$f") B $c" ;; esac
    done
    echo "  entries naming tombstones or dropbox:"
    unzip -Z1 "$work/bugreport-mode$mode.zip" | grep -i -E 'tombstone|dropbox' | head -20 | sed 's/^/    /'
  else
    echo "bugreport: not produced"
  fi
} | tee "$res/crash-artefacts-mode$mode.txt"
