#!/usr/bin/env bash
# Runs every emulator check of the S0 spike on one booted emulator, in the order the evidence
# document uses, and pulls what the host tools read. See README.md for the environment.
#   scripts/run-all.sh <api> [--sources generate|push] [--long] [--steps a,b,c] [--golden-from <dir>]
# --sources generate: build the video and image sources on this emulator (needs its encoders:
#                     API 35's AV1 encoder for the AVIF source); push: copy results/../work/api35/src
#                     (identical inputs on every API level; the default).
# --long:             also the V-M22 bitrate runs over the 160-s sources (about an hour).
# --steps:            run only these steps, in this order (default: all):
#                     install env sources vm1 goldens seek images crash mtime preview metrics bench
#                     short long analyse
# --golden-from DIR:  push DIR/match720p30__DESIGN.mp4 into the app's out/ before `seek`, for an
#                     emulator whose GL stack cannot transcode (the API 29 image under SwiftShader
#                     exposes only OpenGL ES 2.0 and Media3's frame processor needs ES 3).
# Every step's report goes to results/api<api>/; pulled media to work/api<api>/ (git-ignored).
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
api="$1"; shift
sources=push; long=0; steps=""; golden=""
while [ $# -gt 0 ]; do
  case "$1" in
    --sources) sources="$2"; shift 2 ;;
    --long) long=1; shift ;;
    --steps) steps="$2"; shift 2 ;;
    --golden-from) golden="$2"; shift 2 ;;
    *) echo "unknown $1"; exit 2 ;;
  esac
done
if [ -z "$steps" ]; then
  steps="install,env,sources,vm1,goldens,seek,images,crash,mtime,preview,metrics,bench,analyse"
  [ "$long" = 1 ] && steps="$steps,long"
fi
serial="${ADB_SERIAL:-emulator-5576}"
export ADB_SERIAL="$serial"
a() { MSYS_NO_PATHCONV=1 adb -s "$serial" "$@"; }
res="$here/results/api$api"; work="$here/work/api$api"
mkdir -p "$res" "$work/out" "$work/crash" "$work/metrics"
tool="${MEDIATOOL:-$CARGO_TARGET_DIR/release/mediatool.exe}"
pkgdata=/data/data/org.ghost.spike.media
probe() { bash "$here/scripts/probe.sh" "$api" "$@"; }
uid() { a shell "stat -c %u $pkgdata" | tr -d '\r'; }
# A root-side "what changed under /data" listing; an empty answer is a result, not an error.
rootfind() { a shell "find /data -xdev -newer /data/local/tmp/$1.marker -type f 2>/dev/null | grep -v '^/data/local/tmp'" | tr -d '\r' > "$2" || true; }

a root >/dev/null 2>&1 || true; sleep 2

step_install() {
  a install -r -t "$(cygpath -w "$here/android/probe/build/outputs/apk/debug/probe-debug.apk")" | tail -1
  probe clean >/dev/null
}
step_env() { probe env; }
step_sources() {
  if [ "$sources" = push ]; then
    a shell "mkdir -p /data/local/tmp/s0src"
    for f in "$here/work/api35/src/"*; do a push "$(cygpath -w "$f")" /data/local/tmp/s0src/ >/dev/null; done
    a shell "mkdir -p $pkgdata/files/src && cp /data/local/tmp/s0src/* $pkgdata/files/src/ && chown -R $(uid):$(uid) $pkgdata/files && restorecon -R $pkgdata/files"
    a shell "ls -la $pkgdata/files/src" | tr -d '\r' > "$res/sources-pushed.txt"
  else
    probe sources -e set video
    TAG=stills probe sources -e set stills
    TAG=big probe sources -e set big
  fi
}
# V-M1: 24 transcodes observed (FileObserver + inventory in the app, find -newer as root).
step_vm1() {
  a shell "touch /data/local/tmp/vm1.marker"; sleep 1
  TAG=vm1-observe probe transcode -e set basic -e observe 1
  rootfind vm1 "$res/transcode-vm1-observe-rootfind.txt"
}
# Goldens (saved outside any observation) and the corrections under test.
step_goldens() {
  TAG=save probe transcode -e set basic -e save 1
  TAG=fixes probe transcode -e set fixes -e save 1
  a pull "$pkgdata/files/out/." "$(cygpath -w "$work/out")" >/dev/null
}
# V-M2 over the golden of this emulator, or over a pushed one (--golden-from).
step_seek() {
  if [ -n "$golden" ]; then
    a push "$(cygpath -w "$golden/match720p30__DESIGN.mp4")" /data/local/tmp/golden.mp4 >/dev/null
    a shell "mkdir -p $pkgdata/files/out && cp /data/local/tmp/golden.mp4 $pkgdata/files/out/match720p30__DESIGN.mp4 && chown -R $(uid):$(uid) $pkgdata/files/out && restorecon -R $pkgdata/files/out"
    echo "golden pushed from $golden" > "$res/seek-golden-source.txt"
  fi
  probe seek
  a pull "$pkgdata/files/out/." "$(cygpath -w "$work/out")" >/dev/null
}
# V-M4, V-M5, V-M19, V-M6, V-M18.
step_images() {
  probe orient
  probe iso
  probe isoTiming
  probe unguarded
  probe compress
  a pull "$pkgdata/files/out/." "$(cygpath -w "$work/out")" >/dev/null
}
# V-M20 tombstones and dropbox: native crash with registers into plaintext, Java crash.
step_crash() {
  for m in 1 2; do
    a shell "touch /data/local/tmp/crash$m.marker"; sleep 1
    TAG=mode$m probe crash -e mode $m
    sleep 6
    a shell "find /data/tombstones /data/system/dropbox -newer /data/local/tmp/crash$m.marker -type f" | tr -d '\r' > "$work/crash/new-mode$m.txt" || true
    while read -r f; do [ -n "$f" ] && a pull "$f" "$(cygpath -w "$work/crash/mode$m-$(basename "$f")")" >/dev/null; done < "$work/crash/new-mode$m.txt"
    cp "$work/crash/new-mode$m.txt" "$res/crash-mode$m-files.txt"
  done
}
# V-M16.
step_mtime() {
  probe mtime
  a shell "cd $pkgdata/no_backup/m && for f in \$(ls); do stat -c '%n ino=%i mtime=%y ctime=%z atime=%x' \$f; done" | tr -d '\r' > "$res/mtime-stat.txt"
}
# V-M23.
step_preview() {
  a shell "touch /data/local/tmp/vm23.marker"; sleep 1
  probe preview
  rootfind vm23 "$res/preview-rootfind.txt"
}
# V-M13.
step_metrics() {
  a shell dumpsys media.metrics | tr -d '\r' > "$work/metrics/before.txt"
  TAG=diag0 probe play -e diag 0 -e file match720p30__DESIGN_tfdt_mfra.mp4
  a shell dumpsys media.metrics | tr -d '\r' > "$work/metrics/after-diag0.txt"
  TAG=diag1 probe play -e diag 1 -e file match720p30__DESIGN_tfdt_mfra.mp4
  a shell dumpsys media.metrics | tr -d '\r' > "$work/metrics/after-diag1.txt"
  for f in before after-diag0 after-diag1; do grep -cE 'org.ghost.spike.media|codec|playback' "$work/metrics/$f.txt" | sed "s/^/$f: matching lines /" ; done > "$res/media-metrics-counts.txt" || true
  grep -nE 'org.ghost.spike.media' "$work/metrics/after-diag1.txt" | head -40 >> "$res/media-metrics-counts.txt" || true
}
# V-M9 (emulator half): JCA in the app; the Rust sealer as a native binary.
step_bench() {
  probe bench
  local native="${NATIVE_MEDIATOOL:-}"
  if [ -n "$native" ]; then
    a push "$(cygpath -w "$native")" /data/local/tmp/mediatool >/dev/null
    a shell "chmod 755 /data/local/tmp/mediatool; for i in 1 2 3; do /data/local/tmp/mediatool bench; /data/local/tmp/mediatool bench-stream; done" | tr -d '\r' > "$res/native-bench.txt"
  fi
}
# V-M22: the 10-s sources of every complexity, CBR and VBR (short), and the 160-s sources (long).
step_short() {
  TAG=short probe sources -e set short
  TAG=short probe transcode -e set short
}
step_long() {
  TAG=long probe sources -e set long
  TAG=long probe transcode -e set long -e reps "${REPS:-5}"
  TAG=longvbr probe transcode -e set longvbr
}
# Host analysis of what was pulled.
step_analyse() {
  if [ -x "$tool" ] || [ -f "$tool" ]; then
    ( cd "$work/out" && for f in *.mp4; do "$tool" mp4 "$f"; done ) > "$res/mp4-report.txt" 2>&1 || true
    ( cd "$work/out" && "$tool" jpeg cmp_*.jpg strip_*.jpg ) > "$res/jpeg-markers.txt" 2>&1 || true
  fi
}

IFS=, read -r -a list <<< "$steps"
for s in "${list[@]}"; do
  echo "== step $s ($(date +%H:%M:%S))"
  "step_$s"
done
echo "run-all $api done: $steps"
