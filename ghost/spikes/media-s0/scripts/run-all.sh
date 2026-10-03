#!/usr/bin/env bash
# Runs the emulator checks of the S0 spike on one booted emulator, in the order the evidence
# document uses, and pulls what the host tools read. See README.md for the environment.
#   scripts/run-all.sh <api> [--sources generate|push] [--long] [--steps a,b,c] [--golden-from <dir>]
# --sources generate: build the video and image sources on this emulator (needs its encoders:
#                     API 35's AV1 encoder for the AVIF source); push: copy work/api35/src
#                     (identical inputs on every API level; the default).
# --long:             also the V-M22 bitrate runs over the 160-s sources (about an hour).
# --steps:            run only these steps, in this order (default: the list below):
#                     install env glinfo sources vm1 goldens seek images heiclog crash snapshots
#                     picker mtime preview metrics encoders bench mte analyse; also short, long
# --golden-from DIR:  push DIR/match720p30__DESIGN.mp4 into the app's out/ before `seek`, for an
#                     emulator whose GL stack cannot transcode (the API 29 image under the
#                     SwiftShader renderer: V-M1).
# Per-API probe arguments (environment): SEEK_ARGS (e.g. "-e player 0"), SEEK_PLAYER_ARGS (a second
# seek run, e.g. "-e readerFormat private"), PREVIEW_ARGS (e.g. "-e formats private"), REPS (long).
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
  steps="install,env,glinfo,sources,vm1,goldens,seek,images,heiclog,crash,snapshots,picker,mtime,preview,metrics,encoders,bench,mte,analyse"
  [ "$long" = 1 ] && steps="$steps,short,long"
fi
serial="${ADB_SERIAL:-emulator-5576}"
export ADB_SERIAL="$serial"
a() { MSYS_NO_PATHCONV=1 adb -s "$serial" "$@"; }
res="$here/results/api$api"; work="$here/work/api$api"
mkdir -p "$res" "$work/out" "$work/crash" "$work/metrics" "$work/jpg" "$work/canon"
tool="${MEDIATOOL:-${CARGO_TARGET_DIR:-}/release/mediatool.exe}"
pkgdata=/data/data/org.ghost.spike.media
probe() { bash "$here/scripts/probe.sh" "$api" "$@"; }
uid() { a shell "stat -c %u $pkgdata" | tr -d '\r'; }
# A root-side "what changed under /data" listing; an empty answer is a result, not an error.
# It refuses to report anything unless adbd really runs as root (an unprivileged `find` sees nothing
# under /data and would look like a clean result), and it marks the end of a complete listing.
rootfind() {
  if [ "$(a shell whoami | tr -d '\r')" != root ]; then echo "(adbd is not root: no search)" > "$2"; return; fi
  { a shell "find /data -xdev -newer /data/local/tmp/$1.marker -type f 2>/dev/null | grep -v '^/data/local/tmp'" | tr -d '\r'
    echo "(end of the list; searched as root)"; } > "$2" || true
}

a root >/dev/null 2>&1 || true; sleep 2
# `adb root` restarts adbd; wait until it answers as root.
for _ in 1 2 3 4 5 6 7 8 9 10; do [ "$(a shell whoami 2>/dev/null | tr -d '\r')" = root ] && break; sleep 2; done

step_install() {
  a install -r -t "$(cygpath -w "$here/android/probe/build/outputs/apk/debug/probe-debug.apk")" | tail -1
  probe clean >/dev/null
}
step_env() { probe env; }
# What the GL stack offers Media3's frame processor (V-M1 on API 29).
step_glinfo() {
  {
    echo "ro.opengles.version=$(a shell getprop ro.opengles.version | tr -d '\r')"
    echo "ro.hardware.egl=$(a shell getprop ro.hardware.egl | tr -d '\r')"
    echo "ro.kernel.qemu.gles=$(a shell getprop ro.kernel.qemu.gles | tr -d '\r')"
    a shell dumpsys SurfaceFlinger | tr -d '\r' | grep -i -E 'GLES|EGL|OpenGL' | head -8
  } | tee "$res/glinfo.txt"
}
step_sources() {
  if [ "$sources" = push ]; then
    a shell "mkdir -p /data/local/tmp/s0src"
    for f in "$here/work/api35/src/"*; do
      case "$(basename "$f")" in long160_*|t10_*) continue ;; esac
      a push "$(cygpath -w "$f")" /data/local/tmp/s0src/ >/dev/null
    done
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
  # shellcheck disable=SC2086
  probe seek ${SEEK_ARGS:-}
  # shellcheck disable=SC2086
  [ -z "${SEEK_PLAYER_ARGS:-}" ] || TAG=player probe seek $SEEK_PLAYER_ARGS
  a pull "$pkgdata/files/out/." "$(cygpath -w "$work/out")" >/dev/null
}
# V-M4, V-M5, V-M19, V-M6, V-M18; then the JPEGs to the host (marker walk, canonicaliser).
step_images() {
  probe orient
  probe iso
  probe isoTiming
  probe unguarded
  probe compress
  a pull "$pkgdata/files/out/." "$(cygpath -w "$work/jpg")" >/dev/null
  if [ -f "$tool" ]; then
    ( cd "$work/jpg" && "$tool" jpeg cmp_*.jpg strip_*.jpg ) > "$res/jpeg-markers.txt" 2>&1 || true
    for f in "$work/jpg"/strip_*.jpg; do "$tool" canon "$f" "$work/canon/$(basename "$f" .jpg).canon.jpg" >/dev/null 2>&1 || true; done
  fi
}
# V-M5: what the platform logs while an isolated instance tries HEIF and AVIF.
step_heiclog() {
  a logcat -c
  TAG=heif probe iso -e files photo.heic,photo.avif
  a logcat -d -v time | tr -d '\r' > "$work/heif-logcat.txt"
  grep -i -E 'avc: *denied|media\.player|media\.extractor|ServiceManager|HeifDecoder|heif|avif|isolated|Waiting for service|getService' "$work/heif-logcat.txt" \
    | grep -v -E 'SpikeRunner|probe iso' | head -60 > "$res/heif-logcat.txt" || true
}
# V-M20 tombstones, dropbox and bug report after forced :mdec crashes.
step_crash() {
  bash "$here/scripts/vm20-crash.sh" "$api" 1
  bash "$here/scripts/vm20-crash.sh" "$api" 2
}
# V-M20 task snapshots.
step_snapshots() {
  bash "$here/scripts/vm20-snapshots.sh" "$api"
  pwsh -NoProfile -File "$(cygpath -w "$here/scripts/count-pattern.ps1")" $(for f in "$res/vm20"/*.jpg "$res/vm20"/*.png; do cygpath -w "$f"; done) | tr -d '\r' > "$res/vm20/pattern-counts.txt" || true
}
# V-M21 / V-M11 picker residues.
step_picker() { bash "$here/scripts/vm21-picker.sh" "$api" "$here/work/api35/src/orient6.jpg"; }
# V-M16.
step_mtime() {
  probe mtime
  a shell "cd $pkgdata/no_backup/m && for f in \$(ls); do stat -c '%n ino=%i mtime=%y ctime=%z atime=%x' \$f; done" | tr -d '\r' > "$res/mtime-stat.txt"
}
# V-M23.
step_preview() {
  a shell "touch /data/local/tmp/vm23.marker"; sleep 1
  # shellcheck disable=SC2086
  probe preview ${PREVIEW_ARGS:-}
  rootfind vm23 "$res/preview-rootfind.txt"
}
# V-M13.
step_metrics() {
  a shell dumpsys media.metrics | tr -d '\r' > "$work/metrics/before.txt"
  TAG=diag0 probe play -e diag 0 -e file match720p30__DESIGN_tfdt_mfra.mp4
  a shell dumpsys media.metrics | tr -d '\r' > "$work/metrics/after-diag0.txt"
  TAG=diag1 probe play -e diag 1 -e file match720p30__DESIGN_tfdt_mfra.mp4
  a shell dumpsys media.metrics | tr -d '\r' > "$work/metrics/after-diag1.txt"
  for f in before after-diag0 after-diag1; do echo "$f: $(wc -l < "$work/metrics/$f.txt") lines, $(grep -c -E 'codec|playback|audio' "$work/metrics/$f.txt" || true) codec/playback/audio lines, $(grep -c -i -E 'LogSessionId|playbackId|sessionId' "$work/metrics/$f.txt" || true) session-id lines"; done > "$res/media-metrics-counts.txt"
}
# V-M12 (this API level's software encoders): a 10-s source made here, walked on the host.
step_encoders() {
  TAG=encoders probe sources -e set one -e name t10_plain.mp4
  a pull "$pkgdata/files/src/t10_plain.mp4" "$(cygpath -w "$work/out/encoder_t10_plain.mp4")" >/dev/null
  [ -f "$tool" ] && "$tool" mp4 "$work/out/encoder_t10_plain.mp4" > "$res/encoders-mp4.txt" 2>&1 || true
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
# V-M15 (manifest level): does the package manager accept a per-process memtagMode for :mdec?
step_mte() {
  a install -r -t "$(cygpath -w "$here/android/mteprobe/build/outputs/apk/debug/mteprobe-debug.apk")" | tail -1 | tee "$res/mte-install.txt"
  a shell dumpsys package org.ghost.spike.mte | tr -d '\r' | grep -i -E 'memtag|processes|:mdec|flags=|pkgFlags|privateFlags' | head -20 >> "$res/mte-install.txt" || true
  a uninstall org.ghost.spike.mte >/dev/null 2>&1 || true
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
  if [ -f "$tool" ]; then
    ( cd "$work/out" && for f in *.mp4; do "$tool" mp4 "$f"; done ) > "$res/mp4-report.txt" 2>&1 || true
  fi
}

IFS=, read -r -a list <<< "$steps"
for s in "${list[@]}"; do
  echo "== step $s ($(date +%H:%M:%S))"
  "step_$s"
done
echo "run-all $api done: $steps"
