#!/usr/bin/env bash
# V-M21 / V-M11: what the system picker records about a pick, and whether reading the picked
# stream writes anything into the app's directories.
#   scripts/vm21-picker.sh <api> <image-on-host>
# 1. pushes the image to /sdcard/Pictures under a fresh name (ghost_s0_pick_<time>.jpg, touched so
#    that it is the newest picture) and waits for MediaProvider's row;
# 2. hashes, as root, every file of the picker-side packages (MediaProvider module, legacy
#    MediaProvider, DocumentsUI, the photo picker's own package where it exists) and of the
#    system-side records a pick can touch (URI grants, recent tasks, usage stats), before;
# 3. starts the `pick` probe (it launches ACTION_PICK_IMAGES on API 33+, ACTION_OPEN_DOCUMENT on
#    API 29, and reads the returned stream under FileObserver), then drives the picker UI with
#    uiautomator: it taps the node that names the pushed file, else a photo thumbnail, else the
#    way to the picture (the "Pictures" bucket, the "Images" root, the roots drawer);
# 4. hashes again, lists the changed files, pulls every changed file under 4 MiB into
#    results/api<api>/vm21/changed/ (SQLite databases together with their -wal/-shm), and dumps
#    every table row of the changed databases that names the probe package or the picked file;
# 5. lists every file of shared storage (/data/media/0) written during the pick (thumbnails the
#    system caches there) and pulls those under 4 MiB into results/api<api>/vm21/shared/.
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
api="$1"; img="$2"
serial="${ADB_SERIAL:-emulator-5576}"
out="$here/results/api$api/vm21"
mkdir -p "$out/changed" "$out/shared"
a() { MSYS_NO_PATHCONV=1 adb -s "$serial" "$@"; }
a root >/dev/null 2>&1 || true
sleep 2
pkgs="/data/data/com.android.providers.media.module /data/user_de/0/com.android.providers.media.module /data/data/com.android.providers.media /data/user_de/0/com.android.providers.media /data/data/com.android.documentsui /data/user_de/0/com.android.documentsui /data/data/com.google.android.providers.media.module /data/data/com.android.photopicker /data/user_de/0/com.android.photopicker"
system="/data/system/urigrants.xml /data/system_ce/0/recent_tasks /data/system_ce/0/recent_images /data/system/usagestats /data/system_ce/0/usagestats /data/system_de/0/usagestats"
# The trailing `true`: a missing directory must not make the remote shell (and so, under
# pipefail, this script) fail.
snap() { a shell "for d in $pkgs $system; do [ -e \$d ] && find \$d -type f -exec md5sum {} \\; ; done; true" | tr -d '\r' | sort -k2; }
# A DocumentsUI instance left over from an earlier run stays in the probe's task after the probe
# dies; the probe's NEW_TASK start then only brings that stale task to the front, and a pick in it
# returns to a dead requester (seen on API 29). DocumentsUI is stopped first (not MediaProvider).
for p in com.android.documentsui com.google.android.documentsui; do a shell am force-stop "$p" >/dev/null 2>&1 || true; done
name="ghost_s0_pick_$(date +%H%M%S).jpg"
a push "$(cygpath -w "$img")" "/sdcard/Pictures/$name" >/dev/null
a shell touch "/sdcard/Pictures/$name"
a shell am broadcast -a android.intent.action.MEDIA_SCANNER_SCAN_FILE -d "file:///sdcard/Pictures/$name" >/dev/null 2>&1 || true
sleep 5
a shell content query --uri content://media/external/images/media --projection _id:_display_name:owner_package_name | tr -d '\r' | grep "$name" | tee "$out/mediastore-row.txt" || true
snap > "$out/before.md5"
a shell "touch /data/local/tmp/vm21.marker"; sleep 1
( bash "$here/scripts/probe.sh" "$api" pick -e waitS 900 > "$out/probe-run.txt" 2>&1 ) &
probe_pid=$!
tapped=0
for attempt in $(seq 1 40); do
  sleep 4
  a shell uiautomator dump /data/local/tmp/ui.xml >/dev/null 2>&1 || continue
  a pull /data/local/tmp/ui.xml "$(cygpath -w "$out/ui-$attempt.xml")" >/dev/null
  # The node naming the pushed file; else a photo thumbnail; failing that (DocumentsUI on API 29
  # can open on an empty "Recent" root), the way to it: the "Pictures" bucket, the "Images" root,
  # opening the roots drawer first.
  bounds=""
  for pat in "text=\"$name\"" 'content-desc="Photo|content-desc="Media item|icon_thumbnail|thumbnail' 'text="Pictures"' 'text="Images"' 'content-desc="Show roots"'; do
    bounds="$(tr '>' '\n' < "$out/ui-$attempt.xml" | grep -E "$pat" | grep -o 'bounds="[^"]*"' | head -1 || true)"
    [ -n "$bounds" ] && break
  done
  if [ -n "$bounds" ]; then
    # A screenshot only of the screens acted on (each is ~0.5 MB).
    a shell screencap -p /data/local/tmp/pick.png; a pull /data/local/tmp/pick.png "$(cygpath -w "$out/ui-$attempt.png")" >/dev/null
    read -r x1 y1 x2 y2 < <(echo "$bounds" | sed -E 's/bounds="\[([0-9]+),([0-9]+)\]\[([0-9]+),([0-9]+)\]"/\1 \2 \3 \4/')
    a shell input tap $(( (x1 + x2) / 2 )) $(( (y1 + y2) / 2 ))
    echo "tap attempt $attempt at $bounds (pattern $pat)" | tee -a "$out/taps.txt"
    tapped=$((tapped + 1))
    sleep 3
    # Some pickers need a confirming "Done"/"Select" (multi-select UIs).
    a shell uiautomator dump /data/local/tmp/ui2.xml >/dev/null 2>&1 || true
    a pull /data/local/tmp/ui2.xml "$(cygpath -w "$out/ui-$attempt-after.xml")" >/dev/null 2>&1 || true
    if ! kill -0 "$probe_pid" 2>/dev/null; then break; fi
  fi
done
wait "$probe_pid" || true
cp "$here/results/api$api/pick.txt" "$out/pick.txt" 2>/dev/null || true
# The bytes the picker handed over (written by the probe after its observation ended), against the
# pushed file: identical, or changed by the picker (e.g. location redaction).
if a pull /data/data/org.ghost.spike.media/files/picked.bin "$(cygpath -w "$out/picked.bin")" >/dev/null 2>&1; then
  { echo "pushed: $(wc -c < "$img") B sha256=$(sha256sum "$img" | cut -c1-64)"
    echo "picked: $(wc -c < "$out/picked.bin") B sha256=$(sha256sum "$out/picked.bin" | cut -c1-64)"
    echo "differing bytes (offset, pushed, picked; octal):"
    cmp -l "$img" "$out/picked.bin" | head -64 || true
  } > "$out/picked-vs-pushed.txt"
  cat "$out/picked-vs-pushed.txt"
fi
sleep 3
snap > "$out/after.md5"
diff "$out/before.md5" "$out/after.md5" > "$out/changed.txt" || true
echo "== changed files"; cat "$out/changed.txt"
# Pull every changed or new file (and a database's companions) that is not too large.
: > "$out/pulled.txt"
for f in $(grep -E '^>' "$out/changed.txt" | awk '{print $3}' | sort -u); do
  for g in "$f" "${f%-wal}" "${f%-shm}" "${f%-wal}-wal" "${f%-shm}-shm" "${f%-wal}-shm" "${f%-shm}-wal"; do
    size="$(a shell "stat -c %s '$g' 2>/dev/null" | tr -d '\r' || true)"
    [ -n "$size" ] || continue
    [ "$size" -le 4194304 ] || { echo "skip $g ($size B)" >> "$out/pulled.txt"; continue; }
    local_name="$(echo "$g" | sed 's#^/##; s#/#__#g')"
    [ -e "$out/changed/$local_name" ] && continue
    a pull "$g" "$(cygpath -w "$out/changed/$local_name")" >/dev/null && echo "$g $size B" >> "$out/pulled.txt"
  done
done
cat "$out/pulled.txt"
# Rows of the changed databases (WAL included: sqlite3 on the device reads the live files).
: > "$out/db-dump.txt"
for db in $(grep -E '^>' "$out/changed.txt" | awk '{print $3}' | sed -E 's/-(wal|shm|journal)$//' | grep -E '\.db$' | sort -u); do
  echo "== $db" >> "$out/db-dump.txt"
  for t in $(a shell "sqlite3 $db '.tables'" | tr -d '\r'); do
    a shell "sqlite3 $db \"SELECT '$t', * FROM $t\"" | tr -d '\r' | grep -E 'org\.ghost|ghost_s0_pick' >> "$out/db-dump.txt" || true
  done
done
cat "$out/db-dump.txt"
# Shared storage written during the pick (the pushed picture itself is older than the marker).
a shell "find /data/media/0 -newer /data/local/tmp/vm21.marker -type f -exec stat -c '%n %s B mtime=%y' {} \\; 2>/dev/null; true" | tr -d '\r' > "$out/shared-written.txt"
echo "== shared storage written during the pick"; cat "$out/shared-written.txt"
while read -r f _; do
  [ -n "$f" ] || continue
  size="$(a shell "stat -c %s '$f'" | tr -d '\r')"
  [ "$size" -le 4194304 ] || continue
  a pull "$f" "$(cygpath -w "$out/shared/$(echo "${f#/data/media/0/}" | sed 's#/#__#g')")" >/dev/null || true
done < "$out/shared-written.txt"
echo "done: $out"
