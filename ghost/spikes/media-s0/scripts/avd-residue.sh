#!/usr/bin/env bash
# Review H5 (2026-10-04): what the S0 sessions left in the shared AVDs (ghost-dm-api29/-api35, which
# the product's device suites also use). Default: list it, as root, into results/api<api>/.
#   scripts/avd-residue.sh <api> [--clean]
# --clean (only on a writable boot, i.e. without -read-only): removes exactly what S0 created, each
# item identified by S0's package names (org.ghost.spike.*), S0's file names (ghost_s0_*, s0src,
# the vm*.marker and crash*.marker files, the vm20-*.png captures, golden.mp4, mediatool) or S0's canaries (GHOST-S0-PLAINTEXT-CANARY, GHOSTCANARYS0), and
# lists again afterwards. Nothing else on the image is touched.
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
api="$1"; mode="${2:-list}"
serial="${ADB_SERIAL:-emulator-5576}"
a() { MSYS_NO_PATHCONV=1 adb -s "$serial" "$@"; }
a root >/dev/null 2>&1 || true
for _ in 1 2 3 4 5 6 7 8 9 10; do [ "$(a shell whoami 2>/dev/null | tr -d '\r')" = root ] && break; sleep 2; done
out="$here/results/api$api/avd-residue-$( [ "$mode" = --clean ] && echo after-clean || echo before ).txt"
mkdir -p "$(dirname "$out")"
sh_() { a shell "$1" | tr -d '\r'; }

listing() {
  echo "# $(date -u +%Y-%m-%dT%H:%M:%SZ) emulator-$api $(sh_ 'getprop ro.build.fingerprint') uptime=$(sh_ 'cat /proc/uptime')"
  echo "## packages (S0 and the product's suites)"
  sh_ "pm list packages | grep -E 'ghost' | sort; true"
  for p in org.ghost.spike.media org.ghost.spike.mte; do
    sh_ "dumpsys package $p | grep -E 'firstInstallTime|lastUpdateTime' | head -2; true" | sed "s|^|$p |"
  done
  echo "## /data/tombstones (S0 = names org.ghost.spike or carries the S0 canary)"
  sh_ "for f in /data/tombstones/*; do [ -f \"\$f\" ] || continue; s0=no; grep -q -a -E 'org.ghost.spike|GHOST-S0' \"\$f\" && s0=yes; stat -c \"%n %s B mode=%a mtime=%y\" \"\$f\" | tr '\n' ' '; echo \"s0=\$s0\"; done; true"
  echo "## /data/system/dropbox entries that name org.ghost.spike or carry an S0 canary"
  sh_ "for f in /data/system/dropbox/*; do [ -f \"\$f\" ] || continue; case \"\$f\" in *.gz) zcat \"\$f\" 2>/dev/null | grep -q -a -E 'org.ghost.spike|GHOST-S0|GHOSTCANARYS0' || continue ;; *) grep -q -a -E 'org.ghost.spike|GHOST-S0|GHOSTCANARYS0' \"\$f\" || continue ;; esac; stat -c '%n %s B mode=%a mtime=%y' \"\$f\"; done; true"
  echo "## shared storage: pictures, thumbnails, transform placeholders"
  sh_ "find /data/media/0/Pictures /data/media/0/DCIM /data/media/0/.transforms -type f 2>/dev/null | while read f; do stat -c '%n %s B mode=%a owner=%U:%G mtime=%y' \"\$f\"; done; true"
  echo "## MediaStore image rows"
  sh_ "content query --uri content://media/external/images/media --projection _id:_display_name:_data:owner_package_name:date_added 2>/dev/null; true"
  echo "## MediaProvider caches (photo picker's Glide cache) and picker database"
  sh_ "for d in /data/data/com.android.providers.media.module/cache /data/data/com.android.providers.media/cache; do [ -d \$d ] && find \$d -type f | while read f; do stat -c '%n %s B mode=%a mtime=%y' \"\$f\"; done; done; true"
  echo "## DocumentsUI records (API 29)"
  if [ -n "$(sh_ 'command -v sqlite3; true')" ]; then
    sh_ "[ -f /data/data/com.android.documentsui/databases/lastAccess.db ] && sqlite3 /data/data/com.android.documentsui/databases/lastAccess.db 'select package_name, timestamp, external from lastAccessed;'; true"
    sh_ "[ -f /data/data/com.android.documentsui/databases/pickCountRecord.db ] && sqlite3 /data/data/com.android.documentsui/databases/pickCountRecord.db 'select * from pickCountRecordTable;'; true"
  else
    echo "(no sqlite3 on this image)"
  fi
  echo "## usage stats files naming org.ghost.spike"
  sh_ "grep -r -l -a 'org.ghost.spike' /data/system/usagestats /data/system_ce/0/usagestats 2>/dev/null | head -20; true"
  echo "## /data/local/tmp"
  sh_ "ls -la /data/local/tmp; true"
}

clean() {
  echo "## removing what S0 created"
  for p in org.ghost.spike.media org.ghost.spike.mte; do echo "uninstall $p: $(a uninstall "$p" 2>&1 | tr -d '\r')"; done
  sh_ "for f in /data/tombstones/*; do [ -f \"\$f\" ] || continue; if grep -q -a -E 'org.ghost.spike|GHOST-S0' \"\$f\"; then rm -f \"\$f\" && echo removed \$f; fi; done; true"
  sh_ "for f in /data/system/dropbox/*; do [ -f \"\$f\" ] || continue; case \"\$f\" in *.gz) zcat \"\$f\" 2>/dev/null | grep -q -a -E 'org.ghost.spike|GHOST-S0|GHOSTCANARYS0' || continue ;; *) grep -q -a -E 'org.ghost.spike|GHOST-S0|GHOSTCANARYS0' \"\$f\" || continue ;; esac; rm -f \"\$f\" && echo removed \$f; done; true"
  # S0's pushed pictures, through MediaProvider (so the rows, thumbnails and placeholders go too),
  # then any thumbnail or placeholder file still left for the removed ids.
  ids="$(sh_ "content query --uri content://media/external/images/media --projection _id:_data 2>/dev/null | grep -E 'ghost_s0_|/orient[0-9]\.jpg' | sed -E 's/.*_id=([0-9]+),.*/\1/'; true")"
  for id in $ids; do
    echo "delete MediaStore image $id: $(sh_ "su 2000 content delete --uri content://media/external/images/media/$id 2>&1; true")"
    sh_ "rm -f /data/media/0/Pictures/.thumbnails/$id.jpg /data/media/0/.transforms/synthetic/picker/0/com.android.providers.media.photopicker/media/$id.jpg; true"
  done
  sh_ "rm -f /data/media/0/Pictures/ghost_s0_* ; true"
  # The photo picker's Glide disk cache: a cache MediaProvider rebuilds, whose only entry on these
  # AVDs is S0's thumbnail (the before-listing shows it); removed whole, since its entry names are
  # hashes that cannot be tied to a picture.
  sh_ "rm -rf /data/data/com.android.providers.media.module/cache/image_manager_disk_cache; true"
  if [ -n "$(sh_ 'command -v sqlite3; true')" ]; then
    sh_ "[ -f /data/data/com.android.documentsui/databases/lastAccess.db ] && sqlite3 /data/data/com.android.documentsui/databases/lastAccess.db \"delete from lastAccessed where package_name like 'org.ghost.spike%';\"; true"
  fi
  sh_ "cd /data/local/tmp && rm -rf s0src s0-rootfind.txt s0-rootfind.err golden.mp4 mediatool ui.xml ui2.xml pick.png vm1.marker vm23.marker vm1fix.marker vm23fix.marker crash1.marker crash2.marker crash3.marker vm20-recents.png vm20-screen.png; true"
  sh_ "sync; true"
}

if [ "$mode" = --clean ]; then
  { clean; echo; listing; } > "$out" 2>&1
else
  listing > "$out" 2>&1
fi
echo "== $out ($(wc -l < "$out") lines)"
