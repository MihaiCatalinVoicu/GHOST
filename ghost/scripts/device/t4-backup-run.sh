#!/usr/bin/env bash
# T4's emulator run (design faza13-ux.md Appendix B.2): the local-transport backup path, both
# postures in one pass. A control application (the :backupctl module, relaxed backup rules)
# writes a canary file that MUST appear in its backup archive; GHOST (allowBackup="false") must
# be refused by the transport. A green run proves the pipeline carried data when GHOST's archive
# is absent - not that backups are empty because nothing ran.
#
#   t4-backup-run.sh <api> <control-apk>
#
# Requires a booted emulator, `adb root` (the local transport's store is read as root), and the
# control APK built (`./gradlew :backupctl:assembleDebug`). Exit 0 when the canary rode the
# backup and no org.ghost.app.gate archive exists; the device-transfer (is_device_transfer) path
# is a D2D flow and stays on the device checklist.
set -uo pipefail
api="${1:-}"
apk="${2:-}"
[ -n "$api" ] && [ -n "$apk" ] || { echo "usage: t4-backup-run.sh <api> <control-apk>" >&2; exit 2; }
adb="${GHOST_ADB:-adb}"
serial="${ANDROID_SERIAL:-}"

say() { echo "t4: $*" >&2; }

"$adb" root >/dev/null 2>&1 || { say "adb root refused - userdebug image required"; exit 1; }
# adb root restarts adbd; wait until the shell answers as root before touching the store.
"$adb" wait-for-device >/dev/null 2>&1
for _ in 1 2 3 4 5 6 7 8 9 10; do
  "$adb" shell id 2>/dev/null | grep -q uid=0 && break
  sleep 1
done
"$adb" install -r "$apk" >/dev/null || { say "control install failed"; exit 1; }
"$adb" shell am start -n org.ghost.backupctl/.BackupCtlActivity >/dev/null
sleep 2
"$adb" shell bmgr enable true >/dev/null

out_ctl=$("$adb" shell bmgr backupnow org.ghost.backupctl 2>&1 | tr -d '\r')
out_ghost=$("$adb" shell bmgr backupnow org.ghost.app.gate 2>&1 | tr -d '\r')
say "control: $(printf '%s\n' "$out_ctl" | tail -1)"
say "ghost:   $(printf '%s\n' "$out_ghost" | tail -2 | head -1)"

archive=/data/data/com.android.localtransport/files/1/_full/org.ghost.backupctl
rc=0
if printf '%s' "$out_ghost" | grep -q 'Backup is not allowed'; then
  say "GHOST refused by the transport (allowBackup=false respected)"
else
  say "GHOST was NOT refused - allowBackup=false is not holding"; rc=1
fi
# Capture before grep: pipefail plus grep -q would turn adb's SIGPIPE into a failure.
entries=$("$adb" shell "tar -tf $archive" 2>/dev/null | tr -d '' || true)
if printf '%s
' "$entries" | grep -q 't4_canary.txt'; then
  say "the control's canary rode the backup (pipeline carried data)"
else
  say "canary missing from the control archive - the run proves nothing"; rc=1
fi
if "$adb" shell "ls /data/data/com.android.localtransport/files/1/_full/" 2>/dev/null | tr -d '\r' | grep -qx 'org.ghost.app.gate'; then
  say "a GHOST archive exists - allowBackup=false is not holding"; rc=1
else
  say "no GHOST archive in the transport store"
fi
exit "$rc"
