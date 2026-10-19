#!/usr/bin/env bash
# T20's wipe half and T57's emulator floor (design faza13-ux.md Appendix B.2; WipeController's
# CS-U1): plant a database-shaped file, restart the app, and its own resumption path (W4-W6)
# must delete it before any wiring. Plus the scheduler dumps: after a plain launch, no
# jobscheduler / alarm / notification entry may name the package.
#
#   t20-wipe-run.sh <api>
#
# Requires a booted emulator and `adb root` (the store is planted and read as the app uid via
# run-as). Exit 0 when the planted file is gone at relaunch and the dumps name no GHOST entry.
set -uo pipefail
api="${1:-}"
[ -n "$api" ] || { echo "usage: t20-wipe-run.sh <api>" >&2; exit 2; }
adb="${GHOST_ADB:-adb}"
pkg=org.ghost.app.gate

say() { echo "t20: $*" >&2; }

"$adb" root >/dev/null 2>&1 || { say "adb root refused - userdebug image required"; exit 1; }
"$adb" wait-for-device >/dev/null 2>&1
for _ in 1 2 3 4 5 6 7 8 9 10; do
  "$adb" shell id 2>/dev/null | grep -q uid=0 && break
  sleep 1
done

rc=0
# Baseline first: a fresh install has no database-key envelope - that is the predicate CS-U1's
# resumption waits for (an envelope present means a real database, not crash residue).
"$adb" shell pm clear "$pkg" >/dev/null 2>&1
sleep 3

# Plant a database-shaped file with a canary (as root - run-as races the just-cleared package).
"$adb" shell "mkdir -p /data/user/0/$pkg/databases && echo T20-RESUME-CANARY > /data/user/0/$pkg/databases/ghost.db && echo wal > /data/user/0/$pkg/databases/ghost.db-wal" \
  || { say "planting the canary failed"; exit 1; }
say "planted databases/ghost.db with a canary"

# Restart the app: onCreate's resumption (CS-U1) runs W4-W6 before any wiring.
"$adb" shell am force-stop "$pkg"
"$adb" shell am start -n "$pkg/org.ghost.app.MainActivity" >/dev/null
sleep 4

remains=$("$adb" shell "ls /data/user/0/$pkg/databases/ 2>/dev/null" | tr -d '\r')
if printf '%s\n' "$remains" | grep -q 'ghost\.db'; then
  say "ghost.db survived the relaunch - resumption (W5) did not run"; rc=1
else
  say "the planted ghost.db is gone - CS-U1's resumption deleted it before wiring"
fi

# T20's dump floor: no jobscheduler entry, no notification. The one inexact alarm is by
# design (Faza 9, ADR-32: the messaging layer's single inexact alarm without extras), reported.
# The jobscheduler dump names every installed package in its uid mapping; the check is for
# OWNED jobs - the "#u0a<uid>" headers.
uid=$("$adb" shell "dumpsys package $pkg | grep userId=" | tr -d '\r' | sed 's/.*userId=//')
uidhex=$(printf '%x' "$uid" 2>/dev/null || echo "")
if [ -n "$uidhex" ] && "$adb" shell "dumpsys jobscheduler" 2>/dev/null | tr -d '\r' | grep -qE "^  #u0a${uidhex}/"; then
  say "dumpsys jobscheduler: $pkg owns a job (uid $uid)"; rc=1
else
  say "dumpsys jobscheduler: no owned job for $pkg"
fi
# A posted notification is a violation; the channel REGISTRATION (ghost_messages_v1, created at
# app start by design, §4.6) lives in the preferences section and is expected.
posted=$("$adb" shell "dumpsys notification" 2>/dev/null | tr -d '\r' | sed -n '/Notification List/,/Notification Preferences/p' | grep -c "$pkg" || true)
if [ "${posted:-0}" -gt 0 ]; then
  say "dumpsys notification: $pkg has a POSTED notification"; rc=1
else
  say "dumpsys notification: nothing posted for $pkg (the channel registration is by design)"
fi
if "$adb" shell "dumpsys alarm" 2>/dev/null | tr -d '\r' | grep -q "$pkg"; then
  say "dumpsys alarm names $pkg (the design's one inexact alarm - reported, allowed)"
else
  say "dumpsys alarm: no $pkg entry"
fi
exit "$rc"
