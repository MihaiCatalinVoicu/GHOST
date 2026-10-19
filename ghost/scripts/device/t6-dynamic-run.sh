#!/usr/bin/env bash
# T6's dynamic emulator run (design faza13-ux.md Appendix B.2): traffic attributed to the
# GHOST uid, with a positive control. The control application (the :backupctl module) resolves
# a name and connects clearnet on purpose - the capture and the socket list MUST see it, or a
# silent GHOST would prove a broken tap, not a quiet app. Attribution is per-uid via `ss -p`
# as root: any socket owned by GHOST's uid is a violation (no socket, no packets), and the
# control's socket is the positive control. (This build's netstats exposes no live per-uid byte
# counters; socket-level attribution plus the pcap is the honest tap.)
#
#   t6-dynamic-run.sh <api> <control-apk> <app-apk>
#
# Requires a booted emulator and `adb root`. Exit 0 when: the control's socket is seen (positive
# control), no GHOST-owned socket exists in the foreground (DNS or otherwise), no GHOST-owned
# UDP socket names a DNS server, and the pcap carries the control's DNS query. Tor is
# unreachable in this run by construction (no identity is activated, so no session starts -
# §3.5); a Tor-blocking harness is the device checklist's variant.
set -uo pipefail
api="${1:-}"
ctl_apk="${2:-}"
app_apk="${3:-}"
[ -n "$api" ] && [ -n "$ctl_apk" ] && [ -n "$app_apk" ] || { echo "usage: t6-dynamic-run.sh <api> <control-apk> <app-apk>" >&2; exit 2; }
adb="${GHOST_ADB:-adb}"
pkg=org.ghost.app.gate
ctl=org.ghost.backupctl

say() { echo "t6: $*" >&2; }

uid_of() { # $1 = package - stat is root-reliable; dumpsys package's userId field is not.
  "$adb" shell "stat -c %u /data/user/0/$1" 2>/dev/null | tr -d '\r'
}

"$adb" root >/dev/null 2>&1 || { say "adb root refused - userdebug image required"; exit 1; }
"$adb" wait-for-device >/dev/null 2>&1
for _ in 1 2 3 4 5 6 7 8 9 10; do "$adb" shell id 2>/dev/null | grep -q uid=0 && break; sleep 1; done

"$adb" install -r "$ctl_apk" >/dev/null || { say "control install failed"; exit 1; }
"$adb" install -r "$app_apk" >/dev/null || { say "app install failed"; exit 1; }
"$adb" shell am force-stop "$pkg"; "$adb" shell am force-stop "$ctl"

g_uid=$(uid_of "$pkg"); c_uid=$(uid_of "$ctl")
[ -n "$g_uid" ] && [ -n "$c_uid" ] || { say "uid resolution failed"; exit 1; }
say "uids: ghost=$g_uid control=$c_uid"

pcap=/data/local/tmp/t6-$api.pcap
"$adb" shell "rm -f $pcap"
"$adb" shell "tcpdump -i any -s 0 -w $pcap" >/dev/null 2>&1 &
tcp_pid=$!
sleep 2

# The journeys: the control's probe, then GHOST in the foreground (no session without unlock),
# while /proc/net snapshots attribute every live socket to its uid (toybox ss shows no uid
# column on this image; /proc/net/{tcp,udp}{,6} carry it directly, as root).
"$adb" shell am start -n "$ctl/org.ghost.backupctl.BackupCtlActivity" >/dev/null
"$adb" shell am start -n "$pkg/org.ghost.app.MainActivity" >/dev/null
ghost_socks=0; ctl_socks=0; ghost_dns=0
for _ in 1 2 3 4 5 6 7 8; do
  snap=$("$adb" shell "cat /proc/net/tcp /proc/net/tcp6 /proc/net/udp /proc/net/udp6 2>/dev/null" | tr -d '\r')
  g=$(printf '%s\n' "$snap" | grep -c " $g_uid " || true)
  c=$(printf '%s\n' "$snap" | grep -c " $c_uid " || true)
  d=$(printf '%s\n' "$snap" | grep " $g_uid " | grep -c ':0035 ' || true)
  ghost_socks=$((ghost_socks + g)); ctl_socks=$((ctl_socks + c)); ghost_dns=$((ghost_dns + d))
  sleep 2
done
"$adb" shell am force-stop "$pkg"; "$adb" shell am force-stop "$ctl"
kill "$tcp_pid" >/dev/null 2>&1 || true
"$adb" shell "pkill tcpdump" >/dev/null 2>&1 || true
sleep 1

rc=0
if [ "$ctl_socks" -gt 0 ]; then
  say "positive control: $ctl_socks socket(s) owned by the control's uid ($c_uid)"
else
  say "no control socket seen - the tap is broken, this run proves nothing"; rc=1
fi
if [ "$ghost_socks" -eq 0 ]; then
  say "zero sockets owned by GHOST's uid ($g_uid) in the foreground - no GHOST packets exist"
else
  say "GHOST's uid owned $ghost_socks socket(s) in the foreground"; rc=1
fi
if [ "$ghost_dns" -eq 0 ]; then
  say "no GHOST-owned socket to a DNS server"
else
  say "GHOST's uid owned $ghost_dns DNS socket(s)"; rc=1
fi

# Read the capture on the device (its image carries tcpdump; the host needn't), then pull it.
dns_q=$("$adb" shell "tcpdump -r $pcap udp port 53 2>/dev/null | grep -c example.com" 2>/dev/null | tr -d '\r' || true)
"$adb" shell "chmod 644 $pcap 2>/dev/null" >/dev/null
"$adb" pull "$pcap" "t6-api$api.pcap" >/dev/null 2>&1 || say "pcap pull failed (kept on device at $pcap)"
"$adb" shell "rm -f $pcap" >/dev/null
if [ "${dns_q:-0}" -gt 0 ]; then
  say "the pcap carries the control's DNS query for example.com ($dns_q packets)"
else
  say "no DNS query in the pcap - the capture saw nothing"; rc=1
fi
exit "$rc"
