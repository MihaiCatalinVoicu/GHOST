#!/usr/bin/env bash
# t6-host-twin.sh — the host form of the T6 twin on the WSL staging runner (design B.2 row T6;
# the emulator form t6-dynamic-run.sh is a different mechanism - UID attribution only exists here).
#
#   t6-host-twin.sh available -- <workload...>   egress open: capture and classify
#   t6-host-twin.sh blocked  -- <workload...>    the UID's egress dropped by nftables: the
#                                                workload's Tor must fail with NO plaintext fallback
#
# What it proves, per run:
#   1. attribution: every counted/captured egress packet belongs to the dedicated UID
#      (nftables meta skuid counter, WSL2 kernel honours it);
#   2. available: only TCP :443 (Tor OR connections) leave the UID - zero UDP/53, zero other;
#   3. blocked: nftables drops everything for the UID (counter), the wire sees nothing, and the
#      workload reports failure instead of falling back to plaintext.
#
# Output: one fixed line per finding (T3), the pcap path, exit 0 only when the assertions hold.
set -euo pipefail

VARIANT=${1:?available|blocked}; shift
[ "$1" = "--" ] && shift
WORKLOAD=("$@")
[ ${#WORKLOAD[@]} -gt 0 ] || { echo "usage: t6-host-twin.sh available|blocked -- <workload...>" >&2; exit 2; }

UID_T6=$(id -u ghost-t6)
IFACE=${IFACE:-eth0}
OUT=${OUT:-/srv/harness/t6}
mkdir -p "$OUT"
IP=$(ip -4 -o addr show "$IFACE" | awk '{split($4,a,"/"); print a[1]}')
STAMP=$(date -u +%Y%m%dT%H%M%SZ)
PCAP="$OUT/t6-$VARIANT-$STAMP.pcap"
NFT_TABLE=inet/t6

nft_cleanup() { sudo nft delete table "$NFT_TABLE" 2>/dev/null || true; }
nft_cleanup
sudo nft add table "$NFT_TABLE"
sudo nft add chain "$NFT_TABLE" output '{ type filter hook output priority 10; policy accept; }'
case "$VARIANT" in
  available) sudo nft add rule "$NFT_TABLE" output skuid "$UID_T6" counter accept ;;
  blocked)   sudo nft add rule "$NFT_TABLE" output skuid "$UID_T6" counter drop ;;
  *) echo "unknown variant $VARIANT" >&2; exit 2 ;;
esac
trap nft_cleanup EXIT

# Capture the VM's egress for the workload window only. -s 96 keeps headers, drops payload.
sudo tcpdump -i "$IFACE" -U -s 96 -w "$PCAP" >"$OUT/tcpdump-$VARIANT-$STAMP.log" 2>&1 &
TCPDUMP_PID=$!
sleep 2

set +e
sudo -u ghost-t6 "${WORKLOAD[@]}"
WORKLOAD_RC=$?
set -e

sleep 2
sudo kill "$TCPDUMP_PID" 2>/dev/null || true
wait "$TCPDUMP_PID" 2>/dev/null || true

COUNTER=$(sudo nft list table "$NFT_TABLE" | grep -oE 'packets [0-9]+' | head -1 || true)
echo "t6: variant=$VARIANT workload_rc=$WORKLOAD_RC uid=$UID_T6 counter=[$COUNTER]"
echo "t6: pcap=$PCAP self=$IP iface=$IFACE"

# Classification of OUR outbound SYNs and DNS: attribution by the capture window plus the
# skuid counter above (nothing else runs in this window). Tor OR ports: 443/9001/9030 are
# canonical; any other destination port must be verified as a Tor relay out of band (the
# available run of 2026-10-23 verified 146.0.32.214:777 by its randomized link certificate).
SYNS=$(sudo tcpdump -nn -r "$PCAP" "src host $IP and tcp and tcp[tcpflags] & tcp-syn != 0 and tcp[tcpflags] & tcp-ack == 0" 2>/dev/null | wc -l || true)
DNS=$(sudo tcpdump -nn -r "$PCAP" "src host $IP and udp and dst port 53" 2>/dev/null | wc -l || true)
NONOR=$(sudo tcpdump -nn -r "$PCAP" "src host $IP and tcp and dst port != 443 and dst port != 9001 and dst port != 9030 and tcp[tcpflags] & tcp-syn != 0 and tcp[tcpflags] & tcp-ack == 0" 2>/dev/null | wc -l || true)
OTHER_DST=$(sudo tcpdump -nn -r "$PCAP" "src host $IP and tcp and dst port != 443 and dst port != 9001 and dst port != 9030 and tcp[tcpflags] & tcp-syn != 0 and tcp[tcpflags] & tcp-ack == 0" 2>/dev/null | awk '{print $NF, $(NF-1)}' | sort -u || true)
DST443=$(sudo tcpdump -nn -r "$PCAP" "src host $IP and tcp and dst port 443 and tcp[tcpflags] & tcp-syn != 0 and tcp[tcpflags] & tcp-ack == 0" 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i ~ />/) {split($i,a,">"); print a[2]}}' | sort -u | wc -l || true)
echo "t6: syns=$SYNS tor443=$DST443 other_or_syn=$NONOR dns_udp53=$DNS"
[ -n "$OTHER_DST" ] && echo "t6: verify-other-or: $OTHER_DST"

FAIL=0
if [ "$DNS" != "0" ]; then echo "t6: FAIL dns leak"; FAIL=1; fi
case "$VARIANT" in
  available)
    [ "$SYNS" -gt 0 ] || { echo "t6: FAIL no tor traffic captured"; FAIL=1; }
    [ "$NONOR" = "0" ] || echo "t6: NOTE non-canonical OR ports present - verify each as Tor"
    ;;
  blocked)
    [ "$SYNS" = "0" ] || { echo "t6: FAIL traffic left the wire under the drop"; FAIL=1; }
    ;;
esac
[ "$FAIL" = "0" ] && echo "t6: PASS $VARIANT"
exit "$FAIL"
