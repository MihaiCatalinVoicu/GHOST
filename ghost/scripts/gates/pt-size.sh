#!/usr/bin/env bash
# Gate G-T3 (design faza12-transports.md §9.1, §13): the extracted and compressed sizes of the
# shipped lyrebird binaries stay within the rev-2 pinned budgets. The pins are the exact byte
# values in pins.env; a bump that grows a binary re-pins them there, with the evidence — size
# growth past the pin without a re-pin fails here.
# Build-dependent: reads third_party/lyrebird/out/ (the BUILD.sh outputs). Where they do not
# exist this gate prints a skip and exits 0; the CI android job runs it right after BUILD.sh,
# where a skip is impossible.
#   - extracted:  file size ≤ LYREBIRD_{ARM64,AMD64}_SIZE_MAX (exact: the byte count is
#     host-independent)
#   - compressed: gzip -9 size ≤ pin + 0.5% (S3-T5: the pins were measured with a specific
#     gzip build; the stream and header vary by a few bytes across hosts and gzip versions —
#     measured here: +1/+4 B — while a real size bump is orders above: the unpruned build
#     the budgets fired on was +8 MiB. 0.5 % ≈ 15 KiB sits two orders over tooling noise and
#     two under a re-pin-worthy growth)
source "$(dirname "${BASH_SOURCE[0]}")/common.sh"
LB="$GHOST_ROOT/third_party/lyrebird"
pin() { sed -n "s/^$1=//p" "$LB/pins.env" 2>/dev/null | head -1; }

[ -f "$LB/pins.env" ] || { fail "third_party/lyrebird/pins.env missing"; finish pt-size; }
missing=0
for f in lyrebird-android-arm64 lyrebird-android-amd64; do
  [ -f "$LB/out/$f" ] || { echo "pt-size: skip ($f not built; run BUILD.sh)"; exit 0; }
done

check_one() { # $1 = binary name, $2 = size pin, $3 = gzip pin
  local bin="$LB/out/$1" size_pin="$2" gz_pin="$3" size gz gz_max
  size=$(wc -c < "$bin" | tr -d ' \r\n')
  gz=$(gzip -9 -c "$bin" | wc -c | tr -d ' \r\n')
  gz_max=$(( gz_pin + gz_pin / 200 ))
  [ "$size" -le "$size_pin" ] \
    || fail "$1: extracted $size B exceeds the pinned budget $size_pin B (§9.1; re-pin in pins.env with evidence, or prune)"
  [ "$gz" -le "$gz_max" ] \
    || fail "$1: gzip -9 $gz B exceeds the pinned budget $gz_pin B (+0.5 % host tolerance, S3-T5; a real bump re-pins)"
  echo "pt-size: $1: $size B extracted (≤ $size_pin), $gz B gzip -9 (≤ $gz_pin, host tolerance to $gz_max)"
}

check_one lyrebird-android-arm64 "$(pin LYREBIRD_ARM64_SIZE_MAX)" "$(pin LYREBIRD_ARM64_GZIP_MAX)"
check_one lyrebird-android-amd64 "$(pin LYREBIRD_AMD64_SIZE_MAX)" "$(pin LYREBIRD_AMD64_GZIP_MAX)"
# The pins must exist and be numeric (a deleted pin must not silently disable the gate).
for k in LYREBIRD_ARM64_SIZE_MAX LYREBIRD_AMD64_SIZE_MAX LYREBIRD_ARM64_GZIP_MAX LYREBIRD_AMD64_GZIP_MAX; do
  v="$(pin "$k")"
  [[ "$v" =~ ^[0-9]+$ ]] || fail "pins.env: $k missing or not numeric ('$v')"
done
finish pt-size
