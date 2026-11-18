#!/usr/bin/env bash
set -euo pipefail
root="$(cd "$(dirname "$0")" && pwd)"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
cat > "$tmp/input.log" <<'LOG'
2026-11-17 10:00:00 get_address address_index_outofbound
2026-11-17 10:00:01 get_address address_index_outofbound
2026-11-17 10:00:02 RPC transport timeout
2026-11-17 10:00:03 another_method address_index_outofbound
LOG
bash "$root/wallet-rpc-log.sh" "$tmp/input.log" >"$tmp/out" 2>"$tmp/err"
[ "$(wc -l < "$tmp/out")" -eq 2 ]
grep -q 'RPC transport timeout' "$tmp/out"
grep -q 'another_method address_index_outofbound' "$tmp/out"
! grep -q 'get_address address_index_outofbound' "$tmp/out"
grep -q 'suppressed 2 expected end-of-pool probe' "$tmp/err"
echo "wallet-rpc-log test: OK"
