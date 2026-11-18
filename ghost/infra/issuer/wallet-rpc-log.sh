#!/usr/bin/env bash
# Read wallet-rpc diagnostics without the expected end-of-pool probes. Nothing is rewritten.
set -euo pipefail
file="${1:-/var/log/monero/wallet-rpc.log}"
[ -f "$file" ] || { echo "wallet-log: file is unavailable" >&2; exit 1; }
awk '
  index($0, "get_address") && index($0, "address_index_outofbound") { expected++; next }
  { print }
  END {
    if (expected > 0) {
      print "wallet-log: suppressed " expected " expected end-of-pool probe line(s)" > "/dev/stderr"
    }
  }
' "$file"
