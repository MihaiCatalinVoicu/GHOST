#!/usr/bin/env bash
# Gate (§9.1): the normative wire schemas compile with protoc and carry explicit versions.
source "$(dirname "${BASH_SOURCE[0]}")/common.sh"
command -v protoc >/dev/null || { echo "protoc not found" >&2; exit 2; }
for p in "$GHOST_ROOT"/protocol/*/v*/*.proto; do
  protoc --proto_path="$GHOST_ROOT/protocol" -o "$(mktemp)" "$p" || fail "$p: protoc rejected schema"
  grep -q 'uint32 version = 1;' "$p" || fail "$p: requests must carry 'uint32 version = 1'"
done
finish proto-check
