#!/usr/bin/env bash
# Gate (§9.1; Phase 8 design §5.2, §14.1, RC G18): the normative wire schemas compile with protoc,
# and every request message carries an explicit protocol version: each `message <Name>Request`
# block must contain the field `uint32 version = 1;` (checked per message, not per file, so one
# versioned request cannot hide an unversioned one).
source "$(dirname "${BASH_SOURCE[0]}")/common.sh"
command -v protoc >/dev/null || { echo "protoc not found" >&2; exit 2; }
# One line per request message without its version: "<line of the message>: message <Name> ...".
UNVERSIONED_AWK='
{
  line = $0
  sub(/\/\/.*/, "", line)
  if (!inreq && line ~ /^[[:space:]]*message[[:space:]]+[A-Za-z0-9_]*Request[[:space:]]*\{/) {
    name = line
    sub(/^[[:space:]]*message[[:space:]]+/, "", name)
    sub(/[[:space:]]*\{.*$/, "", name)
    inreq = 1; depth = 0; found = 0; start = NR
  }
  if (inreq) {
    if (line ~ /(^|[^A-Za-z0-9_])uint32[[:space:]]+version[[:space:]]*=[[:space:]]*1[[:space:]]*;/) found = 1
    opens = line; n_open = gsub(/\{/, "", opens)
    closes = line; n_close = gsub(/\}/, "", closes)
    depth += n_open - n_close
    if (depth <= 0) {
      if (!found) printf "%d: message %s lacks uint32 version = 1;\n", start, name
      inreq = 0
    }
  }
}'
for p in "$GHOST_ROOT"/protocol/*/v*/*.proto; do
  [ -e "$p" ] || continue
  protoc --proto_path="$GHOST_ROOT/protocol" -o "$(mktemp)" "$p" || fail "$p: protoc rejected schema"
  while IFS= read -r v; do
    [ -n "$v" ] && fail "$p:$v"
  done < <(awk "$UNVERSIONED_AWK" "$p")
done
finish proto-check
