#!/usr/bin/env bash
# Gate (§9.1): the normative wire schemas compile with protoc and carry explicit versions: every
# `message <Name>Request { ... }` block declares `uint32 version = 1;` as a top-level field
# (Phase 8 design §14.1, RC G18), so a request added without a version is caught even when another
# message of the same file has one.
source "$(dirname "${BASH_SOURCE[0]}")/common.sh"
command -v protoc >/dev/null || { echo "protoc not found" >&2; exit 2; }
files=0
for p in "$GHOST_ROOT"/protocol/*/v*/*.proto; do
  [ -f "$p" ] || continue
  files=$((files + 1))
  protoc --proto_path="$GHOST_ROOT/protocol" -o "$(mktemp)" "$p" || fail "$p: protoc rejected schema"
  # Prints "<line> <name>" for every *Request message without a top-level version field.
  missing="$(awk '
    {
      line = $0
      sub(/\/\/.*/, "", line)
      if (depth == 0 && line ~ /^[[:space:]]*message[[:space:]]+[A-Za-z0-9_]+Request[[:space:]]*\{/) {
        name = line
        sub(/^[[:space:]]*message[[:space:]]+/, "", name)
        sub(/[[:space:]]*\{.*/, "", name)
        req = 1; found = 0; start = NR
      }
      if (req && depth == 1 && line ~ /^[[:space:]]*uint32[[:space:]]+version[[:space:]]*=[[:space:]]*1[[:space:]]*;/) found = 1
      opens = gsub(/\{/, "{", line)
      closes = gsub(/\}/, "}", line)
      depth += opens - closes
      if (req && depth == 0) {
        if (!found) print start " " name
        req = 0
      }
    }' "$p")"
  while read -r line name; do
    [ -n "$line" ] && fail "$p:$line: message $name must carry 'uint32 version = 1;'"
  done <<< "$missing"
done
[ "$files" -gt 0 ] || fail "no .proto files found under $GHOST_ROOT/protocol"
finish proto-check
