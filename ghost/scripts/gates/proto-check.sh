#!/usr/bin/env bash
# Gate (§9.1; Phase 8 design §5.2, §14.1, RC G18): the normative wire schemas compile with protoc,
# and every request message carries an explicit protocol version: each `message <Name>Request`
# block must itself declare the field `uint32 version = 1;` (checked per message, not per file,
# so one versioned request cannot hide an unversioned one; a version declared by a nested message
# does not count; the block's `{` may be on a later line than its header).
source "$(dirname "${BASH_SOURCE[0]}")/common.sh"
command -v protoc >/dev/null || { echo "protoc not found" >&2; exit 2; }
# One line per request message without its version: "<line of the message>: message <Name> ...".
# The file is read statement by statement (text up to the next "{", "}" or ";", across lines,
# after "//" comments are removed): a "{" opens a block, which is a request block when the text
# before it is "message <Name>Request"; a ";" ends a statement, and "uint32 version = 1" counts
# for the innermost open block only.
UNVERSIONED_AWK='
{
  line = $0
  sub(/\/\/.*/, "", line)
  n = length(line)
  for (i = 1; i <= n; i++) {
    ch = substr(line, i, 1)
    if (ch == "{") {
      depth++
      isreq[depth] = 0; found[depth] = 0
      if (stmt ~ /^[[:space:]]*message[[:space:]]+[A-Za-z0-9_]*Request[[:space:]]*$/) {
        name = stmt
        sub(/^[[:space:]]*message[[:space:]]+/, "", name)
        sub(/[[:space:]]*$/, "", name)
        isreq[depth] = 1; reqname[depth] = name; reqline[depth] = stmtline
      }
      stmt = ""; stmtline = 0
    } else if (ch == "}") {
      if (depth > 0) {
        if (isreq[depth] && !found[depth]) printf "%d: message %s lacks uint32 version = 1;\n", reqline[depth], reqname[depth]
        depth--
      }
      stmt = ""; stmtline = 0
    } else if (ch == ";") {
      if (depth > 0 && isreq[depth] && stmt ~ /^[[:space:]]*uint32[[:space:]]+version[[:space:]]*=[[:space:]]*1[[:space:]]*$/) found[depth] = 1
      stmt = ""; stmtline = 0
    } else {
      if (stmtline == 0 && ch !~ /[[:space:]]/) stmtline = NR
      stmt = stmt ch
    }
  }
  stmt = stmt " "
}'
for p in "$GHOST_ROOT"/protocol/*/v*/*.proto; do
  [ -e "$p" ] || continue
  protoc --proto_path="$GHOST_ROOT/protocol" -o "$(mktemp)" "$p" || fail "$p: protoc rejected schema"
  while IFS= read -r v; do
    [ -n "$v" ] && fail "$p:$v"
  done < <(awk "$UNVERSIONED_AWK" "$p")
done
finish proto-check
