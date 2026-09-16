#!/usr/bin/env bash
# Gate (§9.1; Phase 8 design §5.2, §14.1, RC G18): the normative wire schemas compile with protoc,
# and every request message carries an explicit protocol version: each `message <Name>Request`
# block must itself declare the field `uint32 version = 1;` (checked per message, not per file,
# so one versioned request cannot hide an unversioned one; a version declared by a nested message
# or written only in a comment does not count; the block's `{` may be on a later line than its
# header).
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
files=0
for p in "$GHOST_ROOT"/protocol/*/v*/*.proto; do
  [ -f "$p" ] || continue
  files=$((files + 1))
  protoc --proto_path="$GHOST_ROOT/protocol" -o "$(mktemp)" "$p" || fail "$p: protoc rejected schema"
  while IFS= read -r v; do
    [ -n "$v" ] && fail "$p:$v"
  done < <(awk "$UNVERSIONED_AWK" "$p")
done
[ "$files" -gt 0 ] || fail "no .proto files found under $GHOST_ROOT/protocol"
# Phase 9 (design §4.2, §16.1): relay.proto carries RegisterKeyRequest (versioned by the rule
# above), and the enums KeyKind and RegisterResult hold exactly the design's values, field for
# field (a KeyKind 2, the Write byte of capability headers, or a replacing RegisterResult fails).
# The file is read statement by statement as above; each enum prints "<Name>: <NAME>=<n> ...".
ENUMS_AWK='
{
  line = $0
  sub(/\/\/.*/, "", line)
  n = length(line)
  for (i = 1; i <= n; i++) {
    ch = substr(line, i, 1)
    if (ch == "{") {
      depth++
      enumname[depth] = ""
      if (stmt ~ /^[[:space:]]*enum[[:space:]]+[A-Za-z0-9_]+[[:space:]]*$/) {
        name = stmt
        sub(/^[[:space:]]*enum[[:space:]]+/, "", name)
        sub(/[[:space:]]*$/, "", name)
        enumname[depth] = name
        order[++count] = name
        values[name] = ""
      }
      stmt = ""
    } else if (ch == "}") {
      if (depth > 0) depth--
      stmt = ""
    } else if (ch == ";") {
      if (depth > 0 && enumname[depth] != "") {
        v = stmt
        gsub(/[[:space:]]+/, "", v)
        if (v != "") values[enumname[depth]] = values[enumname[depth]] (values[enumname[depth]] == "" ? "" : " ") v
      }
      stmt = ""
    } else {
      stmt = stmt ch
    }
  }
  stmt = stmt " "
}
END { for (k = 1; k <= count; k++) printf "%s: %s\n", order[k], values[order[k]] }'
RELAY_PROTO="$GHOST_ROOT/protocol/relay/v1/relay.proto"
if [ -f "$RELAY_PROTO" ]; then
  grep -qE '^[[:space:]]*message[[:space:]]+RegisterKeyRequest([[:space:]{]|$)' "$RELAY_PROTO" \
    || fail "$RELAY_PROTO: message RegisterKeyRequest is missing (design §4.2)"
  enums="$(awk "$ENUMS_AWK" "$RELAY_PROTO")"
  for want in "KeyKind: KEY_KIND_UNSPECIFIED=0 KEY_KIND_READ=1 KEY_KIND_DEPOSIT=3 KEY_KIND_FETCH=4" \
    "RegisterResult: REGISTER_RESULT_UNSPECIFIED=0 REGISTER_RESULT_OK=1 REGISTER_RESULT_WRONG_PERIOD=2"; do
    name="${want%%:*}"
    got="$(printf '%s\n' "$enums" | grep -E "^${name}: " || true)"
    [ "$got" = "$want" ] \
      || fail "$RELAY_PROTO: enum $name must be exactly {${want#*: }} (design §4.2), found {${got#*: }}"
  done
else
  fail "$RELAY_PROTO: missing"
fi
finish proto-check
