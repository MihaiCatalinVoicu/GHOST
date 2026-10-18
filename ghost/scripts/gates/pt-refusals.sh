#!/usr/bin/env bash
# Gate G-T8 (design faza12-transports.md §13): the refusal contract is pinned in source —
# a grammar change must arrive with its fixture update, not slip through a refactor.
#   - the grammar table of client-core/net/src/bridge_line.rs: exactly the two PT names
#     (`"obfs4"` / `"webtunnel"` string arms), the snowflake arm refused distinctly
#     (`SnowflakeDeferred`), iat-mode pinned to 0|1|2, the webtunnel `https://` pin, the
#     1 024-char line bound and the 8-line cap as literals;
#   - snowflake is never *accepted*: no Ok(...) path names it — the only `"snowflake"` arm is
#     the refusal;
#   - PT lines require the binary: transport.rs gates PT configs on `needs_pt_binary()` and
#     names `PtBinaryMissing`; `LYREBIRD_BINARY` is the only PT binary name;
#   - the shipped crate links `pt-client` and the allowlist carries tor-ptmgr;
#   - the rust-feature-policy pt-server clause is armed (arti stays a PT client only).
# Reads sources only (the Phase 9 practice); comment lines do not satisfy a rule.
source "$(dirname "${BASH_SOURCE[0]}")/common.sh"
BL="$GHOST_ROOT/client-core/net/src/bridge_line.rs"
TR="$GHOST_ROOT/client-core/net/src/transport.rs"
CARGO="$GHOST_ROOT/client-core/net/Cargo.toml"
ALLOW="$GHOST_ROOT/client-core/rust-dependency-allowlist.txt"
FEATURE_POLICY="$GATES_DIR/rust-feature-policy.sh"
[ -f "$BL" ] || { fail "client-core/net/src/bridge_line.rs missing"; finish pt-refusals; }

code() { grep -v -E '^[[:space:]]*(//|///|/\*|\*|\*/)' "$1" || true; }

while IFS= read -r rule; do
  name="${rule%%::*}"; pat="${rule#*::}"
  grep -qE "$pat" <<< "$(code "$BL")" || fail "bridge_line.rs: $name is not pinned ($pat)"
done <<'RULES'
obfs4 arm::"obfs4"[[:space:]]*=>[[:space:]]*parse_pt_tail
webtunnel arm::"webtunnel"[[:space:]]*=>[[:space:]]*parse_pt_tail
snowflake refused distinctly::"snowflake"[[:space:]]*=>[[:space:]]*Err\(BridgeLineError::SnowflakeDeferred\)
iat-mode set::matches!\(value,[[:space:]]*"0"[[:space:]]*\|[[:space:]]*"1"[[:space:]]*\|[[:space:]]*"2"\)
webtunnel https pin::value\.starts_with\("https://"\)
line length bound::MAX_LINE_LEN:[[:space:]]*usize[[:space:]]*=[[:space:]]*1024
line count cap::MAX_LINES:[[:space:]]*usize[[:space:]]*=[[:space:]]*8
RULES

# Snowflake must not be accepted anywhere: every `"snowflake"` occurrence in code is the
# refusal arm above (count == 1 modulo the arm's own line).
n_snowflake="$(grep -c '"snowflake"' <<< "$(code "$BL")")"
[ "$n_snowflake" = 1 ] || fail "bridge_line.rs: '$n_snowflake' code occurrences of \"snowflake\": the only one must be the distinct refusal arm"
# Exactly two pluggable-transport grammars: a third arm is a grammar change without the
# fixture update this gate exists to force.
n_arms="$(grep -cE '=>[[:space:]]*parse_pt_tail' <<< "$(code "$BL")")"
[ "$n_arms" = 2 ] || fail "bridge_line.rs: $n_arms PT grammar arms (expected exactly 2: obfs4 and webtunnel; a new transport needs the refusal fixtures updated)"

# PT lines require the compiled-in feature's binary at config time.
grep -q 'needs_pt_binary()' <<< "$(code "$TR")" \
  || fail "transport.rs: PT configs are not gated on needs_pt_binary() (a PT line without the binary must refuse)"
grep -q 'PtBinaryMissing' <<< "$(code "$TR")" \
  || fail "transport.rs: PtBinaryMissing is not named (the refusal must stay typed)"
grep -q 'LYREBIRD_BINARY' <<< "$(code "$TR")" \
  || fail "transport.rs: LYREBIRD_BINARY missing (exactly one PT binary name is allowed)"

# The shipped feature and the allowlist (the arti-client features live on the workspace
# dependency, ghost/Cargo.toml).
grep -qE 'pt-client' "$GHOST_ROOT/Cargo.toml" || fail "the workspace arti-client pin does not enable pt-client (PT lines cannot work; ADR-61)"
grep -qx 'tor-ptmgr' "$ALLOW" || fail "client-core/rust-dependency-allowlist.txt does not carry tor-ptmgr"

# The pt-server clause stays armed in the feature policy gate.
grep -q 'arti-client:pt-server' "$FEATURE_POLICY" || fail "rust-feature-policy.sh lost the arti-client:pt-server clause (G-T8's twin)"
grep -q 'tor-ptmgr:pt-server' "$FEATURE_POLICY" || fail "rust-feature-policy.sh lost the tor-ptmgr:pt-server clause"

finish pt-refusals
