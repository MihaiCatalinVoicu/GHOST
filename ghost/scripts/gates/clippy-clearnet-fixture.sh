#!/usr/bin/env bash
# Gate (T6, ADR-19): every ban in client-core/net/clippy.toml must actually fire. Runs clippy on
# the negative fixture (src/clippy_fixture.rs, feature `clippy-fixture`) and requires one
# "disallowed method/type `<path>`" diagnostic per configured path, and no other compile error.
# A mistyped or unresolvable path in clippy.toml is otherwise ignored silently by clippy.
source "$(dirname "${BASH_SOURCE[0]}")/common.sh"
command -v cargo >/dev/null || { echo "cargo not found" >&2; exit 2; }
cd "$GHOST_ROOT"
CONF="client-core/net/clippy.toml"
out="$(cargo clippy --locked -p ghost-client-net --features clippy-fixture --message-format short -- -D warnings 2>&1 || true)"
if printf '%s\n' "$out" | grep -qE '^error\[E[0-9]+\]'; then
  printf '%s\n' "$out" | grep -E '^error\[E[0-9]+\]' | head -5 >&2
  fail "the clippy fixture does not compile; the bans were not exercised"
fi
paths="$(grep -oE 'path = "[^"]+"' "$CONF" | sed -E 's/path = "(.*)"/\1/')"
[ -n "$paths" ] || fail "no bans found in $CONF"
# Self-test hook: a path that clippy.toml does not ban must be reported as not firing.
if [ -n "${GHOST_CLIPPY_EXTRA_BAN:-}" ]; then paths+=$'\n'"$GHOST_CLIPPY_EXTRA_BAN"; fi
n=0
while IFS= read -r p; do
  [ -n "$p" ] || continue
  n=$((n + 1))
  printf '%s\n' "$out" | grep -qF "disallowed method \`$p\`" \
    || printf '%s\n' "$out" | grep -qF "disallowed type \`$p\`" \
    || fail "clippy.toml ban '$p' did not fire on the fixture"
done <<< "$paths"
echo "checked $n bans"
finish clippy-clearnet-fixture
