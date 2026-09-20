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
# Piped `printf | grep -q` can report a spurious pipeline failure under `set -o pipefail`: grep
# exits after its first match and closes its end of the pipe, so printf can get SIGPIPE and its
# own non-zero exit then becomes the pipeline's status even though grep matched (or found nothing
# and exited 1, which is also swallowed the same way here). Here-strings avoid the second process.
if grep -qE '^error\[E[0-9]+\]' <<< "$out"; then
  # || true: head -5 can close its end while grep is still writing more matching lines, and under
  # `set -o pipefail` that SIGPIPEs grep and aborts the script right here (this line is a bare
  # statement, not an `if`/`||` condition) instead of reaching the `fail` below (license-notices.sh
  # guards its own `diff | head` the same way).
  grep -E '^error\[E[0-9]+\]' <<< "$out" | head -5 >&2 || true
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
  grep -qF "disallowed method \`$p\`" <<< "$out" \
    || grep -qF "disallowed type \`$p\`" <<< "$out" \
    || fail "clippy.toml ban '$p' did not fire on the fixture"
done <<< "$paths"
echo "checked $n bans"
finish clippy-clearnet-fixture
