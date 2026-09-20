#!/usr/bin/env bash
# Gate G-R6 (Phase 9 design §2.6, §2.3): the DM JNI surface is a **closed list**.
#
# Two directions, both checked:
#   1. every `Java_org_ghost_crypto_bridge_DmNative_*` symbol the built library exports is on the
#      list `client-core/dm/src/jni.rs` declares, and
#   2. every list entry marked `Availability::Exported` really is exported.
#
# The list itself is the Rust constant `CLOSED_LIST`, so the gate and the code cannot drift: a
# function added to the crate without a list entry fails direction 1, and an entry promoted to
# `Exported` without an export fails direction 2. Entries marked `Declared("Sn")` name the slice
# that will export them; a build that exports one of those early fails direction 1 as well, which
# is what keeps the list closed while it is being filled.
#
# The Kotlin side is checked too: `org.ghost.crypto.bridge.DmNative` must declare exactly the
# exported names as `external fun`, so a native method without a body or a body without a
# declaration is caught before a device sees `UnsatisfiedLinkError`.
#
# Usage: dm-jni-surface.sh [<library>]
#   <library>  the built cdylib to read symbols from (the CI `android` job passes the
#              `ghost-dm-host` build). Without it the symbol half is skipped and the source halves
#              still run, so the gate is useful on a host without the Rust toolchain.
# Self-test hooks: GHOST_DM_JNI_SOURCE, GHOST_DM_JNI_KOTLIN.
source "$(dirname "${BASH_SOURCE[0]}")/common.sh"
SOURCE="${GHOST_DM_JNI_SOURCE:-$GHOST_ROOT/client-core/dm/src/jni.rs}"
KOTLIN="${GHOST_DM_JNI_KOTLIN:-$GHOST_ROOT/android/crypto-bridge/src/main/kotlin/org/ghost/crypto/bridge/DmNative.kt}"
LIBRARY="${1:-}"
PREFIX="Java_org_ghost_crypto_bridge_DmNative_"

[ -f "$SOURCE" ] || { echo "DM JNI source not found: $SOURCE" >&2; exit 2; }
[ -f "$KOTLIN" ] || { echo "DmNative.kt not found: $KOTLIN" >&2; exit 2; }

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

# The closed list, from the Rust constant: `(n, "name", Availability::Exported)` lines.
grep -oE '\([0-9]+, "[A-Za-z0-9]+", Availability::(Exported|Declared\("[A-Za-z0-9]+"\))\)' "$SOURCE" \
  > "$work/entries" || true
[ -s "$work/entries" ] || { fail "no closed-list entries read from $SOURCE"; finish dm-jni-surface; }
sed -E 's/^\([0-9]+, "([A-Za-z0-9]+)".*$/\1/' "$work/entries" | sort -u > "$work/declared"
grep 'Availability::Exported' "$work/entries" \
  | sed -E 's/^\([0-9]+, "([A-Za-z0-9]+)".*$/\1/' | sort -u > "$work/expected"

# The names the export macro really emits, from the macro arms of the same file.
grep -oE "pub extern \"system\" fn ${PREFIX}[A-Za-z0-9]+" "$SOURCE" \
  | sed -E "s/.*${PREFIX}//" | sort -u > "$work/emitted"

while read -r name; do
  [ -n "$name" ] || continue
  fail "the crate exports '$name', which is not on the closed list of §2.6 ($SOURCE)"
done < <(comm -23 "$work/emitted" "$work/declared")

while read -r name; do
  [ -n "$name" ] || continue
  fail "'$name' is marked Exported on the closed list but the crate emits no entry point for it"
done < <(comm -23 "$work/expected" "$work/emitted")

while read -r name; do
  [ -n "$name" ] || continue
  fail "'$name' is emitted but not marked Exported on the closed list"
done < <(comm -13 "$work/expected" "$work/emitted")

# Kotlin declares exactly the exported names.
grep -oE 'external fun [A-Za-z0-9]+' "$KOTLIN" | sed -E 's/external fun //' | sort -u > "$work/kotlin"
while read -r name; do
  [ -n "$name" ] || continue
  fail "DmNative declares 'external fun $name', which the crate does not export"
done < <(comm -23 "$work/kotlin" "$work/expected")
while read -r name; do
  [ -n "$name" ] || continue
  fail "DmNative does not declare 'external fun $name', which the crate exports"
done < <(comm -13 "$work/kotlin" "$work/expected")

# The built library, when one was named: its dynamic symbols are exactly the expected set.
#
# `nm -D` reads ELF. The CI android job builds the Linux `.so` and this half runs there; the
# owner's Windows machine builds an MSVC `.dll`, which `nm` cannot read at all, so that case is
# reported as skipped rather than failed — a missing toolchain must not look like a passing gate,
# and a *wrong* one must not look like a failing build. An ELF library with no `nm` is a broken
# runner and does fail.
if [ -n "$LIBRARY" ]; then
  if [ ! -f "$LIBRARY" ]; then
    fail "library not found: $LIBRARY"
  elif [ "$(head -c 4 "$LIBRARY" | od -An -tx1 | tr -d ' \n')" != "7f454c46" ]; then
    echo "[dm-jni-surface] symbol check skipped: $LIBRARY is not ELF (nm -D cannot read it)" >&2
  elif ! command -v nm >/dev/null; then
    fail "nm not found: the symbol check of an ELF library needs binutils"
  else
    nm -D --defined-only "$LIBRARY" 2>/dev/null | grep -oE "${PREFIX}[A-Za-z0-9]+" \
      | sed -E "s/${PREFIX}//" | sort -u > "$work/symbols" || true
    while read -r name; do
      [ -n "$name" ] || continue
      fail "$LIBRARY exports '$name', which is not on the closed list"
    done < <(comm -23 "$work/symbols" "$work/expected")
    while read -r name; do
      [ -n "$name" ] || continue
      fail "$LIBRARY does not export '$name', which the closed list marks Exported"
    done < <(comm -13 "$work/symbols" "$work/expected")
  fi
fi

finish dm-jni-surface
