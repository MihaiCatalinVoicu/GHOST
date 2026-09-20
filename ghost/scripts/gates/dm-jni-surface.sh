#!/usr/bin/env bash
# Gate G-R6 (Phase 9 design §2.6, §2.3): the DM JNI surface is a **closed list**.
#
# Two directions, both checked:
#   1. every `Java_org_ghost_crypto_bridge_DmNative_*` entry point the **workspace** writes, and
#      every such symbol a built library exports, is on the list `client-core/dm/src/jni.rs`
#      declares, and
#   2. every list entry marked `Availability::Exported` really is emitted, and really is exported
#      by each library the caller names.
#
# The list itself is the Rust constant `CLOSED_LIST`, so the gate and the code cannot drift: a
# function added to the crate without a list entry fails direction 1, and an entry promoted to
# `Exported` without an export fails direction 2. Entries marked `Declared("Sn")` name the slice
# that will export them; a build that exports one of those early fails direction 1 as well, which
# is what keeps the list closed while it is being filled. The entry points are looked for across
# the whole workspace, not only in the file the list lives in: `ghost-client-net` invokes
# `export_jni!`, and a hand-written entry point in any other crate would otherwise be invisible.
#
# The Kotlin side is checked too: `org.ghost.crypto.bridge.DmNative` must declare exactly the
# exported names as `external fun`, so a native method without a body or a body without a
# declaration is caught before a device sees `UnsatisfiedLinkError`; and each declaration must be
# `internal` **with** an explicit `@JvmName`, which is the facade rule of §2.6 and §13.1 together
# with the only way to keep it (Kotlin mangles internal members' JVM names).
#
# Usage: dm-jni-surface.sh [<library> ...]
#   <library>  a built library to read symbols from: the CI `android` job passes the
#              `ghost-dm-host` build and `android-native` every shipped
#              `libghost_client_net.so` (§22.8.10 points 6 and 10). Without one the symbol half is
#              skipped and the source halves still run, so the gate is useful on a host without
#              the Rust toolchain.
# Self-test hooks: GHOST_DM_JNI_SOURCE, GHOST_DM_JNI_KOTLIN, GHOST_DM_JNI_SCAN, and
# GHOST_DM_JNI_NM, which names the symbol reader — the fixtures in
# `test-harness/gates/dm-jni/nm/` are readers that print an exported list with one symbol too many,
# one too few, or fail outright, which is how the symbol half gets negative fixtures without
# committing built libraries (review round 2, R2-05).
source "$(dirname "${BASH_SOURCE[0]}")/common.sh"
SOURCE="${GHOST_DM_JNI_SOURCE:-$GHOST_ROOT/client-core/dm/src/jni.rs}"
KOTLIN="${GHOST_DM_JNI_KOTLIN:-$GHOST_ROOT/android/crypto-bridge/src/main/kotlin/org/ghost/crypto/bridge/DmNative.kt}"
# Where entry points are looked for. The closed list lives in one file; an entry point does not
# have to, and one added to `ghost-client-net` (which invokes `export_jni!`) or to any other crate
# of the workspace would be invisible to a file-scoped read. The default is the whole workspace,
# minus build outputs, the gate's own fixtures and the S0' spike crate, which is not shipped.
if [ -n "${GHOST_DM_JNI_SOURCE:-}" ]; then SCAN_DEFAULT="$SOURCE"; else SCAN_DEFAULT="$GHOST_ROOT"; fi
SCAN="${GHOST_DM_JNI_SCAN:-$SCAN_DEFAULT}"
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

# The names the export macro really emits: the macro arms of the closed-list file, and every other
# Rust source of the scan root, so an entry point written by hand somewhere else is caught too.
prune=(-not -path '*/target/*')
if [ -z "${GHOST_DM_JNI_SCAN:-}" ]; then
  prune+=(-not -path '*/test-harness/*' -not -path '*/dm-spike/*')
fi
{
  grep -oE "pub extern \"system\" fn ${PREFIX}[A-Za-z0-9]+" "$SOURCE" || true
  if [ -d "$SCAN" ]; then
    find "$SCAN" -name '*.rs' "${prune[@]}" -exec \
      grep -ohE "pub extern \"system\" fn ${PREFIX}[A-Za-z0-9]+" {} + || true
  elif [ "$SCAN" != "$SOURCE" ]; then
    grep -oE "pub extern \"system\" fn ${PREFIX}[A-Za-z0-9]+" "$SCAN" || true
  fi
} | sed -E "s/.*${PREFIX}//" | sort -u > "$work/emitted"

while read -r name; do
  [ -n "$name" ] || continue
  fail "the crate exports '$name', which is not on the closed list of §2.6 ($SOURCE; scanned $SCAN)"
done < <(comm -23 "$work/emitted" "$work/declared")

while read -r name; do
  [ -n "$name" ] || continue
  fail "'$name' is marked Exported on the closed list but the crate emits no entry point for it"
done < <(comm -23 "$work/expected" "$work/emitted")

while read -r name; do
  [ -n "$name" ] || continue
  fail "'$name' is emitted but not marked Exported on the closed list"
done < <(comm -13 "$work/expected" "$work/emitted")

# Kotlin declares exactly the exported names, and declares them `internal` with an explicit
# `@JvmName`: `:messaging` must go through the typed facade (§2.6, §13.1), and Kotlin mangles an
# internal member's JVM name (`ctxClose` -> `ctxClose$crypto_bridge`), which no JNI symbol matches.
# Both halves are checked, so tightening the visibility cannot turn into an UnsatisfiedLinkError on
# a device, and loosening it cannot slip past review.
awk '
  match($0, /@JvmName\("[A-Za-z0-9]+"\)/) {
    pinned = substr($0, RSTART + 10, RLENGTH - 12); pinned_line = NR; next
  }
  match($0, /external fun [A-Za-z0-9]+/) {
    name = substr($0, RSTART + 13, RLENGTH - 13)
    if ($0 !~ /internal external fun/) { print "public " name; next }
    if (pinned != name || NR - pinned_line > 2) { print "unpinned " name }
  }
' "$KOTLIN" > "$work/visibility"
while read -r kind name; do
  [ -n "$name" ] || continue
  case "$kind" in
    public) fail "DmNative declares 'external fun $name' outside the module: it must be internal" ;;
    unpinned) fail "DmNative's internal 'external fun $name' has no @JvmName(\"$name\"): Kotlin would mangle the JNI name" ;;
  esac
done < "$work/visibility"

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
# and a *wrong* one must not look like a failing build. An ELF library with no reader is a broken
# runner and does fail.
#
# `llvm-nm` is preferred where it exists, as §22.8.10 point 6 writes it: `android-native` passes
# the **Android** libraries, and a host binutils `nm` is not always built with the aarch64 target,
# while llvm-nm reads every target it was compiled for.
#
# The reader's **exit status** is checked (review round 2, R2-05): an `nm` that cannot read the
# library — a binutils build without the aarch64 target, a truncated file — used to be swallowed by
# `2>/dev/null … || true` and reported as eleven missing exports, which reads as "the library is
# wrong" when the truth is "the runner is". A broken reader is its own failure.
if [ -n "${GHOST_DM_JNI_NM:-}" ]; then NM="$GHOST_DM_JNI_NM"
elif command -v llvm-nm >/dev/null; then NM=llvm-nm
elif command -v nm >/dev/null; then NM=nm
else NM=""; fi
for LIBRARY in "$@"; do
  if [ ! -f "$LIBRARY" ]; then
    fail "library not found: $LIBRARY"
  elif [ "$(head -c 4 "$LIBRARY" | od -An -tx1 | tr -d ' \n')" != "7f454c46" ]; then
    echo "[dm-jni-surface] symbol check skipped: $LIBRARY is not ELF (${NM:-nm} -D cannot read it)" >&2
  elif [ -z "$NM" ]; then
    fail "neither llvm-nm nor nm found: the symbol check of an ELF library needs one of them"
  elif ! "$NM" -D --defined-only "$LIBRARY" > "$work/nm-out" 2> "$work/nm-err"; then
    fail "$NM could not read $LIBRARY: $(head -n 1 "$work/nm-err")"
  else
    grep -oE "${PREFIX}[A-Za-z0-9]+" "$work/nm-out" \
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
done

finish dm-jni-surface
