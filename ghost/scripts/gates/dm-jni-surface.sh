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
# **Only `:crypto-bridge` references `DmNative`** (§16.1 G-R6, §21.13 point 7; added by slice S12):
# no production source set of any other Android module — `src/main`, `src/release`, `src/gate` —
# names it in code, and inside `:crypto-bridge` only `src/main` and `src/gate` may. `:messaging`
# reaches the ratchet through the typed facade (`DmSessions`) and nothing else.
#
# **No other JNI entry point, under any class name** (Phase 9 review GATES-3). The checks above
# name one class, `DmNative`: an entry point exported as `Java_org_ghost_crypto_bridge_DmDebug_…`
# (or under any other package), an `external fun` in another Android class, and a library exporting
# either passed every half. So the workspace's Rust sources, every production Android source set and
# every library read here may carry a JNI entry point only of `DmNative` (the closed list),
# `DmEquivalence.run` and `.bindingHooks` (test libraries and `src/equivalence` only) or the three
# classes of the network surface (`OTHER_JNI_CLASSES`: Phases 6 and 8, not DM). A new class is a
# change to this list, which is what makes it arrive deliberately.
#
# **The test-vectors entry points** (§15.9 item 7, §22.8.10 point 6; slice S12) are the symbols a
# *test* library adds: `Java_org_ghost_crypto_bridge_DmEquivalence_run` and, since §22.37,
# `…_DmEquivalence_bindingHooks` (MC-20's mutant and KC5b's replayed binding, switched per DM
# context), compiled only with `ghost-client-dm`'s `test-vectors` feature, which only
# `ghost-dm-host` enables. A library passed as `--test <library>` must export exactly the closed
# list plus those symbols; every other library is a shipped one and must export no
# `DmEquivalence` symbol at all.
#
# Usage: dm-jni-surface.sh [[--test] <library> ...]
#   <library>  a built library to read symbols from: `android-native` passes every shipped
#              `libghost_client_net.so` (§22.8.10 points 6 and 10); the `android` job, the DM exit
#              gate and `dm-emulator.yml` pass the `ghost-dm-host` builds with `--test`. Without one
#              the symbol half is skipped and the source halves still run, so the gate is useful on
#              a host without the Rust toolchain.
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
# minus build outputs and the gate's own fixtures (the S0' spike crate, pruned here until the S0'
# gate slice deleted it, design §22.33 item 12, is gone).
if [ -n "${GHOST_DM_JNI_SOURCE:-}" ]; then SCAN_DEFAULT="$SOURCE"; else SCAN_DEFAULT="$GHOST_ROOT"; fi
SCAN="${GHOST_DM_JNI_SCAN:-$SCAN_DEFAULT}"
PREFIX="Java_org_ghost_crypto_bridge_DmNative_"
# The test libraries' extra symbols (see the header).
ENTRY_PREFIX="Java_org_ghost_crypto_bridge_DmEquivalence_"
ENTRY_NAMES="run bindingHooks"
# The other classes a GHOST library may export JNI entry points for (see the header): the network
# surface of `ghost-client-net`, whose files are `android/network/src/main/…/<class>.kt`.
OTHER_JNI_CLASSES="TorRelayTransport TorIssuerTransport EntitlementCrypto"
OTHER_JNI_PREFIX="Java_org_ghost_network_"
# A JNI symbol is allowed when it is `DmNative`'s, `DmEquivalence`'s (decided by the halves below)
# or one of the network classes'. Prints the symbols of stdin that are none of these.
foreign_jni() {
  local classes
  classes="$(printf '%s|' $OTHER_JNI_CLASSES)"
  classes="${classes%|}"
  grep -vE "^(${PREFIX}|${ENTRY_PREFIX}|${OTHER_JNI_PREFIX}(${classes})_)" || true
}
# The Android tree the source-set half reads (self-test hook: GHOST_DM_JNI_ANDROID).
ANDROID_TREE="${GHOST_DM_JNI_ANDROID:-$GHOST_ROOT/android}"

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
  prune+=(-not -path '*/test-harness/*')
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

# Every other JNI entry point of the scan root, under any class (GATES-3): `pub extern "system" fn
# Java_…` whatever attributes precede it, and an `export_name` that spells one.
{
  if [ -d "$SCAN" ]; then
    find "$SCAN" -name '*.rs' "${prune[@]}" -exec \
      grep -ohE 'pub extern "system" fn Java_[A-Za-z0-9_]+|export_name *= *"Java_[A-Za-z0-9_]+' {} + || true
  else
    grep -ohE 'pub extern "system" fn Java_[A-Za-z0-9_]+|export_name *= *"Java_[A-Za-z0-9_]+' "$SCAN" "$SOURCE" || true
  fi
} | grep -oE 'Java_[A-Za-z0-9_]+' | sort -u | foreign_jni > "$work/foreign-source"
while read -r symbol; do
  [ -n "$symbol" ] || continue
  fail "the workspace exports the JNI entry point '$symbol', which is neither DmNative's closed list nor the network surface (G-R6)"
done < "$work/foreign-source"

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

# No other native declaration in a production source set (GATES-3): an `external fun` (Kotlin) or a
# `native` method (Java) anywhere but DmNative.kt and the network classes' own files. Without it a
# second class in `:crypto-bridge` — `DmDebug.exportSessionState` — needed no closed-list entry and
# was not `DmNative` for the reference rule below, so `:messaging` could call it directly.
if [ -d "$ANDROID_TREE" ]; then
  while IFS= read -r f; do
    [ -n "$f" ] || continue
    case "$f" in
      */crypto-bridge/src/main/kotlin/org/ghost/crypto/bridge/DmNative.kt) continue ;;
    esac
    allowed=0
    for class in $OTHER_JNI_CLASSES; do
      case "$f" in */network/src/main/kotlin/org/ghost/network/"$class".kt) allowed=1 ;; esac
    done
    [ "$allowed" = 1 ] && continue
    while IFS= read -r v; do
      [ -n "$v" ] && fail "$v"
    done < <(awk '
      { t = $0; sub(/^[ \t]+/, "", t)
        if (t ~ /^(\*|\/\/|\/\*)/) next
        if ($0 ~ /(^|[^A-Za-z0-9_])external[ \t]+fun[ \t]/ || (FILENAME ~ /\.java$/ && $0 ~ /(^|[ \t])native[ \t]/))
          print FILENAME ":" FNR ": declares a native method outside DmNative and the network classes (G-R6)"
      }' "$f")
  done < <(find "$ANDROID_TREE" -path '*/build' -prune -o -type f \( -name '*.kt' -o -name '*.java' \) \
             \( -path '*/src/main/*' -o -path '*/src/release/*' -o -path '*/src/gate/*' \) -print 2>/dev/null || true)
fi

# Only `:crypto-bridge`'s `main` and `gate` source sets reference `DmNative` (see the header). Code
# lines only: the design's KDoc across `:messaging` names `DmNative` on purpose.
if [ -d "$ANDROID_TREE" ]; then
  refs=()
  while IFS= read -r f; do
    [ -n "$f" ] || continue
    case "$f" in
      */crypto-bridge/src/main/*|*/crypto-bridge/src/gate/*) continue ;;
    esac
    refs+=("$f")
  done < <(find "$ANDROID_TREE" -path '*/build' -prune -o -type f \( -name '*.kt' -o -name '*.java' \) \
             \( -path '*/src/main/*' -o -path '*/src/release/*' -o -path '*/src/gate/*' \) -print 2>/dev/null || true)
  if [ "${#refs[@]}" -gt 0 ]; then
    while IFS= read -r v; do
      [ -n "$v" ] && fail "$v"
    done < <(awk '
      { line = $0
        t = line; sub(/^[ \t]+/, "", t)
        if (t ~ /^(\*|\/\/|\/\*)/) next
        sub(/[ \t]\/\/.*$/, "", line)
        if (line ~ /(^|[^A-Za-z0-9_])DmNative([^A-Za-z0-9_]|$)/)
          print FILENAME ":" FNR ": references DmNative outside :crypto-bridge src/{main,gate} (G-R6: go through the typed facade)"
      }' "${refs[@]}")
  fi
fi

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
printf '%s\n' $ENTRY_NAMES | sort -u > "$work/entry-expected"
TEST_LIBRARY=0
for LIBRARY in "$@"; do
  if [ "$LIBRARY" = "--test" ]; then
    TEST_LIBRARY=1
    continue
  fi
  is_test="$TEST_LIBRARY"
  TEST_LIBRARY=0
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
    # Any other JNI symbol of the library, under any class (GATES-3).
    grep -oE 'Java_[A-Za-z0-9_]+' "$work/nm-out" | sort -u | foreign_jni > "$work/foreign-symbols"
    while read -r symbol; do
      [ -n "$symbol" ] || continue
      fail "$LIBRARY exports the JNI symbol '$symbol', which is neither DmNative's closed list nor the network surface (G-R6)"
    done < "$work/foreign-symbols"
    # The test-vectors entry points: exactly their symbols in a test library, none in a shipped
    # one (§22.8.10 point 6, §22.37).
    grep -oE "${ENTRY_PREFIX}[A-Za-z0-9]+" "$work/nm-out" \
      | sed -E "s/${ENTRY_PREFIX}//" | sort -u > "$work/entry-symbols" || true
    if [ "$is_test" = 1 ]; then
      while read -r name; do
        [ -n "$name" ] || continue
        fail "test library $LIBRARY exports 'DmEquivalence.$name', which is not the test-vectors entry point"
      done < <(comm -23 "$work/entry-symbols" "$work/entry-expected")
      while read -r name; do
        [ -n "$name" ] || continue
        fail "test library $LIBRARY does not export the test-vectors entry point 'DmEquivalence.$name'"
      done < <(comm -13 "$work/entry-symbols" "$work/entry-expected")
    else
      while read -r name; do
        [ -n "$name" ] || continue
        fail "$LIBRARY exports the test-vectors entry point 'DmEquivalence.$name': a shipped library never carries it"
      done < "$work/entry-symbols"
    fi
  fi
done
[ "$TEST_LIBRARY" = 0 ] || fail "--test names no library"

finish dm-jni-surface
