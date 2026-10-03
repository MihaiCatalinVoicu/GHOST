#!/usr/bin/env bash
# Gate G-M6 (Phase 10 design faza10-forum.md §10.2, §13.1; ADR-19, ADR-40; slice S2b): the channel
# JNI surface `org.ghost.crypto.bridge.MlsNative` is a **closed list** — G-R6's method
# (`dm-jni-surface.sh`) applied to the channel surface.
#
#   the exported `Java_org_ghost_crypto_bridge_MlsNative_*` symbols of the shipped library equal
#   §10.2's list minus the reserved function 16; the host library's equal that plus its one test
#   entry (`MlsVectors.run`)
#
# The list is the Rust constant `CLOSED_LIST` of `client-core/mls/src/jni.rs`, so the gate and the
# code cannot drift. Entries marked `Availability::Declared("Sn")` are **reserved**: function 16
# (`revealSeal`, `revealOpen`, the reveal of §6.9) is slice S9's, and a build that writes or exports
# it early fails here, as does any symbol the list does not name.
#
# Halves:
#   1. **Sources.** Every `MlsNative` entry point the workspace writes is on the list and marked
#      `Exported`, and every `Exported` entry is written; the test entry point is written with
#      exactly its one name (`MlsVectors.run`); and no JNI entry point of any class outside
#      `common.sh`'s GHOST_JNI_CLASSES is written anywhere (the list the DM gate reads too, so the
#      two gates agree on what is allowed).
#   2. **Kotlin.** `MlsNative.kt` declares exactly the exported names, each `internal` with its
#      `@JvmName` (Kotlin mangles an internal member's JVM name). No production Android source set
#      (`src/main`, `src/release`, `src/gate`) declares a native method outside GHOST_JNI_NATIVE_FILES
#      — so `MlsVectors`, the test entry's declaration, lives in `:crypto-bridge`'s `src/test` only —
#      and only `:crypto-bridge`'s `src/main` references `MlsNative` (everyone else goes through the
#      typed facade `ChannelCrypto`); code lines only, the design's KDoc may name it.
#   3. **Libraries** (ELF, read with `llvm-nm -D --defined-only`, else `nm`): a shipped library
#      exports exactly the exported names and no `MlsVectors` symbol; a library passed with `--test`
#      exports exactly the exported names plus `MlsVectors.run`; a reserved name exported is reported
#      as such; any JNI symbol of a class outside GHOST_JNI_CLASSES fails; a reader that cannot read
#      the library fails (it is not "the library is wrong"); a non-ELF library (the owner's MSVC
#      `.dll`) is reported as skipped, never as passing or failing.
#
# Usage: mls-jni-surface.sh [[--test] <library> ...]
#   <library>  `android-native` passes every shipped `libghost_client_net.so`; the `android` job
#              passes the `ghost-dm-host` build with `--test`. Without one the symbol half is
#              skipped and the source halves still run.
# Self-test hooks: GHOST_MLS_JNI_SOURCE, GHOST_MLS_JNI_KOTLIN, GHOST_MLS_JNI_SCAN, GHOST_MLS_JNI_ANDROID
# and GHOST_MLS_JNI_NM (the symbol reader: the fixtures in `test-harness/gates/mls-jni/nm/` print a
# shipped list, a test list, one symbol too many or too few, the reserved function, or fail).
source "$(dirname "${BASH_SOURCE[0]}")/common.sh"
SOURCE="${GHOST_MLS_JNI_SOURCE:-$GHOST_ROOT/client-core/mls/src/jni.rs}"
KOTLIN="${GHOST_MLS_JNI_KOTLIN:-$GHOST_ROOT/android/crypto-bridge/src/main/kotlin/org/ghost/crypto/bridge/MlsNative.kt}"
if [ -n "${GHOST_MLS_JNI_SOURCE:-}" ]; then SCAN_DEFAULT="$SOURCE"; else SCAN_DEFAULT="$GHOST_ROOT"; fi
SCAN="${GHOST_MLS_JNI_SCAN:-$SCAN_DEFAULT}"
ANDROID_TREE="${GHOST_MLS_JNI_ANDROID:-$GHOST_ROOT/android}"
PREFIX="Java_org_ghost_crypto_bridge_MlsNative_"
ENTRY_PREFIX="Java_org_ghost_crypto_bridge_MlsVectors_"
ENTRY_NAMES="run"

[ -f "$SOURCE" ] || { echo "channel JNI source not found: $SOURCE" >&2; exit 2; }
[ -f "$KOTLIN" ] || { echo "MlsNative.kt not found: $KOTLIN" >&2; exit 2; }

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

# The closed list: `(n, "name", Availability::…)` lines of the Rust constant.
grep -oE '\([0-9]+, "[A-Za-z0-9]+", Availability::(Exported|Declared\("[A-Za-z0-9]+"\))\)' "$SOURCE" \
  > "$work/entries" || true
[ -s "$work/entries" ] || { fail "no closed-list entries read from $SOURCE"; finish mls-jni-surface; }
sed -E 's/^\([0-9]+, "([A-Za-z0-9]+)".*$/\1/' "$work/entries" | sort -u > "$work/declared"
grep 'Availability::Exported' "$work/entries" | sed -E 's/^\([0-9]+, "([A-Za-z0-9]+)".*$/\1/' | sort -u > "$work/expected"
grep 'Availability::Declared' "$work/entries" | sed -E 's/^\([0-9]+, "([A-Za-z0-9]+)".*$/\1/' | sort -u > "$work/reserved"
[ -s "$work/expected" ] || fail "no Exported entry on the closed list of $SOURCE (the gate would pass vacuously)"
printf '%s\n' $ENTRY_NAMES | sort -u > "$work/entry-expected"

# ---- half 1: the sources ----------------------------------------------------------------------
# Build outputs are pruned, not filtered (a developer tree's `target/` holds every dependency's
# sources), and the gates' own fixtures unless a fixture is the scan root.
prune=(-name target -o -name build -o -name .gradle)
[ -n "${GHOST_MLS_JNI_SCAN:-}" ] || prune+=(-o -name test-harness)
rust_sources() { # every Rust file the halves read: the scan root (a directory or one file) and $SOURCE
  if [ -d "$SCAN" ]; then
    find "$SCAN" -type d \( "${prune[@]}" \) -prune -o -type f -name '*.rs' -print
  elif [ "$SCAN" != "$SOURCE" ]; then
    printf '%s\n' "$SCAN"
  fi
  printf '%s\n' "$SOURCE"
}
rust_sources | sort -u > "$work/rust-files"
# Every JNI entry point the Rust sources write (`pub extern "system" fn Java_…` whatever attributes
# precede it, and an `export_name` that spells one), read in one batch.
tr '\n' '\0' < "$work/rust-files" \
  | xargs -0 grep -ohE 'pub extern "system" fn Java_[A-Za-z0-9_]+|export_name *= *"Java_[A-Za-z0-9_]+' 2>/dev/null \
  | grep -oE 'Java_[A-Za-z0-9_]+' | sort -u > "$work/jni-source" || true
emitted_names() { # $1 = symbol prefix: the names written after it in an entry point, sorted
  { grep -E "^${1}" "$work/jni-source" || true; } | sed -E "s/^${1}//" | sort -u
}
emitted_names "$PREFIX" > "$work/emitted"
emitted_names "$ENTRY_PREFIX" > "$work/entry-emitted"

while read -r name; do
  [ -n "$name" ] || continue
  fail "the workspace exports 'MlsNative.$name', which is not on the closed list of §10.2 ($SOURCE; scanned $SCAN)"
done < <(comm -23 "$work/emitted" "$work/declared")
while read -r name; do
  [ -n "$name" ] || continue
  fail "'MlsNative.$name' is reserved on the closed list (a later slice's: Declared) but the workspace already writes its entry point"
done < <(comm -12 "$work/emitted" "$work/reserved")
while read -r name; do
  [ -n "$name" ] || continue
  fail "'MlsNative.$name' is marked Exported on the closed list but the workspace writes no entry point for it"
done < <(comm -23 "$work/expected" "$work/emitted")
while read -r name; do
  [ -n "$name" ] || continue
  fail "the workspace writes the test entry point 'MlsVectors.$name', which is not the one test entry ($ENTRY_NAMES)"
done < <(comm -23 "$work/entry-emitted" "$work/entry-expected")
while read -r name; do
  [ -n "$name" ] || continue
  fail "the workspace writes no test entry point 'MlsVectors.$name' (the JDK vector replay needs it)"
done < <(comm -13 "$work/entry-emitted" "$work/entry-expected")
# Every other JNI entry point of the sources, under any class: one list for both surface gates.
jni_foreign < "$work/jni-source" > "$work/foreign-source"
while read -r symbol; do
  [ -n "$symbol" ] || continue
  fail "the workspace exports the JNI entry point '$symbol', which is not a class of the JNI surfaces (common.sh GHOST_JNI_CLASSES; G-M6)"
done < "$work/foreign-source"

# ---- half 2: Kotlin ------------------------------------------------------------------------------
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
    public) fail "MlsNative declares 'external fun $name' outside the module: it must be internal" ;;
    unpinned) fail "MlsNative's internal 'external fun $name' has no @JvmName(\"$name\"): Kotlin would mangle the JNI name" ;;
  esac
done < "$work/visibility"
{ grep -oE 'external fun [A-Za-z0-9]+' "$KOTLIN" || true; } | sed -E 's/external fun //' | sort -u > "$work/kotlin"
while read -r name; do
  [ -n "$name" ] || continue
  if grep -qx "$name" "$work/reserved"; then
    fail "MlsNative declares 'external fun $name', which is reserved for a later slice (Declared on the closed list)"
  else
    fail "MlsNative declares 'external fun $name', which the crate does not export"
  fi
done < <(comm -23 "$work/kotlin" "$work/expected")
while read -r name; do
  [ -n "$name" ] || continue
  fail "MlsNative does not declare 'external fun $name', which the crate exports"
done < <(comm -13 "$work/kotlin" "$work/expected")
# No native declaration outside the allowed files, in any production source set.
while IFS= read -r v; do
  [ -n "$v" ] && fail "$v"
done < <(jni_stray_natives "$ANDROID_TREE" "MlsNative, DmNative and the network classes (G-M6)")
# Only `:crypto-bridge`'s src/main references MlsNative (code lines; the design's KDoc names it).
if [ -d "$ANDROID_TREE" ]; then
  refs=()
  while IFS= read -r f; do
    [ -n "$f" ] || continue
    case "$f" in */crypto-bridge/src/main/*) continue ;; esac
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
        if (line ~ /(^|[^A-Za-z0-9_])MlsNative([^A-Za-z0-9_]|$)/)
          print FILENAME ":" FNR ": references MlsNative outside :crypto-bridge src/main (G-M6: go through the typed facade ChannelCrypto)"
      }' "${refs[@]}")
  fi
fi

# ---- half 3: the built libraries ------------------------------------------------------------------
if [ -n "${GHOST_MLS_JNI_NM:-}" ]; then NM="$GHOST_MLS_JNI_NM"
elif command -v llvm-nm >/dev/null; then NM=llvm-nm
elif command -v nm >/dev/null; then NM=nm
else NM=""; fi
TEST_LIBRARY=0
read_libraries=0
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
    echo "[mls-jni-surface] symbol check skipped: $LIBRARY is not ELF (${NM:-nm} -D cannot read it)" >&2
  elif [ -z "$NM" ]; then
    fail "neither llvm-nm nor nm found: the symbol check of an ELF library needs one of them"
  elif ! "$NM" -D --defined-only "$LIBRARY" > "$work/nm-out" 2> "$work/nm-err"; then
    fail "$NM could not read $LIBRARY: $(head -n 1 "$work/nm-err")"
  else
    read_libraries=$((read_libraries + 1))
    { grep -oE "${PREFIX}[A-Za-z0-9_]+" "$work/nm-out" || true; } | sed -E "s/^${PREFIX}//" | sort -u > "$work/symbols"
    while read -r name; do
      [ -n "$name" ] || continue
      if grep -qx "$name" "$work/reserved"; then
        fail "$LIBRARY exports 'MlsNative.$name', which is reserved for a later slice (function 16 is S9's)"
      else
        fail "$LIBRARY exports 'MlsNative.$name', which is not on the closed list"
      fi
    done < <(comm -23 "$work/symbols" "$work/expected")
    while read -r name; do
      [ -n "$name" ] || continue
      fail "$LIBRARY does not export 'MlsNative.$name', which the closed list marks Exported"
    done < <(comm -13 "$work/symbols" "$work/expected")
    { grep -oE 'Java_[A-Za-z0-9_]+' "$work/nm-out" || true; } | sort -u | jni_foreign > "$work/foreign-symbols"
    while read -r symbol; do
      [ -n "$symbol" ] || continue
      fail "$LIBRARY exports the JNI symbol '$symbol', which is not a class of the JNI surfaces (common.sh GHOST_JNI_CLASSES; G-M6)"
    done < "$work/foreign-symbols"
    { grep -oE "${ENTRY_PREFIX}[A-Za-z0-9_]+" "$work/nm-out" || true; } | sed -E "s/^${ENTRY_PREFIX}//" | sort -u > "$work/entry-symbols"
    if [ "$is_test" = 1 ]; then
      while read -r name; do
        [ -n "$name" ] || continue
        fail "test library $LIBRARY exports 'MlsVectors.$name', which is not its one test entry point"
      done < <(comm -23 "$work/entry-symbols" "$work/entry-expected")
      while read -r name; do
        [ -n "$name" ] || continue
        fail "test library $LIBRARY does not export the test entry point 'MlsVectors.$name'"
      done < <(comm -13 "$work/entry-symbols" "$work/entry-expected")
    else
      while read -r name; do
        [ -n "$name" ] || continue
        fail "$LIBRARY exports the test entry point 'MlsVectors.$name': a shipped library never carries it"
      done < "$work/entry-symbols"
    fi
    echo "[mls-jni-surface] $LIBRARY: $(grep -c . "$work/symbols" || true) MlsNative symbols, $(grep -c . "$work/entry-symbols" || true) test entry ($([ "$is_test" = 1 ] && echo test || echo shipped))"
  fi
done
[ "$TEST_LIBRARY" = 0 ] || fail "--test names no library"
echo "[mls-jni-surface] closed list: $(grep -c . "$work/expected") exported, $(grep -c . "$work/reserved" || true) reserved; $read_libraries library/libraries read"
finish mls-jni-surface
