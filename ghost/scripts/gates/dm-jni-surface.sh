#!/usr/bin/env bash
# Gate G-R6 (Phase 9 design §2.6, §2.3): the DM JNI surface is a **closed list**. Gains G-M5's
# second list in slice S2 (Phase 11 design §13.2): the media surface `MediaNative` is checked by
# the same two directions, from the same workspace scan and the same library arguments.
#
# Two directions, both checked (for each of the two closed lists):
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
# every library read here may carry a JNI entry point only of the classes `common.sh` lists in
# `GHOST_JNI_CLASSES` — `DmNative` (the closed list), `DmEquivalence.run`, `.bindingHooks`,
# `.stateWrapHook` and `.sidecarLogHook` (test libraries and `src/equivalence` only), the channel
# surface `MlsNative` and its test entry `MlsVectors` (Phase 10 slice S2b, checked exactly by G-M6,
# `mls-jni-surface.sh`) and the three classes of the network surface (Phases 6 and 8) — and a native
# method may be declared only in the files of `GHOST_JNI_NATIVE_FILES`. One list for both surface
# gates, so they agree on what is allowed; a new class is a change to it, which is what makes it
# arrive deliberately.
#
# **The test-vectors entry points** (§15.9 item 7, §22.8.10 point 6; slice S12) are the symbols a
# *test* library adds: `Java_org_ghost_crypto_bridge_DmEquivalence_run`, since §22.37
# `…_DmEquivalence_bindingHooks` (MC-20's mutant and KC5b's replayed binding, switched per DM
# context) and since §22.38 `…_DmEquivalence_stateWrapHook` and `…_DmEquivalence_sidecarLogHook`
# (ME-24's and MC-30's mutants, each switched per DM context), compiled only with
# `ghost-client-dm`'s `test-vectors` feature, which only
# `ghost-dm-host` enables. **The media surface's two** (Phase 11 design §13.2, §15.6; slice S2)
# are `…_MediaNative_testVectors` and `…_MediaNative_testSealBeginWithKey`, the same feature, the
# same host-only rule (G-M5). A library passed as `--test <library>` must export exactly the two
# closed lists plus those test symbols; every other library is a shipped one and must export no
# test symbol at all.
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
ENTRY_NAMES="run bindingHooks stateWrapHook sidecarLogHook"
# A JNI symbol of a class outside `common.sh`'s GHOST_JNI_CLASSES (`DmNative`'s and `DmEquivalence`'s
# are decided by the halves below, the channel surface's by G-M6). Prints the symbols of stdin that
# belong to none of them.
foreign_jni() { jni_foreign; }
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
# Rust source of the scan root, so an entry point written by hand somewhere else is caught too. Read
# as code by common.sh's jni_source_symbols — any `fn Java_…` whatever its qualifiers (`unsafe`,
# `extern "C"`, no `pub`) or line breaks, and any string literal that is a `Java_…` symbol — over
# jni_rust_files, which prunes a `target` or `build` directory only outside `src/` (review of S2b:
# the first readers matched `pub extern "system" fn` on one line and filtered every `*/target/*`).
fixtures=""
[ -z "${GHOST_DM_JNI_SCAN:-}" ] || fixtures=with-fixtures
{ printf '%s\n' "$SOURCE"; jni_rust_files "$SCAN" "$fixtures"; } | sort -u > "$work/rust-files"
if ! jni_source_symbols < "$work/rust-files" > "$work/jni-scan"; then
  fail "the JNI source reader (perl) failed: the source half is unproven"
fi
read_n="$(sed -n 's/^JNI-FILES-READ //p' "$work/jni-scan")"
[ "${read_n:-0}" -gt 0 ] || fail "the JNI source reader read no Rust file (the source half would pass vacuously)"
{ grep -v '^JNI-FILES-READ ' "$work/jni-scan" || true; } | sort -u > "$work/jni-source"
{ grep -E "^${PREFIX}" "$work/jni-source" || true; } | sed -E "s/^${PREFIX}//" | sort -u > "$work/emitted"

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

# Every other JNI entry point of the scan root, under any class (GATES-3), from the same reading.
foreign_jni < "$work/jni-source" > "$work/foreign-source"
while read -r symbol; do
  [ -n "$symbol" ] || continue
  fail "the workspace exports the JNI entry point '$symbol', which is not a class of the JNI surfaces (common.sh GHOST_JNI_CLASSES; G-R6)"
done < "$work/foreign-source"

# Kotlin declares exactly the exported names, and declares them `internal` with an explicit
# `@JvmName`: `:messaging` must go through the typed facade (§2.6, §13.1), and Kotlin mangles an
# internal member's JVM name (`ctxClose` -> `ctxClose$crypto_bridge`), which no JNI symbol matches.
# Both halves are checked, so tightening the visibility cannot turn into an UnsatisfiedLinkError on
# a device, and loosening it cannot slip past review. A `@JvmName` and its declaration may share a
# line, which is read for both (review of S2b: a `next` here skipped the declaration).
awk '
  match($0, /@JvmName\("[A-Za-z0-9]+"\)/) {
    pinned = substr($0, RSTART + 10, RLENGTH - 12); pinned_line = NR
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

# -------------------------------------------------------------------------------------------
# G-M5: the media surface `MediaNative` (Phase 11 design §13.2) — the gate's second closed list.
# The list is the Rust constant `MEDIA_CLOSED_LIST` of `jni_media.rs`, so this half and the code
# cannot drift, exactly as the DM half's `CLOSED_LIST` is its source of truth. The two host-only
# entries (`testVectors`, `testSealBeginWithKey`) are not on the shipped list: like
# `DmEquivalence`'s, they may exist only in test libraries, which the library half below checks.
# Self-test hooks: GHOST_DM_JNI_MEDIA_SOURCE and GHOST_DM_JNI_MEDIA_KOTLIN, the same pattern as
# the DM halves' hooks.
MEDIA_SOURCE="${GHOST_DM_JNI_MEDIA_SOURCE:-$GHOST_ROOT/client-core/dm/src/jni_media.rs}"
MEDIA_KOTLIN="${GHOST_DM_JNI_MEDIA_KOTLIN:-$GHOST_ROOT/android/crypto-bridge/src/main/kotlin/org/ghost/crypto/bridge/MediaNative.kt}"
MEDIA_PREFIX="Java_org_ghost_crypto_bridge_MediaNative_"
MEDIA_TEST_NAMES="testVectors testSealBeginWithKey"

[ -f "$MEDIA_SOURCE" ] || { echo "Media JNI source not found: $MEDIA_SOURCE" >&2; exit 2; }
[ -f "$MEDIA_KOTLIN" ] || { echo "MediaNative.kt not found: $MEDIA_KOTLIN" >&2; exit 2; }

# The media list, from the Rust constant: `(n, "name")` rows of `MEDIA_CLOSED_LIST`. The slice
# stops at the constant's closing `];`, so `MEDIA_TEST_LIST`'s rows (the host-only entries,
# checked against built libraries below and kept out of shipped graphs by G-R2) do not leak into
# the shipped list.
sed -n '/pub const MEDIA_CLOSED_LIST/,/^]/p' "$MEDIA_SOURCE" \
  | grep -oE '\([0-9]+, "[A-Za-z0-9]+"\)' | sed -E 's/^\([0-9]+, "([A-Za-z0-9]+)"\)$/\1/' \
  | sort -u > "$work/media-declared"
[ -s "$work/media-declared" ] || { fail "no media closed-list entries read from $MEDIA_SOURCE"; finish dm-jni-surface; }

# Names the media export macros really emit, from the same whole-workspace scan as the DM half.
# The two host-only entries are written in `export_media_test_jni!`'s body like
# `DmEquivalence`'s are; whether they are *built* is the library half's and G-R2's question, so
# the source emission check excludes them here.
{ grep -E "^${MEDIA_PREFIX}" "$work/jni-source" || true; } | sed -E "s/^${MEDIA_PREFIX}//" \
  | grep -vE "^test" | sort -u > "$work/media-emitted"
printf '%s\n' $MEDIA_TEST_NAMES | sort -u > "$work/media-test-names"

while read -r name; do
  [ -n "$name" ] || continue
  fail "the workspace exports MediaNative.$name, which is not on §13.2's list ($MEDIA_SOURCE; scanned $SCAN)"
done < <(comm -23 "$work/media-emitted" "$work/media-declared")
while read -r name; do
  [ -n "$name" ] || continue
  fail "'$name' is on §13.2's media list but the crate emits no entry point for it"
done < <(comm -23 "$work/media-declared" "$work/media-emitted")

# Kotlin declares exactly the shipped names, internal with an explicit @JvmName — the same
# facade rule as DmNative. The two test entries have no production declarations until the JVM
# tests of the later slices land them in a test source set (the `MlsVectors` precedent), so
# they are compared against the workspace's Rust emission only, not against this file.
# The two entries ARE declared on `MediaNative` itself: §13.2 names them `MediaNative.testVectors`
# / `MediaNative.testSealBeginWithKey`, and the JNI symbol pins the declaring class, so unlike
# `DmEquivalence`'s they have no test-only class to live on and their declarations sit in this
# production file (inert on a device: a shipped library exports no such symbol, which the
# library half below checks). They are excluded from the Kotlin-vs-list comparison below,
# exactly as the Rust emission half above excludes `^test` names; the library half still
# checks precisely their two symbols in a test library and none in a shipped one (the JVM
# tests of slice S2 are their only caller and load the host build).
awk -v file="MediaNative" '
  match($0, /@JvmName\("[A-Za-z0-9]+"\)/) {
    pinned = substr($0, RSTART + 10, RLENGTH - 12); pinned_line = NR
  }
  match($0, /external fun [A-Za-z0-9]+/) {
    name = substr($0, RSTART + 13, RLENGTH - 13)
    if ($0 !~ /internal external fun/) { print "public " name; next }
    if (pinned != name || NR - pinned_line > 2) { print "unpinned " name }
  }
' "$MEDIA_KOTLIN" > "$work/media-visibility"
while read -r kind name; do
  [ -n "$name" ] || continue
  case "$kind" in
    public) fail "MediaNative declares 'external fun $name' outside the module: it must be internal" ;;
    unpinned) fail "MediaNative's internal 'external fun $name' has no @JvmName(\"$name\"): Kotlin would mangle the JNI name" ;;
  esac
done < "$work/media-visibility"

grep -oE 'external fun [A-Za-z0-9]+' "$MEDIA_KOTLIN" | sed -E 's/external fun //' | grep -vE '^test' | sort -u > "$work/media-kotlin"
while read -r name; do
  [ -n "$name" ] || continue
  fail "MediaNative declares 'external fun $name', which the crate does not export for a shipped library"
done < <(comm -23 "$work/media-kotlin" "$work/media-declared")
while read -r name; do
  [ -n "$name" ] || continue
  fail "MediaNative does not declare 'external fun $name', which §13.2's list marks shipped"
done < <(comm -13 "$work/media-kotlin" "$work/media-declared")

# -------------------------------------------------------------------------------------------
# G-D5: the update surface (Phase 14 design §9.3; G-R6 extended) — `UpdateNative`'s and
# `TorMirrorTransport`'s closed lists, the gate's third closed-list family. The lists are the
# Rust constants `CLOSED_UPDATE` / `CLOSED_MIRROR` of `client-core/net/src/update.rs`, so the
# gate and the code cannot drift, exactly as the DM and media halves. The two classes live on
# the network tree (like `TorRelayTransport`), so their Kotlin declarations are `private
# external fun` — the internal/@JvmName rule of §2.6 is `:crypto-bridge`'s facade rule and does
# not apply to the network classes; the name-set comparison below is still both directions.
# Self-test hooks: GHOST_DM_JNI_UPDATE_SOURCE, GHOST_DM_JNI_UPDATE_KOTLIN and
# GHOST_DM_JNI_MIRROR_KOTLIN, the same pattern as the halves above.
UPDATE_SOURCE="${GHOST_DM_JNI_UPDATE_SOURCE:-$GHOST_ROOT/client-core/net/src/update.rs}"
UPDATE_KOTLIN="${GHOST_DM_JNI_UPDATE_KOTLIN:-$GHOST_ROOT/android/network/src/main/kotlin/org/ghost/network/UpdateNative.kt}"
MIRROR_KOTLIN="${GHOST_DM_JNI_MIRROR_KOTLIN:-$GHOST_ROOT/android/network/src/main/kotlin/org/ghost/network/TorMirrorTransport.kt}"
UPDATE_PREFIX="Java_org_ghost_network_UpdateNative_"
MIRROR_PREFIX="Java_org_ghost_network_TorMirrorTransport_"
MUTANTS_PREFIX="Java_org_ghost_network_UpdateMutants_"

[ -f "$UPDATE_SOURCE" ] || { echo "Update JNI source not found: $UPDATE_SOURCE" >&2; exit 2; }
[ -f "$UPDATE_KOTLIN" ] || { echo "UpdateNative.kt not found: $UPDATE_KOTLIN" >&2; exit 2; }
[ -f "$MIRROR_KOTLIN" ] || { echo "TorMirrorTransport.kt not found: $MIRROR_KOTLIN" >&2; exit 2; }

# The lists, from the Rust constants (plain string arrays): `sed` stops at each constant's
# closing `];`, so the two lists cannot leak into each other.
sed -n '/pub const CLOSED_UPDATE/,/^]/p' "$UPDATE_SOURCE"   | grep -oE '"[A-Za-z0-9]+"' | tr -d '"' | sort -u > "$work/update-declared"
sed -n '/pub const CLOSED_MIRROR/,/^]/p' "$UPDATE_SOURCE"   | grep -oE '"[A-Za-z0-9]+"' | tr -d '"' | sort -u > "$work/mirror-declared"
[ -s "$work/update-declared" ] || { fail "no UpdateNative closed-list entries read from $UPDATE_SOURCE"; finish dm-jni-surface; }
[ -s "$work/mirror-declared" ] || { fail "no TorMirrorTransport closed-list entries read from $UPDATE_SOURCE"; finish dm-jni-surface; }

# Names the workspace really emits, from the same whole-workspace scan as the DM half.
{ grep -E "^${UPDATE_PREFIX}" "$work/jni-source" || true; } | sed -E "s/^${UPDATE_PREFIX}//"   | sort -u > "$work/update-emitted"
{ grep -E "^${MIRROR_PREFIX}" "$work/jni-source" || true; } | sed -E "s/^${MIRROR_PREFIX}//"   | sort -u > "$work/mirror-emitted"

while read -r name; do
  [ -n "$name" ] || continue
  fail "the workspace exports UpdateNative.$name, which is not on §9.3's list ($UPDATE_SOURCE; scanned $SCAN)"
done < <(comm -23 "$work/update-emitted" "$work/update-declared")
while read -r name; do
  [ -n "$name" ] || continue
  fail "'$name' is on §9.3's UpdateNative list but the crate emits no entry point for it"
done < <(comm -23 "$work/update-declared" "$work/update-emitted")
while read -r name; do
  [ -n "$name" ] || continue
  fail "the workspace exports TorMirrorTransport.$name, which is not on §9.3's list ($UPDATE_SOURCE; scanned $SCAN)"
done < <(comm -23 "$work/mirror-emitted" "$work/mirror-declared")
while read -r name; do
  [ -n "$name" ] || continue
  fail "'$name' is on §9.3's TorMirrorTransport list but the crate emits no entry point for it"
done < <(comm -23 "$work/mirror-declared" "$work/mirror-emitted")

# Kotlin declares exactly the list names, both directions, per class. The network classes use
# `private external fun` (the JNI symbol pins the class, and visibility does not change the
# symbol a dynamic lookup finds), so — unlike DmNative/MediaNative — no @JvmName check here.
grep -oE 'external fun [A-Za-z0-9]+' "$UPDATE_KOTLIN" | sed -E 's/external fun //' | sort -u > "$work/update-kotlin"
while read -r name; do
  [ -n "$name" ] || continue
  fail "UpdateNative declares 'external fun $name', which the crate does not export"
done < <(comm -23 "$work/update-kotlin" "$work/update-declared")
while read -r name; do
  [ -n "$name" ] || continue
  fail "UpdateNative does not declare 'external fun $name', which §9.3's list ships"
done < <(comm -13 "$work/update-kotlin" "$work/update-declared")
grep -oE 'external fun [A-Za-z0-9]+' "$MIRROR_KOTLIN" | sed -E 's/external fun //' | sort -u > "$work/mirror-kotlin"
while read -r name; do
  [ -n "$name" ] || continue
  fail "TorMirrorTransport declares 'external fun $name', which the crate does not export"
done < <(comm -23 "$work/mirror-kotlin" "$work/mirror-declared")
while read -r name; do
  [ -n "$name" ] || continue
  fail "TorMirrorTransport does not declare 'external fun $name', which §9.3's list ships"
done < <(comm -13 "$work/mirror-kotlin" "$work/mirror-declared")

# §11.3's mutant selector (slice S6c): the one `UpdateMutants` entry, both directions, from the
# same Rust constant the workspace scan is diffed against. No Kotlin half: no production source
# ever declares the class (its only caller is the JVM update world's test source, reaching the
# host library's symbol directly), like `DmEquivalence` before its test sources landed.
sed -n '/pub const TEST_MUTANT_SWITCHES/,/^]/p' "$UPDATE_SOURCE" | grep -oE '"[A-Za-z0-9]+"' | tr -d '"' | sort -u > "$work/mutants-declared"
[ -s "$work/mutants-declared" ] || { fail "no UpdateMutants selector entries read from $UPDATE_SOURCE"; finish dm-jni-surface; }
{ grep -E "^${MUTANTS_PREFIX}" "$work/jni-source" || true; } | sed -E "s/^${MUTANTS_PREFIX}//" | sort -u > "$work/mutants-emitted"
while read -r name; do
  [ -n "$name" ] || continue
  fail "the workspace exports UpdateMutants.$name, which is not §11.3's selector list ($UPDATE_SOURCE; scanned $SCAN)"
done < <(comm -23 "$work/mutants-emitted" "$work/mutants-declared")
while read -r name; do
  [ -n "$name" ] || continue
  fail "'$name' is on §11.3's UpdateMutants selector list but the crate emits no entry point for it"
done < <(comm -23 "$work/mutants-declared" "$work/mutants-emitted")

# No other native declaration in a production source set (GATES-3): an `external fun` (Kotlin) or a
# `native` method (Java) anywhere but the files of `common.sh`'s GHOST_JNI_NATIVE_FILES (DmNative.kt,
# MediaNative.kt, MlsNative.kt and the network classes' own files). Without it a second class in
# `:crypto-bridge` — `DmDebug.exportSessionState` — needed no closed-list entry and was not
# `DmNative` for the reference rule below, so `:messaging` could call it directly.
while IFS= read -r v; do
  [ -n "$v" ] && fail "$v"
done < <(jni_stray_natives "$ANDROID_TREE" "DmNative, MediaNative, MlsNative and the network classes (G-R6, G-M5)")

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
      fail "$LIBRARY exports the JNI symbol '$symbol', which is not a class of the JNI surfaces (common.sh GHOST_JNI_CLASSES; G-R6)"
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
    # G-M5's media half: exactly §13.2's list, and the two host-only entries exactly in a test
    # library, never in a shipped one. The shipped diff excludes the `^test` names — the source
    # half's and the Kotlin half's exclusion — or a test library's own two entries would read as
    # "not on §13.2's list" here while the check below requires them.
    grep -oE "${MEDIA_PREFIX}[A-Za-z0-9]+" "$work/nm-out" \
      | sed -E "s/${MEDIA_PREFIX}//" | grep -vE '^test' | sort -u > "$work/media-symbols" || true
    while read -r name; do
      [ -n "$name" ] || continue
      fail "$LIBRARY exports 'MediaNative.$name', which is not on §13.2's list"
    done < <(comm -23 "$work/media-symbols" "$work/media-declared")
    while read -r name; do
      [ -n "$name" ] || continue
      fail "$LIBRARY does not export 'MediaNative.$name', which §13.2's list ships"
    done < <(comm -13 "$work/media-symbols" "$work/media-declared")
    grep -oE "${MEDIA_PREFIX}test[A-Za-z0-9]+" "$work/nm-out" \
      | sed -E "s/${MEDIA_PREFIX}//" | sort -u > "$work/media-test-symbols" || true
    if [ "$is_test" = 1 ]; then
      while read -r name; do
        [ -n "$name" ] || continue
        fail "test library $LIBRARY exports 'MediaNative.$name', which is not a host-only media test entry"
      done < <(comm -23 "$work/media-test-symbols" "$work/media-test-names")
      while read -r name; do
        [ -n "$name" ] || continue
        fail "test library $LIBRARY does not export the host-only media entry 'MediaNative.$name' (§13.2, §15.6)"
      done < <(comm -13 "$work/media-test-symbols" "$work/media-test-names")
    else
      while read -r name; do
        [ -n "$name" ] || continue
        fail "$LIBRARY exports the host-only media entry 'MediaNative.$name': a shipped library never carries it (G-M5)"
      done < "$work/media-test-symbols"
    fi
    # G-D5's update half: exactly §9.3's two lists in every library (the lists themselves have
    # no host-only entries; a shipped and a test library carry the same set — §11.3's host-only
    # entry lives on `UpdateMutants`, checked below).
    grep -oE "${UPDATE_PREFIX}[A-Za-z0-9]+" "$work/nm-out"       | sed -E "s/${UPDATE_PREFIX}//" | sort -u > "$work/update-symbols" || true
    while read -r name; do
      [ -n "$name" ] || continue
      fail "$LIBRARY exports 'UpdateNative.$name', which is not on §9.3's list"
    done < <(comm -23 "$work/update-symbols" "$work/update-declared")
    while read -r name; do
      [ -n "$name" ] || continue
      fail "$LIBRARY does not export 'UpdateNative.$name', which §9.3's list ships"
    done < <(comm -13 "$work/update-symbols" "$work/update-declared")
    grep -oE "${MIRROR_PREFIX}[A-Za-z0-9]+" "$work/nm-out"       | sed -E "s/${MIRROR_PREFIX}//" | sort -u > "$work/mirror-symbols" || true
    while read -r name; do
      [ -n "$name" ] || continue
      fail "$LIBRARY exports 'TorMirrorTransport.$name', which is not on §9.3's list"
    done < <(comm -23 "$work/mirror-symbols" "$work/mirror-declared")
    while read -r name; do
      [ -n "$name" ] || continue
      fail "$LIBRARY does not export 'TorMirrorTransport.$name', which §9.3's list ships"
    done < <(comm -13 "$work/mirror-symbols" "$work/mirror-declared")
    # §11.3's mutant selector (slice S6c): `UpdateMutants.select` exactly in a test library —
    # a `--test` build is the `test-mutants` feature's only enabler (ghost-dm-host) — and never
    # in a shipped one, where the `mutants` feature cannot exist (G-D5, G-D6).
    grep -oE "${MUTANTS_PREFIX}[A-Za-z0-9]+" "$work/nm-out"      | sed -E "s/${MUTANTS_PREFIX}//" | sort -u > "$work/mutants-symbols" || true
    if [ "$is_test" = 1 ]; then
      while read -r name; do
        [ -n "$name" ] || continue
        fail "test library $LIBRARY exports 'UpdateMutants.$name', which is not §11.3's selector"
      done < <(comm -23 "$work/mutants-symbols" "$work/mutants-declared")
      while read -r name; do
        [ -n "$name" ] || continue
        fail "test library $LIBRARY does not export 'UpdateMutants.$name', §11.3's selector (the test-mutants feature)"
      done < <(comm -13 "$work/mutants-symbols" "$work/mutants-declared")
    else
      while read -r name; do
        [ -n "$name" ] || continue
        fail "$LIBRARY exports 'UpdateMutants.$name': a shipped library never carries §11.3's selector (G-D5)"
      done < "$work/mutants-symbols"
    fi
  fi
done
[ "$TEST_LIBRARY" = 0 ] || fail "--test names no library"

finish dm-jni-surface
