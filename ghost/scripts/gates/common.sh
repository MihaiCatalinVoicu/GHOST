#!/usr/bin/env bash
# Shared helpers for GHOST CI gates (ADR-10). Every gate:
#   - scans GHOST_ROOT (default: the ghost/ monorepo) and never legacy/ or build outputs
#   - exits 0 on pass, 1 on violation, 2 on usage error
#   - prints one line per violation as  path:line: message
set -euo pipefail
GATES_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GHOST_ROOT="${GHOST_ROOT:-$(cd "$GATES_DIR/../.." && pwd)}"
FAILURES=0

# T15 permission allowlist, shared by manifest-lint.sh (source manifests) and merged-manifest-lint.sh
# (the merged release manifest). Each entry needs an ADR reference:
#   RECEIVE_BOOT_COMPLETED, ACCESS_NETWORK_STATE: ADR-20 (persisted periodic sync job with a network
#   constraint, Phase 7 design §5.5).
T15_ALLOWED_PERMISSIONS='android.permission.INTERNET|android.permission.FOREGROUND_SERVICE|android.permission.FOREGROUND_SERVICE_DATA_SYNC|android.permission.POST_NOTIFICATIONS|android.permission.CAMERA|android.permission.USE_BIOMETRIC|android.permission.VIBRATE|android.permission.RECEIVE_BOOT_COMPLETED|android.permission.ACCESS_NETWORK_STATE'

fail() { echo "GATE-FAIL: $*" >&2; FAILURES=$((FAILURES + 1)); }
finish() {
  local name="$1"
  if [ "$FAILURES" -gt 0 ]; then echo "[$name] FAILED with $FAILURES violation(s)" >&2; exit 1; fi
  echo "[$name] OK"
}
# Source trees that are on the production path. Test sources are excluded on purpose. `src/release`
# is compiled into the release APK beside `src/main` (slice S12's `DmBranch.kt`; apk-no-debug-hooks.sh
# and dm-jni-surface.sh already read it), so every gate that reads the production path reads it too
# (Phase 9 review GATES-2: no-logging, kotlin-clearnet, anti-placeholder and dm-no-fts read
# `src/main` alone, and a file in `src/release` passed all four).
android_main_files() {
  find "$GHOST_ROOT/android" -path '*/build' -prune -o -type f \( -name '*.kt' -o -name '*.java' \) \
    \( -path '*/src/main/*' -o -path '*/src/release/*' \) -print 2>/dev/null || true
}
# The `gate` build type's source sets (Phase 9 design §21.13 point 7, ADR-34; slice S12): never
# released, but installed on the gate devices and part of the physical exit gate's evidence, so the
# production-path hygiene gates that say so (anti-placeholder.sh) read them too.
android_gate_files() {
  find "$GHOST_ROOT/android" -path '*/build' -prune -o -type f \( -name '*.kt' -o -name '*.java' \) -path '*/src/gate/*' -print 2>/dev/null || true
}
rust_src_files() {
  # test-harness/ is tooling, not the production path (its CLIs may print to the console).
  # Relay and client binary entry points (src/main.rs) print operator-facing constants and
  # configuration only; every library crate stays free of logging primitives. Under issuer/ every
  # crate is found at any depth (issuer/crates/*) and main.rs is not exempt: the issuer keeps no
  # logs at all (Phase 8 design §14.1, ADR-26).
  # Exact exemptions only (Phase 10 review of S2a, F4): the entry point is a crate's own
  # `src/main.rs` (a Cargo.toml next to that src/), not any file named main.rs (`src/x/main.rs` is a
  # module); a build directory is a `target` directory outside every src/, never `src/target/`.
  local f
  { find "$GHOST_ROOT/relay" "$GHOST_ROOT/client-core" -type d -name target -not -path '*/src/*' -prune \
      -o -type f -name '*.rs' -path '*/src/*' -print 2>/dev/null || true; } \
    | while IFS= read -r f; do
        case "$f" in
          */src/main.rs) [ -f "${f%/src/main.rs}/Cargo.toml" ] && continue ;;
        esac
        printf '%s\n' "$f"
      done
  find "$GHOST_ROOT/issuer" -type d -name target -not -path '*/src/*' -prune -o -type f -name '*.rs' -path '*/src/*' -print 2>/dev/null || true
}
manifest_files() {
  find "$GHOST_ROOT/android" -path '*/build' -prune -o -type f -name 'AndroidManifest.xml' -print 2>/dev/null || true
}
gradle_files() {
  find "$GHOST_ROOT/android" -path '*/build' -prune -o -type f \( -name '*.gradle.kts' -o -name 'libs.versions.toml' \) -print 2>/dev/null || true
}
# The JNI surfaces of GHOST's native libraries (Phase 9 G-R6, Phase 10 G-M6, Phase 11 G-M5; one
# list, so the surface gates agree on what is allowed and each checks its own classes exactly):
#   - `org.ghost.crypto.bridge.DmNative` (the DM closed list, dm-jni-surface.sh) and
#     `DmEquivalence` (its test libraries' entry points);
#   - `org.ghost.crypto.bridge.MediaNative` (the media closed list of Phase 11 design §13.2,
#     dm-jni-surface.sh's second list, G-M5); its test entries `MediaNative.testVectors` and
#     `MediaNative.testSealBeginWithKey` are host-library-only, like `MlsVectors`;
#   - `org.ghost.crypto.bridge.MlsNative` (the channel closed list, mls-jni-surface.sh) and
#     `MlsVectors` (its test library's entry point);
#   - the network surface of Phases 6 and 8 (`TorRelayTransport`, `TorIssuerTransport`,
#     `EntitlementCrypto`).
# A JNI entry point of any other class, in the workspace's sources or in a built library, fails both
# gates; a new class is a change to this list, which is what makes it arrive deliberately.
GHOST_JNI_CLASSES="org_ghost_crypto_bridge_DmNative org_ghost_crypto_bridge_DmEquivalence org_ghost_crypto_bridge_MediaNative org_ghost_crypto_bridge_MlsNative org_ghost_crypto_bridge_MlsVectors org_ghost_network_TorRelayTransport org_ghost_network_TorIssuerTransport org_ghost_network_EntitlementCrypto org_ghost_network_UpdateNative org_ghost_network_TorMirrorTransport"
# The production source files allowed to declare a native method (paths under android/): the two
# closed-list classes and the network classes. Test-only declarations (`DmEquivalence`, `MlsVectors`)
# live in test source sets, which no production half reads. `MediaNative`'s declarations are
# production (the surface ships); its two test entries (`testVectors`, `testSealBeginWithKey`)
# have no Kotlin declarations until the JVM tests of the later slices, exactly as `MlsVectors`
# had none before its replay landed.
GHOST_JNI_NATIVE_FILES="crypto-bridge/src/main/kotlin/org/ghost/crypto/bridge/DmNative.kt crypto-bridge/src/main/kotlin/org/ghost/crypto/bridge/MediaNative.kt crypto-bridge/src/main/kotlin/org/ghost/crypto/bridge/MlsNative.kt network/src/main/kotlin/org/ghost/network/TorRelayTransport.kt network/src/main/kotlin/org/ghost/network/TorIssuerTransport.kt network/src/main/kotlin/org/ghost/network/EntitlementCrypto.kt network/src/main/kotlin/org/ghost/network/UpdateNative.kt network/src/main/kotlin/org/ghost/network/TorMirrorTransport.kt"
# The Rust files the surface gates read under $1 (a directory, or one file): build outputs pruned —
# a `target` or `build` directory **outside every `src/`**, so a module directory of either name is
# code and is read (Phase 10 review of S2a F4, review of S2b) — and `.gradle`; the gates' own
# fixtures (`test-harness/`) too, unless $2 is "with-fixtures" (a fixture is the scan root). The one
# directory `spikes/` directly under the scan root is evidence tooling, not product (Phase 11 S0: the
# media spike has its own workspace and lock and a crash-probe crate that exports a `Java_…` symbol on
# purpose, to prove a native crash is contained): it is never linked into a shipped library, and what
# a built library exports is read by each gate's library half whatever its sources are. Only that one
# path is exempt: the same export in any other directory, `client-core/spikes/` included, still fails.
jni_rust_files() { # $1 = scan root, $2 = "with-fixtures" or empty
  local root="${1%/}" fixtures=(-o -name test-harness)
  [ "${2:-}" = with-fixtures ] && fixtures=()
  root="$(printf '%s' "$root" | sed 's/[][*?\\]/\\&/g')" # -path takes a pattern, a path is not one
  if [ -d "$1" ]; then
    find "$1" -type d \( \( -name target -o -name build \) -not -path '*/src/*' -o -name .gradle \
      -o -path "$root/spikes" "${fixtures[@]}" \) \
      -prune -o -type f -name '*.rs' -print 2>/dev/null || true
  elif [ -f "$1" ]; then
    printf '%s\n' "$1"
  fi
}
# Every JNI symbol a set of Rust files writes (G-R6, G-M6; review of S2b), read as code with every
# comment blanked (source-text.pl): a function named `Java_…` **whatever precedes its `fn`** —
# `pub` or not, `unsafe`, `extern "system"` or `extern "C"` — and wherever its name falls (a line
# break after `fn`, a raw identifier); and **a string literal that is exactly a `Java_…` symbol** (an
# `export_name`, or a macro argument that becomes one). S2b's first readers matched
# `pub extern "system" fn Java_…` and `export_name = "Java_…"` on one line, and five spellings the
# compiler exports passed them. Reads file paths on stdin, one per line; prints one symbol per line
# and then `JNI-FILES-READ <n>`; fails when perl does, so a caller can tell "nothing written" from
# "nothing read". A name computed at compile time (`concat!` in an attribute, a procedural macro) is
# not seen here: each gate's library half reads what the linker exported.
jni_source_symbols() {
  GATES="$GATES_DIR" perl -e '
    require "$ENV{GATES}/source-text.pl";
    my $n = 0;
    while (my $f = <STDIN>) {
      chomp $f;
      next unless length $f;
      my ($w) = views(read_text($f), "rust");
      $n++;
      print "$1\n" while $w =~ /\bfn\s+(?:r#)?(Java_[A-Za-z0-9_]+)/g;
      print "$1\n" while $w =~ /"(Java_[A-Za-z0-9_]+)"/g;
    }
    print "JNI-FILES-READ $n\n";'
}
# Prints the `Java_…` symbols of stdin that belong to no class of GHOST_JNI_CLASSES.
jni_foreign() {
  local alt
  alt="$(printf '%s|' $GHOST_JNI_CLASSES)"
  alt="${alt%|}"
  grep -vE "^Java_(${alt})_" || true
}
# Prints `<file>:<line>: declares a native method outside <who>` for every native declaration
# (Kotlin `external fun`, Java `native`) of the production source sets under $1 (`src/main`,
# `src/release`, `src/gate`) that is not in GHOST_JNI_NATIVE_FILES. Comment lines are skipped.
jni_stray_natives() { # $1 = android tree, $2 = the gate's wording for the allowed classes
  local tree="$1" who="$2" f rel allowed a
  [ -d "$tree" ] || return 0
  # One awk over every file (a process per file costs half a second on the Windows hosts).
  while IFS= read -r f; do
    [ -n "$f" ] || continue
    rel="${f#"$tree"/}"
    allowed=0
    for a in $GHOST_JNI_NATIVE_FILES; do
      [ "$rel" = "$a" ] && allowed=1
    done
    [ "$allowed" = 1 ] || printf '%s\0' "$f"
  done < <(find "$tree" -path '*/build' -prune -o -type f \( -name '*.kt' -o -name '*.java' \) \
             \( -path '*/src/main/*' -o -path '*/src/release/*' -o -path '*/src/gate/*' \) -print 2>/dev/null || true) \
    | xargs -0 -r awk -v who="$who" '
      { t = $0; sub(/^[ \t]+/, "", t)
        if (t ~ /^(\*|\/\/|\/\*)/) next
        if ($0 ~ /(^|[^A-Za-z0-9_])external[ \t]+fun[ \t]/ || (FILENAME ~ /\.java$/ && $0 ~ /(^|[ \t])native[ \t]/))
          print FILENAME ":" FNR ": declares a native method outside " who
      }'
}
