#!/usr/bin/env bash
# Gate G-DM5 (Phase 9 design §16.1, §15.1, §15.10, §21.13 points 5 and 7, §22.8.10 point 11; slice
# S12): **nothing the gate and emulator builds need reaches the release build.**
#
#   the release variant's source sets and R8's mapping.txt contain no class of the key-change debug
#   hook, the order-digest export, a harness package, a transport-injection seam or the
#   equivalence-test entry point, and mapping.txt maps every `org.ghost.` class to itself
#
# What counts as each of those is read from the tree, not listed here, so a hook added later is
# covered the day it exists:
#   - **debug-only classes**: every class, object and interface declared under `android/*/src/gate/`
#     (the key-change hook, the digest export, the gate instrumentation) or
#     `android/*/src/androidTest/` (the emulator suite, its loopback delivery model — the
#     transport-injection seam of §21.13 point 5 — and the equivalence test);
#   - **harness and gate packages**: any `org.ghost.…harness…` or `org.ghost.…gate…` package segment;
#   - **the equivalence-test entry point**: the class `DmEquivalence`, whose one native method is
#     exported only by the test libraries built with the `test-vectors` feature (§15.9 item 7,
#     §22.8.10 point 6), and any `external fun equivalence`.
#
# Two halves:
#   1. **Source sets** (no build needed; `static-gates` runs it through run-all.sh). The release
#      variant compiles `android/*/src/main/` and `android/*/src/release/`. No file there declares a
#      harness or gate package, names a debug-only class in code (comments are dropped first: the
#      design's own KDoc names the hooks), or declares the equivalence entry point.
#   2. **R8's mapping.txt** of the release build (the CI `android` job passes it, after
#      `assembleRelease`). Every `org.ghost.` class is mapped to its own name — `proguard-rules.pro`
#      keeps GHOST's names (`-keepnames`, §22.8.10 point 11), so a renamed class is a rule that
#      stopped applying — and no mapped class is debug-only, in a harness or gate package, or the
#      equivalence entry point. A class R8 removed is not in the mapping, which is the point: what
#      the mapping lists is what shipped.
#
# It refuses to pass vacuously: at least one debug-only class must be found (the gate build type
# exists), at least 20 release sources must be read, and a mapping must list at least one
# `org.ghost.` class.
#
# Usage: apk-no-debug-hooks.sh [mapping.txt]
#   without an argument the mapping half is not run (the source half needs no build).
# Self-test: scripts/gates/self-test.sh, with the fixtures in test-harness/gates/dm-hooks/.
source "$(dirname "${BASH_SOURCE[0]}")/common.sh"
MAPPING="${1:-}"
ANDROID="$GHOST_ROOT/android"
ENTRY_CLASS='DmEquivalence'

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

debug_files() {
  find "$ANDROID" -path '*/build' -prune -o -type f \( -name '*.kt' -o -name '*.java' \) \
    \( -path '*/src/gate/*' -o -path '*/src/androidTest/*' \) -print 2>/dev/null || true
}
release_files() {
  find "$ANDROID" -path '*/build' -prune -o -type f \( -name '*.kt' -o -name '*.java' \) \
    \( -path '*/src/main/*' -o -path '*/src/release/*' \) -print 2>/dev/null || true
}


# `<qualified name> <simple name>` of every class, object and interface a debug-only file declares.
: > "$work/debug"
while IFS= read -r f; do
  [ -n "$f" ] || continue
  pkg="$(grep -m1 -oE '^package[[:space:]]+[A-Za-z0-9_.]+' "$f" | awk '{print $2}' || true)"
  while IFS= read -r name; do
    [ -n "$name" ] || continue
    echo "${pkg:+$pkg.}$name $name" >> "$work/debug"
  done < <(grep -oE '^((public|internal|private|protected|data|sealed|abstract|open|enum|annotation|value|inner|fun)[[:space:]]+)*(class|object|interface)[[:space:]]+[A-Za-z_][A-Za-z0-9_]*' "$f" \
             | awk '{print $NF}' || true)
done < <(debug_files)
sort -u -o "$work/debug" "$work/debug"
[ -s "$work/debug" ] || fail "no class is declared under android/*/src/gate or android/*/src/androidTest (the gate build type is missing; the gate would pass vacuously)"
awk '{print $2}' "$work/debug" | sort -u > "$work/simple"
echo "$ENTRY_CLASS" >> "$work/simple"
simple_alt="$(paste -sd'|' "$work/simple")"

# ---- half 1: the release source sets, read in one pass. Code only: comment lines and trailing `//`
# comments are dropped first, because the design's own KDoc names every hook on purpose and prose is
# not a reference.
release=()
while IFS= read -r f; do [ -n "$f" ] && release+=("$f"); done < <(release_files)
scanned="${#release[@]}"
if [ "$scanned" -gt 0 ]; then
  while IFS= read -r v; do
    [ -n "$v" ] && fail "$v"
  done < <(awk -v names="$simple_alt" -v root="$GHOST_ROOT/" '
    BEGIN { re = "(^|[^A-Za-z0-9_])(" names ")([^A-Za-z0-9_]|$)" }
    FNR == 1 { rel = FILENAME; if (index(rel, root) == 1) rel = substr(rel, length(root) + 1) }
    /^package[ \t]+([A-Za-z0-9_]+\.)*(harness|gate)(\.[A-Za-z0-9_.]+)?[ \t]*$/ {
      print rel ": a release source set declares a harness or gate package (G-DM5)"
    }
    { line = $0
      t = line; sub(/^[ \t]+/, "", t)
      if (t ~ /^(\*|\/\/|\/\*)/) next
      sub(/[ \t]\/\/.*$/, "", line)
      if (line ~ re) print rel ":" FNR ": a release source set names a debug-only class (G-DM5): " line
      if (line ~ /external[ \t]+fun[ \t]+equivalence/) print rel ":" FNR ": a release source set declares the equivalence-test entry point (G-DM5)"
    }
  ' "${release[@]}")
fi
[ "$scanned" -ge "${GHOST_DM_HOOKS_MIN_SOURCES:-20}" ] || fail "only $scanned release sources found under $ANDROID (the gate would pass vacuously)"

# ---- half 2: R8's mapping of the release build
if [ -n "$MAPPING" ]; then
  if [ ! -s "$MAPPING" ]; then
    fail "mapping not found or empty: $MAPPING (run :app:assembleRelease first)"
  else
    { echo "#"; awk '{print $1}' "$work/debug"; } > "$work/qualified"
    # Class lines only: `original -> renamed:` at column 0; member lines are indented. The last line
    # printed is the count of `org.ghost.` classes read, so an empty mapping cannot pass.
    ghost=""
    while IFS= read -r v; do
      case "$v" in
        COUNT\ *) ghost="${v#COUNT }" ;;
        *) [ -n "$v" ] && fail "$v" ;;
      esac
    done < <(awk -v entry="$ENTRY_CLASS" '
      FNR == NR { debug[$1] = 1; next }
      /^[^ #].* -> .*:$/ {
        original = $1; renamed = $3; sub(/:$/, "", renamed)
        if (index(original, "org.ghost.") != 1) next
        n++
        # Two kinds of line carry an org.ghost. name without being a shipped source class (found on
        # the first real release mapping, slice S12): a class R8 removed is listed for retrace as
        # `-> R8$$REMOVED$$CLASS$$n` (it did not ship at all), and a class R8 or D8 *synthesized*
        # (`$$ExternalSynthetic…`, the desugared lambdas) has no source name for -keepnames to keep.
        # Both are still checked below for being debug-only or in a harness or gate package.
        synthetic = (original ~ /\$\$ExternalSynthetic/ || original ~ /\$\$Lambda/)
        removed = (index(renamed, "R8$$REMOVED$$CLASS") == 1)
        if (original != renamed && !synthetic && !removed) print "mapping.txt renames " original " to " renamed ": every org.ghost. class maps to itself (-keepnames, G-DM5)"
        outer = original; sub(/\$.*$/, "", outer)
        simple = outer; sub(/^.*\./, "", simple)
        if (outer in debug) print "mapping.txt ships the debug-only class " original " (G-DM5)"
        else if (simple == entry) print "mapping.txt ships the equivalence-test entry point " original " (G-DM5)"
        else if (outer ~ /\.(harness|gate)(\.|$)/) print "mapping.txt ships " original " from a harness or gate package (G-DM5)"
      }
      END { print "COUNT " (n + 0) }
    ' "$work/qualified" "$MAPPING")
    [ "${ghost:-0}" -gt 0 ] || fail "mapping.txt lists no org.ghost. class (the gate would pass vacuously): $MAPPING"
    echo "[apk-no-debug-hooks] mapping: ${ghost:-0} org.ghost. classes read"
  fi
else
  echo "[apk-no-debug-hooks] mapping half not run (no mapping.txt given; the CI android job passes the release build's)"
fi
echo "[apk-no-debug-hooks] $(wc -l < "$work/debug" | tr -d ' ') debug-only classes, $scanned release sources"
finish apk-no-debug-hooks
