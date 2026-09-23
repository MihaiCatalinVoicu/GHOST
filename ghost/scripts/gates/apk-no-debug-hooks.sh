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
#   - **debug-only classes**: every class, object and interface declared at the top level of a file
#     in **any source set that is not a release one** — `android/<module>/src/<set>/` with `<set>`
#     other than `main` and `release` — except the JVM unit-test sets (`test…`), which no APK
#     packages. That is `src/gate` (the key-change hook, the digest export, the gate
#     instrumentation), `src/androidTest` (the emulator suites, their loopback delivery model — the
#     transport-injection seam of §21.13 point 5 — and the equivalence device test),
#     `src/deviceRunner` (the device suites' `Instrumentation`), `src/equivalence` (the equivalence
#     comparator) and `src/debug`, and every set added later (S12 review: the first version read
#     `src/gate` and `src/androidTest` only, and `org.ghost.device.DeviceRunner` in a release
#     mapping passed). A declaration may carry annotations on its own line or in front of it, and a
#     file's top-level functions are the class `<File>Kt` (or its `@file:JvmName`), so those count
#     too;
#   - **one exception, the build-type twin**: a qualified name that a release source set declares
#     as well (`src/release`'s `org.ghost.app.DmBranch`, which `src/debug` and `src/gate` define
#     again for their build types) is the release's own class, not a debug one. What the gate twin
#     alone names — the key-change hook — is still debug-only and still refused;
#   - **harness and gate packages**: any `org.ghost.…harness…` or `org.ghost.…gate…` package segment;
#   - **the equivalence-test entry point**: the class `DmEquivalence`, whose one native method is
#     exported only by the test libraries built with the `test-vectors` feature (§15.9 item 7,
#     §22.8.10 point 6), and any `external fun equivalence`.
#
# Three halves:
#   1. **Source sets** (no build needed; `static-gates` runs it through run-all.sh). The release
#      variant compiles `android/*/src/main/` and `android/*/src/release/`. No file there declares a
#      harness or gate package, names a debug-only class in code (comments — `//` to the end of a
#      line and `/* … */` over any lines — are dropped first: the design's own KDoc names the
#      hooks), or declares the equivalence entry point.
#   2. **Build scripts** (S12 review): the two directories above are what the release compiles only
#      while no `build.gradle.kts` adds a directory to the `main` or `release` source set. A
#      `srcDir`, `srcDirs` or `setSrcDirs` of any kind (Kotlin, Java, jniLibs, assets, resources)
#      inside a `getByName("main")`/`named("main")`/`main { }` block — or `release` — or on a
#      `sourceSets["main"]` line is refused: it is how `src/deviceRunner` and `src/equivalence` are
#      attached to the test sets, and the same line pointed at `main` would ship them.
#   3. **R8's mapping.txt** of the release build (the CI `android` job passes it, after
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
#   without an argument the mapping half is not run (halves 1 and 2 need no build).
# Self-test: scripts/gates/self-test.sh, with the fixtures in test-harness/gates/dm-hooks/.
source "$(dirname "${BASH_SOURCE[0]}")/common.sh"
MAPPING="${1:-}"
ANDROID="$GHOST_ROOT/android"
ENTRY_CLASS='DmEquivalence'

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

# `<source set> TAB <path>` for every Kotlin and Java file under android/<module>/src/<set>/.
all_sources() {
  find "$ANDROID" -path '*/build' -prune -o -type f \( -name '*.kt' -o -name '*.java' \) -print 2>/dev/null \
    | awk -v a="$ANDROID/" 'index($0, a) == 1 {
        n = split(substr($0, length(a) + 1), p, "/")
        if (n >= 4 && p[2] == "src") print p[3] "\t" $0
      }' || true
}
debug_files() { all_sources | awk -F'\t' '$1 != "main" && $1 != "release" && $1 !~ /^test/ { print $2 }'; }
release_files() { all_sources | awk -F'\t' '$1 == "main" || $1 == "release" { print $2 }'; }

# `<qualified name> <simple name>` of every top-level class, object and interface a file declares,
# and of its facade class for top-level functions (`<File>Kt`, or the `@file:JvmName`).
declarations() { # files on stdin
  local f pkg name base jvm
  while IFS= read -r f; do
    [ -n "$f" ] || continue
    pkg="$(grep -m1 -oE '^package[[:space:]]+[A-Za-z0-9_.]+' "$f" | awk '{print $2}' || true)"
    while IFS= read -r name; do
      [ -n "$name" ] || continue
      echo "${pkg:+$pkg.}$name $name"
    done < <(grep -oE '^((@[A-Za-z_][A-Za-z0-9_.]*(\([^)]*\))?[[:space:]]+)*)((public|internal|private|protected|data|sealed|abstract|open|enum|annotation|value|inner|fun|final|expect|actual)[[:space:]]+)*(class|object|interface)[[:space:]]+[A-Za-z_][A-Za-z0-9_]*' "$f" \
               | awk '{print $NF}' || true)
    case "$f" in
      *.kt)
        jvm="$(grep -m1 -oE '^@file:JvmName\("[A-Za-z_][A-Za-z0-9_]*"\)' "$f" | sed -E 's/.*\("([^"]+)"\).*/\1/' || true)"
        base="$(basename "$f" .kt)"
        name="${jvm:-${base}Kt}"
        echo "${pkg:+$pkg.}$name $name"
        ;;
    esac
  done
}

debug_files | declarations | sort -u > "$work/debug-all"
release_files | declarations | awk '{print $1}' | sort -u > "$work/release-qualified"
# The build-type twin: a name a release source set declares is the release's own (see the header).
awk 'FNR == NR { rel[$1] = 1; next } !($1 in rel)' "$work/release-qualified" "$work/debug-all" > "$work/debug"
twins="$(awk 'FNR == NR { rel[$1] = 1; next } ($1 in rel)' "$work/release-qualified" "$work/debug-all" | awk '{print $1}' | sort -u | paste -sd' ' -)"
[ -s "$work/debug" ] || fail "no class is declared in a non-release source set under android/*/src (the gate build type is missing; the gate would pass vacuously)"
awk '{print $2}' "$work/debug" | sort -u > "$work/simple"
echo "$ENTRY_CLASS" >> "$work/simple"
simple_alt="$(paste -sd'|' "$work/simple")"

# ---- half 1: the release source sets, read in one pass. Code only: `/* … */` comments over any
# number of lines and trailing `//` comments are dropped first, because the design's own KDoc names
# every hook on purpose and prose is not a reference.
release=()
while IFS= read -r f; do [ -n "$f" ] && release+=("$f"); done < <(release_files)
scanned="${#release[@]}"
if [ "$scanned" -gt 0 ]; then
  while IFS= read -r v; do
    [ -n "$v" ] && fail "$v"
  done < <(awk -v names="$simple_alt" -v root="$GHOST_ROOT/" '
    BEGIN { re = "(^|[^A-Za-z0-9_])(" names ")([^A-Za-z0-9_]|$)" }
    FNR == 1 { rel = FILENAME; if (index(rel, root) == 1) rel = substr(rel, length(root) + 1); inc = 0 }
    /^package[ \t]+([A-Za-z0-9_]+\.)*(harness|gate)(\.[A-Za-z0-9_.]+)?[ \t]*$/ {
      print rel ": a release source set declares a harness or gate package (G-DM5)"
    }
    { rest = $0; line = ""
      while (rest != "") {
        if (inc) {
          p = index(rest, "*/")
          if (p == 0) { rest = ""; break }
          rest = substr(rest, p + 2); inc = 0
        } else {
          p = index(rest, "/*")
          if (p == 0) { line = line rest; rest = ""; break }
          line = line substr(rest, 1, p - 1) " "; rest = substr(rest, p + 2); inc = 1
        }
      }
      sub(/(^|[ \t])\/\/.*$/, "", line)
      if (line ~ /^[ \t]*$/) next
      if (line ~ re) print rel ":" FNR ": a release source set names a debug-only class (G-DM5): " line
      if (line ~ /external[ \t]+fun[ \t]+equivalence/) print rel ":" FNR ": a release source set declares the equivalence-test entry point (G-DM5)"
    }
  ' "${release[@]}")
fi
[ "$scanned" -ge "${GHOST_DM_HOOKS_MIN_SOURCES:-20}" ] || fail "only $scanned release sources found under $ANDROID (the gate would pass vacuously)"

# ---- half 2: no build script adds a directory to a release source set
builds=()
while IFS= read -r f; do [ -n "$f" ] && builds+=("$f"); done < <(find "$ANDROID" -mindepth 1 -maxdepth 2 -name 'build.gradle.kts' -not -path '*/build/*' 2>/dev/null | sort)
if [ "${#builds[@]}" -gt 0 ]; then
  while IFS= read -r v; do
    [ -n "$v" ] && fail "$v"
  done < <(awk -v root="$GHOST_ROOT/" '
    FNR == 1 { rel = FILENAME; if (index(rel, root) == 1) rel = substr(rel, length(root) + 1); depth = 0; ns = 0 }
    { line = $0
      sub(/(^|[ \t])\/\/.*$/, "", line)
      hit = 0
      if (line ~ /(getByName|named|maybeCreate)\("(main|release)"\)[^{]*\.(srcDir|srcDirs|setSrcDirs)[ \t]*\(/) hit = 1
      if (line ~ /sourceSets[ \t]*\[[ \t]*"(main|release)"[ \t]*\].*(srcDir|srcDirs|setSrcDirs)[ \t]*[(=]/) hit = 1
      if (match(line, /(getByName|named|maybeCreate|create|register)\("[A-Za-z0-9_]+"\)[^{]*\{/)) {
        nm = substr(line, RSTART, RLENGTH); sub(/^[^"]*"/, "", nm); sub(/".*$/, "", nm)
        ns++; stack[ns] = nm; sdepth[ns] = depth
      } else if (match(line, /^[ \t]*(main|release)[ \t]*\{/)) {
        nm = substr(line, RSTART, RLENGTH); gsub(/[ \t{]/, "", nm)
        ns++; stack[ns] = nm; sdepth[ns] = depth
      }
      if (line ~ /(srcDir|srcDirs|setSrcDirs)[ \t]*[(=]/ && ns > 0 && (stack[ns] == "main" || stack[ns] == "release")) hit = 1
      if (hit) print rel ":" FNR ": a build script adds a directory to a release source set (G-DM5): " line
      opens = gsub(/\{/, "{", line); closes = gsub(/\}/, "}", line)
      depth += opens - closes
      while (ns > 0 && depth <= sdepth[ns]) ns--
    }
  ' "${builds[@]}")
fi


# ---- half 3: R8's mapping of the release build
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
        if (simple == entry) print "mapping.txt ships the equivalence-test entry point " original " (G-DM5)"
        else if (outer in debug) print "mapping.txt ships the debug-only class " original " (G-DM5)"
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
echo "[apk-no-debug-hooks] $(wc -l < "$work/debug" | tr -d ' ') debug-only classes, ${#builds[@]} build scripts, $scanned release sources${twins:+; build-type twins: $twins}"
finish apk-no-debug-hooks
