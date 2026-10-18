#!/usr/bin/env bash
# Gate G-U7 (Phase 13 design faza13-ux.md §13.1; invariants T7, ADR-06): the UI adds no
# forbidden artifact, and test-only dependencies stay out of what ships.
#
#   artifact-level denylist banned from every configuration of every module:
#     androidx.browser, androidx.webkit, androidx.credentials, androidx.ads,
#     androidx.compose.ui:ui-text-google-fonts, com.google.mlkit, com.google.android.gms
#   test-only groups (androidx.test, the accessibility-test-framework, Robolectric, the Compose
#     test artifacts) absent from release runtime classpaths: they may appear only in test
#     configurations (testImplementation/androidTestImplementation) and in :app-uitest
#   the androidx.startup initializer set unchanged (the existing merged-manifest-lint.sh rule
#     keeps carrying this half)

set -euo pipefail
GATES_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GHOST_ROOT="${GHOST_ROOT:-$(cd "$GATES_DIR/../.." && pwd)}"
FAILURES=0
fail() { echo "GATE-FAIL: $*" >&2; FAILURES=$((FAILURES + 1)); }

DENY='androidx\.browser|androidx\.webkit|androidx\.credentials|androidx\.ads|ui-text-google-fonts|com\.google\.mlkit|com\.google\.android\.gms'
TESTONLY='androidx\.test|accessibility-test-framework|robolectric|compose\.ui:ui-test|compose\.ui:ui-test-manifest|compose\.ui:ui-test-junit4'

while IFS= read -r f; do
  rel="${f#"$GHOST_ROOT"/}"
  # Denylist: no configuration may declare one.
  hits=$(grep -nE "($DENY)" "$f" || true)
  [ -z "$hits" ] || while IFS= read -r h; do fail "$rel: denied artifact: $h"; done <<< "$hits"
  # Test-only groups: allowed only in test configurations.
  while IFS= read -r h; do
    line=$(printf '%s' "$h" | cut -d: -f1)
    conf=$(sed -n "${line}p" "$f" | sed -E 's/^[[:space:]]*([A-Za-z0-9]+).*/\1/')
    case "$conf" in
      testImplementation|androidTestImplementation|testRuntimeOnly|androidTestRuntimeOnly|testCompileOnly|debugImplementation) ;;
      *) fail "$rel:$line: test-only dependency in a shipped configuration ($conf): $h" ;;
    esac
  done < <(grep -nE "($TESTONLY)" "$f" || true)
done < <(find "$GHOST_ROOT/android" -path '*/build' -prune -o -type f \( -name 'build.gradle.kts' -o -name 'build.gradle' \) -print 2>/dev/null || true)

# Vacuity floor: at least one Gradle build file.
deps_count=$(find "$GHOST_ROOT/android" -path '*/build' -prune -o -type f \( -name 'build.gradle.kts' -o -name 'build.gradle' \) -print 2>/dev/null | head -1)
[ -n "$deps_count" ] || fail "no Gradle build files (empty scan refused)"

if [ "$FAILURES" -gt 0 ]; then echo "[ui-deps] FAILED with $FAILURES violation(s)" >&2; exit 1; fi
echo "[ui-deps] OK"
