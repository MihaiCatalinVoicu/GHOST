#!/usr/bin/env bash
# Shared helpers for GHOST CI gates (ADR-10). Every gate:
#   - scans GHOST_ROOT (default: the ghost/ monorepo) and never legacy/ or build outputs
#   - exits 0 on pass, 1 on violation, 2 on usage error
#   - prints one line per violation as  path:line: message
set -euo pipefail
GATES_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GHOST_ROOT="${GHOST_ROOT:-$(cd "$GATES_DIR/../.." && pwd)}"
FAILURES=0

fail() { echo "GATE-FAIL: $*" >&2; FAILURES=$((FAILURES + 1)); }
finish() {
  local name="$1"
  if [ "$FAILURES" -gt 0 ]; then echo "[$name] FAILED with $FAILURES violation(s)" >&2; exit 1; fi
  echo "[$name] OK"
}
# Source trees that are on the production path. Test sources are excluded on purpose.
android_main_files() {
  find "$GHOST_ROOT/android" -path '*/build' -prune -o -type f \( -name '*.kt' -o -name '*.java' \) -path '*/src/main/*' -print 2>/dev/null
}
rust_src_files() {
  # test-harness/ is tooling, not the production path (its CLIs may print to the console).
  # Binary entry points (src/main.rs) print operator-facing constants and configuration only;
  # every library crate stays free of logging primitives.
  find "$GHOST_ROOT/relay" "$GHOST_ROOT/issuer" -path '*/target' -prune -o -type f -name '*.rs' -not -name main.rs -path '*/src/*' -print 2>/dev/null
}
manifest_files() {
  find "$GHOST_ROOT/android" -path '*/build' -prune -o -type f -name 'AndroidManifest.xml' -print 2>/dev/null
}
gradle_files() {
  find "$GHOST_ROOT/android" -path '*/build' -prune -o -type f \( -name '*.gradle.kts' -o -name 'libs.versions.toml' \) -print 2>/dev/null
}
