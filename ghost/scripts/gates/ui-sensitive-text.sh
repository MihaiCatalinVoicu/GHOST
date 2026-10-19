#!/usr/bin/env bash
# Gate G-U3 (Phase 13 design faza13-ux.md §13.1, §3.3; invariants T24, T3): the unwrap of
# SensitiveText — the read of its `value` — happens in exactly one file, SensitiveTextView.kt.
#
# **How a call site is recognized, and what still escapes.** The gate reads a file that imports
# `org.ghost.ui.protect.SensitiveText` and fails on any `.value` read in it, outside the one
# site. UI models may hold a SensitiveText (the import) but never read `.value`: rendering goes
# through SensitiveTextView, and comparisons/tests happen in the JVM suite over the value class's
# own equality (no unwrap). A file that holds a secret under a different type and unwraps it
# textually elsewhere is the declared gap (D28) — the JVM reflection test over the UI models is
# the behavioural half that keeps it.

set -euo pipefail
GATES_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GHOST_ROOT="${GHOST_ROOT:-$(cd "$GATES_DIR/../.." && pwd)}"
FAILURES=0
fail() { echo "GATE-FAIL: $*" >&2; FAILURES=$((FAILURES + 1)); }

# **The declared exception.** The :app adapters are the engine crossing (§3.2): a body typed in
# the UI leaves as facade bytes, unwrapped exactly once per call on ghost-ui-io (CS-U6). The
# allowlist names those files, one per line, each with its reason (G-DM2's pattern); a file not
# listed fails the gate on its first `.value` read.
ALLOW="$GATES_DIR/ui-sensitive-unwrap.allow"
[ -f "$ALLOW" ] || { echo "[ui-sensitive-text] ui-sensitive-unwrap.allow missing" >&2; exit 1; }
allowed_file() { # $1 = repo-relative path
  while IFS=$'\t' read -r p _; do
    case "$p" in \#*|'') continue ;; esac
    [ "$p" = "$1" ] && return 0
  done < "$ALLOW"
  return 1
}

UNWRAP_SITE="android/ui/src/main/kotlin/org/ghost/ui/protect/SensitiveTextView.kt"

while IFS= read -r f; do
  rel="${f#"$GHOST_ROOT"/}"
  [ "$rel" = "$UNWRAP_SITE" ] && continue
  grep -q 'import org\.ghost\.ui\.protect\.SensitiveText' "$f" || continue
  if allowed_file "$rel"; then continue; fi
  hits=$(grep -nE '\.value\b' "$f" || true)
  if [ -n "$hits" ]; then
    fail "$rel: a .value read in a file that imports SensitiveText (the unwrap belongs in SensitiveTextView.kt): $hits"
  fi
done < <(find "$GHOST_ROOT/android/ui/src/main" "$GHOST_ROOT/android/app/src/main" "$GHOST_ROOT/android/app/src/release" -type f -name '*.kt' 2>/dev/null || true)

# The unwrap site must exist (vacuity floor) and must actually perform the unwrap.
[ -f "$GHOST_ROOT/$UNWRAP_SITE" ] || fail "SensitiveTextView.kt missing"
grep -q '\.value' "$GHOST_ROOT/$UNWRAP_SITE" || fail "SensitiveTextView.kt no longer unwraps SensitiveText"

if [ "$FAILURES" -gt 0 ]; then echo "[ui-sensitive-text] FAILED with $FAILURES violation(s)" >&2; exit 1; fi
echo "[ui-sensitive-text] OK"
