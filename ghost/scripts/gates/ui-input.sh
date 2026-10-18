#!/usr/bin/env bash
# Gate G-U4 (Phase 13 design faza13-ux.md §13.1, §4.2, §4.5; invariants T24, ADR-08): a text
# field exists in exactly one place — GhostTextField — and every window carries the IME
# interceptor.
#
#   BasicTextField / TextField / OutlinedTextField / BasicSecureTextField named in production
#     sources only inside GhostTextField.kt
#   GhostTextField.kt must apply filterTextContextMenuComponents (the ProcessTextKey filter)
#   InterceptPlatformTextInput present in GhostRoot.kt (the window-level IME incognito)

set -euo pipefail
GATES_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GHOST_ROOT="${GHOST_ROOT:-$(cd "$GATES_DIR/../.." && pwd)}"
FAILURES=0
fail() { echo "GATE-FAIL: $*" >&2; FAILURES=$((FAILURES + 1)); }

FIELD_SITE="android/ui/src/main/kotlin/org/ghost/ui/protect/GhostTextField.kt"
ROOT_SITE="android/ui/src/main/kotlin/org/ghost/ui/shell/GhostRoot.kt"
FIELD_RE='\b(BasicTextField|TextField|OutlinedTextField|BasicSecureTextField)\b'

while IFS= read -r f; do
  rel="${f#"$GHOST_ROOT"/}"
  [ "$rel" = "$FIELD_SITE" ] && continue
  hits=$(grep -nE "$FIELD_RE" "$f" || true)
  if [ -n "$hits" ]; then
    fail "$rel: a text field is built outside GhostTextField.kt: $hits"
  fi
done < <(find "$GHOST_ROOT/android/ui/src/main" "$GHOST_ROOT/android/app/src/main" "$GHOST_ROOT/android/app/src/release" -type f -name '*.kt' 2>/dev/null || true)

[ -f "$GHOST_ROOT/$FIELD_SITE" ] || fail "GhostTextField.kt missing (vacuity floor)"
grep -q 'filterTextContextMenuComponents' "$GHOST_ROOT/$FIELD_SITE" || fail "GhostTextField.kt does not apply the text-menu filter (PM-U34)"
grep -q 'ProcessTextKey' "$GHOST_ROOT/$FIELD_SITE" || fail "GhostTextField.kt does not filter ProcessTextKey items (CR-14)"

[ -f "$GHOST_ROOT/$ROOT_SITE" ] || fail "GhostRoot.kt missing"
grep -q 'InterceptPlatformTextInput\|ImeIncognito' "$GHOST_ROOT/$ROOT_SITE" || fail "GhostRoot.kt does not carry the IME interceptor"

if [ "$FAILURES" -gt 0 ]; then echo "[ui-input] FAILED with $FAILURES violation(s)" >&2; exit 1; fi
echo "[ui-input] OK"
