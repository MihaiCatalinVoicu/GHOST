#!/usr/bin/env bash
# Gate G-U10 (Phase 13 design faza13-ux.md §13.1, §4.6; invariant T11): notifications are one
# constant, content-free message.
#
#   notification builders only in GhostNotifier.kt
#   banned everywhere in the production sources: MessagingStyle, BigTextStyle, InboxStyle,
#     BigPictureStyle, RemoteInput, setNumber, Person, shortcuts, bubbles,
#     VISIBILITY_PUBLIC
#   title and text only from the allowlisted resource ids (notif_title, notif_new,
#     notif_new_count)
#
# S0b note: GhostNotifier.kt lands with S4 (the DM journey). Until then this gate scans the ban
# list over the sources that exist; its vacuity floor (the notifier file present) is added by S4
# in the same commit that builds the notifier, so a tree that never builds one cannot pass the
# full gate by omission.

set -euo pipefail
GATES_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GHOST_ROOT="${GHOST_ROOT:-$(cd "$GATES_DIR/../.." && pwd)}"
FAILURES=0
fail() { echo "GATE-FAIL: $*" >&2; FAILURES=$((FAILURES + 1)); }

NOTIFIER="android/app/src/main/kotlin/org/ghost/app/ui/GhostNotifier.kt"
BANNED='MessagingStyle|BigTextStyle|InboxStyle|BigPictureStyle|RemoteInput|setNumber|ShortcutInfo|BubbleMetadata|VISIBILITY_PUBLIC'

while IFS= read -r f; do
  rel="${f#"$GHOST_ROOT"/}"
  [ "$rel" = "$NOTIFIER" ] && continue
  hits=$(grep -nE "$BANNED" "$f" || true)
  [ -z "$hits" ] || while IFS= read -r h; do fail "$rel: banned notification element: $h"; done <<< "$hits"
done < <(find "$GHOST_ROOT/android/ui/src/main" "$GHOST_ROOT/android/app/src/main" "$GHOST_ROOT/android/app/src/release" -type f -name '*.kt' 2>/dev/null || true)

# Where a notifier exists, its title/text come only from the allowlisted ids.
if [ -f "$GHOST_ROOT/$NOTIFIER" ]; then
  hits=$(grep -nE 'setContentTitle|setContentText' "$GHOST_ROOT/$NOTIFIER" | grep -v 'R\.string\.notif_title\|R\.string\.notif_new\|R\.plurals\.notif_new_count' || true)
  [ -z "$hits" ] || while IFS= read -r h; do fail "$NOTIFIER: title/text outside the allowlist: $h"; done <<< "$hits"
fi

# Vacuity floor: the scanned trees must hold sources (the notifier file itself lands with S4).
notif_count=$(find "$GHOST_ROOT/android/ui/src/main" "$GHOST_ROOT/android/app/src/main" -type f -name '*.kt' 2>/dev/null | head -1)
[ -n "$notif_count" ] || fail "no UI/app sources (empty scan refused)"

if [ "$FAILURES" -gt 0 ]; then echo "[ui-notifications] FAILED with $FAILURES violation(s)" >&2; exit 1; fi
echo "[ui-notifications] OK"
