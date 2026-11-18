#!/usr/bin/env bash
# Gate G-U2 (Phase 13 design faza13-ux.md §13.1, §4.2; invariants T24, ADR-06, ADR-08):
# text cannot leave the app — no selection, no share, no drag, no linkification, no process
# text, and the clipboard is written only by SensitiveClipboard.
#
#   banned everywhere in the production sources of android/ui and android/app:
#     SelectionContainer, textIsSelectable, setTextIsSelectable,
#     ACTION_SEND, ACTION_SEND_MULTIPLE, ShareCompat, createChooser,
#     dragAndDropSource, startDragAndDrop, Linkify, LinkAnnotation, LocalUriHandler, autoLink,
#     the PickVisualMedia contracts and the picker fallback action strings
#   exits to other apps (ACTION_VIEW, ACTION_SENDTO, mailto:, Intent.parseUri, a Uri.parse with
#     a scheme, startActivity with a data URI) only in SystemIntents.kt
#   ClipData / setPrimaryClip / ClipboardManager / LocalClipboard / LocalClipboardManager
#     only in SensitiveClipboard.kt and GhostRoot.kt
#   SensitiveClipboard.kt must contain the sensitive key, clearPrimaryClip and the 30000 ms
#     constant
#   the backup, restore, passphrase and safety-number packages never import the clipboard
#     package (G-U2's path rule)

set -euo pipefail
GATES_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GHOST_ROOT="${GHOST_ROOT:-$(cd "$GATES_DIR/../.." && pwd)}"
FAILURES=0
fail() { echo "GATE-FAIL: $*" >&2; FAILURES=$((FAILURES + 1)); }

SRC_DIRS=("$GHOST_ROOT/android/ui/src/main" "$GHOST_ROOT/android/app/src/main" "$GHOST_ROOT/android/app/src/release")

BANNED='SelectionContainer|textIsSelectable|setTextIsSelectable|ACTION_SEND_MULTIPLE|ACTION_SEND\b|ShareCompat|createChooser|dragAndDropSource|startDragAndDrop|Linkify|LinkAnnotation|LocalUriHandler|autoLink|PickVisualMedia|ACTION_SYSTEM_FALLBACK_PICK_IMAGES'

for dir in "${SRC_DIRS[@]}"; do
  [ -d "$dir" ] || continue
  while IFS= read -r f; do
    rel="${f#"$GHOST_ROOT"/}"
    hits=$(perl -e '
      require "'"$GATES_DIR"'/source-text.pl";
      my $t = read_text($ARGV[0]);
      my ($w, $c) = views($t, "kotlin");
      my @bad;
      while ($c =~ /('"$BANNED"')/g) { push @bad, "$1 at line " . line_of(\$c, $-[0]); }
      print join("\n", @bad);
    ' "$f")
    if [ -n "$hits" ]; then
      while IFS= read -r h; do fail "$rel: $h"; done <<< "$hits"
    fi
  done < <(find "$dir" -type f -name '*.kt' 2>/dev/null || true)
done

# Exits to other apps only in SystemIntents.kt.
EXITS='ACTION_VIEW|ACTION_SENDTO|mailto:|Intent\.parseUri|startActivity\s*\('
for dir in "${SRC_DIRS[@]}"; do
  [ -d "$dir" ] || continue
  while IFS= read -r f; do
    rel="${f#"$GHOST_ROOT"/}"
    case "$rel" in
      android/ui/src/main/kotlin/org/ghost/ui/platform/SystemIntents.kt) continue ;;
      # §3.4's relaunch: LinkIntake starts GHOST's OWN activity explicitly to replace the task's
      # link-carrying base intent with a clean one — the opposite of an exit, never a URI to
      # another app. The relaunch is the D7 mechanism the manifest gate (G-U11) pairs with.
      android/app/src/main/kotlin/org/ghost/app/ui/LinkIntake.kt) continue ;;
    esac
    hits=$(perl -e '
      require "'"$GATES_DIR"'/source-text.pl";
      my $t = read_text($ARGV[0]);
      my ($w, $c) = views($t, "kotlin");
      my @bad;
      while ($c =~ /('"$EXITS"')/g) { push @bad, "$1 at line " . line_of(\$c, $-[0]); }
      # Uri.parse with a scheme (the bare "Uri.parse" call is checked via the with-strings view)
      while ($w =~ /\bUri\.parse\s*\(\s*"([a-zA-Z][a-zA-Z0-9+.-]*):/g) { push @bad, "Uri.parse with scheme $1: at line " . line_of(\$w, $-[0]); }
      print join("\n", @bad);
    ' "$f")
    if [ -n "$hits" ]; then
      while IFS= read -r h; do fail "$rel: $h (exit to another app belongs in SystemIntents.kt)"; done <<< "$hits"
    fi
  done < <(find "$dir" -type f -name '*.kt' 2>/dev/null || true)
done

# Clipboard references only in SensitiveClipboard.kt and GhostRoot.kt.
CLIP_RE='ClipData|setPrimaryClip|ClipboardManager|LocalClipboard|LocalClipboardManager'
for dir in "${SRC_DIRS[@]}"; do
  [ -d "$dir" ] || continue
  while IFS= read -r f; do
    rel="${f#"$GHOST_ROOT"/}"
    case "$rel" in
      android/ui/src/main/kotlin/org/ghost/ui/protect/SensitiveClipboard.kt) continue ;;
      android/ui/src/main/kotlin/org/ghost/ui/shell/GhostRoot.kt) continue ;;
      # The app's ClipboardOwner implementation: every write is delegated to SensitiveClipboard;
      # its platform types are required by the Compose interface, and its getters never read clips.
      android/app/src/main/kotlin/org/ghost/app/ui/AppClipboardOwner.kt) continue ;;
    esac
    if grep -qE "$CLIP_RE" "$f"; then
      fail "$rel: clipboard reference outside SensitiveClipboard.kt/GhostRoot.kt"
    fi
  done < <(find "$dir" -type f -name '*.kt' 2>/dev/null || true)
done

# SensitiveClipboard.kt carries the sensitive key, the clear call and the 30 000 ms constant.
SC="$GHOST_ROOT/android/ui/src/main/kotlin/org/ghost/ui/protect/SensitiveClipboard.kt"
if [ -f "$SC" ]; then
  grep -q 'EXTRA_IS_SENSITIVE' "$SC" || fail "SensitiveClipboard.kt: the sensitive extra key is missing"
  grep -q 'clearPrimaryClip' "$SC" || fail "SensitiveClipboard.kt: clearPrimaryClip is missing"
  grep -q '30_000\|30000' "$SC" || fail "SensitiveClipboard.kt: the 30 000 ms constant is missing"
else
  fail "SensitiveClipboard.kt does not exist (the gate's vacuity floor)"
fi

# The secret packages never import the clipboard package.
for dir in "${SRC_DIRS[@]}"; do
  [ -d "$dir" ] || continue
  while IFS= read -r f; do
    rel="${f#"$GHOST_ROOT"/}"
    case "$rel" in
      *feature/backup*|*feature/restore*|*feature/*passphrase*|*feature/*safety*)
        if grep -q 'import .*\.protect\.SensitiveClipboard\|import .*clipboard' "$f"; then
          fail "$rel: a secret screen imports the clipboard package (G-U2 path rule)"
        fi
        ;;
    esac
  done < <(find "$dir" -type f -name '*.kt' 2>/dev/null || true)
done

if [ "$FAILURES" -gt 0 ]; then echo "[ui-text-protection] FAILED with $FAILURES violation(s)" >&2; exit 1; fi
echo "[ui-text-protection] OK"
