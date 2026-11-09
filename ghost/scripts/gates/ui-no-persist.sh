#!/usr/bin/env bash
# Gate G-U6 (Phase 13 design faza13-ux.md §13.1, §3.3; invariant T54): no UI state is
# persistable — nothing sensitive leaves the process to system_server or disk.
#
#   banned in android/ui and org.ghost.app.ui production sources:
#     rememberSaveable, SavedStateHandle, rememberTextFieldState, @Parcelize / Parcelable,
#     getSharedPreferences, PreferenceManager, DataStore, openFileOutput, FileOutputStream
#   the only onSaveInstanceState override allowed is SecureActivity's

set -euo pipefail
GATES_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GHOST_ROOT="${GHOST_ROOT:-$(cd "$GATES_DIR/../.." && pwd)}"
FAILURES=0
fail() { echo "GATE-FAIL: $*" >&2; FAILURES=$((FAILURES + 1)); }

BANNED='rememberSaveable|SavedStateHandle|rememberTextFieldState|@Parcelize|Parcelable|getSharedPreferences|PreferenceManager|DataStore|openFileOutput|FileOutputStream'

while IFS= read -r f; do
  rel="${f#"$GHOST_ROOT"/}"
  hits=$(BANNED_RE="$BANNED" perl -e '
    require "'"$GATES_DIR"'/source-text.pl";
    my $t = read_text($ARGV[0]);
    my ($w, $c) = views($t, "kotlin");
    my @bad;
    # The pattern arrives through the environment so a literal @ in it is never interpolated
    # as a Perl array (the .tsv rule taught this: /.../ interpolates @names).
    my $re = $ENV{BANNED_RE};
    while ($c =~ /($re)/g) { push @bad, "$1 at line " . line_of(\$c, $-[0]); }
    print join("\n", @bad);
  ' "$f")
  if [ -n "$hits" ]; then
    while IFS= read -r h; do fail "$rel: $h"; done <<< "$hits"
  fi
  # onSaveInstanceState: only SecureActivity may override it.
  if grep -q 'onSaveInstanceState' "$f"; then
    case "$rel" in
      android/ui/src/main/kotlin/org/ghost/ui/protect/SecureActivity.kt) ;;
      *) fail "$rel: onSaveInstanceState outside SecureActivity.kt" ;;
    esac
  fi
done < <(find "$GHOST_ROOT/android/ui/src/main" "$GHOST_ROOT/android/app/src/main/kotlin/org/ghost/app/ui" "$GHOST_ROOT/android/app/src/release" -type f -name '*.kt' 2>/dev/null || true)

# Vacuity floor: the scanned trees must hold sources.
ui_count=$(find "$GHOST_ROOT/android/ui/src/main" -type f -name '*.kt' 2>/dev/null | sed -n '1p')
[ -n "$ui_count" ] || fail "android/ui/src/main holds no sources (empty scan refused)"

if [ "$FAILURES" -gt 0 ]; then echo "[ui-no-persist] FAILED with $FAILURES violation(s)" >&2; exit 1; fi
echo "[ui-no-persist] OK"
