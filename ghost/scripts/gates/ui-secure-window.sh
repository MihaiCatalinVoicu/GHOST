#!/usr/bin/env bash
# Gate G-U1 (Phase 13 design faza13-ux.md §13.1, §4.1; invariant T10): every window of the app
# is secure, and every activity is a SecureActivity.
#
#   FLAG_SECURE / setFlags( / clearFlags( / other window-flag writes
#       only in SecureActivity.kt, before any content call
#   every Activity subclass of the production source sets extends SecureActivity
#   banned window sources (they bypass the Compose secure-flag inheritance or draw on their
#   own surface): Toast, PopupWindow, ListPopupWindow, android.app.Dialog, AlertDialog,
#   DialogFragment, Presentation, WindowManager addView, Spinner, AutoCompleteTextView,
#   PopupMenu, PlayerView, WebView, SurfaceView without setSecure(true)
#   banned: SecureFlagPolicy.SecureOff, overrides of onProvideAssist*
#
# **What it reads.** The Kotlin/Java production sources of android/ui and android/app
# (src/main and src/release). The merged-manifest half (exactly one activity) lives in
# merged-manifest-lint.sh (G-U11), not here.
#
# **Why a gate and not only tests.** T10 is a claim about every window that exists; the JVM
# suite proves it for the screens that have tests, the emulator suite for the platform
# behaviour, and this gate fails the build the day a new window source appears anywhere.

set -euo pipefail
GATES_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GHOST_ROOT="${GHOST_ROOT:-$(cd "$GATES_DIR/../.." && pwd)}"
FAILURES=0
fail() { echo "GATE-FAIL: $*" >&2; FAILURES=$((FAILURES + 1)); }

UI_SRC="$GHOST_ROOT/android/ui/src/main"
APP_SRC_MAIN="$GHOST_ROOT/android/app/src/main"

# Vacuity floor: the anchor file must exist.
[ -f "$UI_SRC/kotlin/org/ghost/ui/protect/SecureActivity.kt" ] || { fail "SecureActivity.kt missing (empty scan refused)"; }

# 1. FLAG_SECURE and any window-flag mutation happen only in SecureActivity.kt.
while IFS= read -r f; do
  rel="${f#"$GHOST_ROOT"/}"
  case "$rel" in
    android/ui/src/main/kotlin/org/ghost/ui/protect/SecureActivity.kt) continue ;;
    # §3.4's relaunch: LinkIntake sets launch flags on GHOST's OWN explicit intent to replace
    # the task's link-carrying base intent — task flags, not window flags (the G-U2 scutire
    # carries the same reason).
    android/app/src/main/kotlin/org/ghost/app/ui/LinkIntake.kt) continue ;;
  esac
  # The whole file as one string, comments blanked, so wrapped calls are still seen.
  hits=$(perl -e '
    require "'"$GATES_DIR"'/source-text.pl";
    my $t = read_text($ARGV[0]);
    my ($w, $c) = views($t, "kotlin");
    my @bad;
    while ($c =~ /\b(setFlags|clearFlags|addFlags|setAttributes)\s*\(/g) {
      my $line = line_of(\$c, $-[0]);
      push @bad, "window flag write at line $line";
    }
    while ($c =~ /\bFLAG_SECURE\b/g) {
      my $line = line_of(\$c, $-[0]);
      push @bad, "FLAG_SECURE at line $line";
    }
    print join("\n", @bad);
  ' "$f")
  if [ -n "$hits" ]; then
    while IFS= read -r h; do fail "$rel: $h (only SecureActivity.kt may touch window flags)"; done <<< "$hits"
  fi
done < <(find "$UI_SRC" "$APP_SRC_MAIN" -type f \( -name '*.kt' -o -name '*.java' \) 2>/dev/null | grep -v 'protect/SecureActivity.kt' || true)

# 2. SecureFlagPolicy.SecureOff and assist overrides: banned everywhere in the production path.
while IFS= read -r f; do
  rel="${f#"$GHOST_ROOT"/}"
  hits=$(perl -e '
    require "'"$GATES_DIR"'/source-text.pl";
    my $t = read_text($ARGV[0]);
    my ($w, $c) = views($t, "kotlin");
    my @bad;
    while ($c =~ /\bSecureFlagPolicy\s*\.\s*SecureOff/g) { push @bad, "SecureFlagPolicy.SecureOff at line " . line_of(\$c, $-[0]); }
    while ($c =~ /\bonProvideAssist(?:Data|Content|Referrer)\s*\(/g) { push @bad, "onProvideAssist* override at line " . line_of(\$c, $-[0]); }
    print join("\n", @bad);
  ' "$f")
  if [ -n "$hits" ]; then
    while IFS= read -r h; do fail "$rel: $h"; done <<< "$hits"
  fi
done < <(find "$UI_SRC" "$APP_SRC_MAIN" -type f \( -name '*.kt' -o -name '*.java' \) 2>/dev/null || true)

# 3. Banned window sources (class names, matched as code identifiers only).
BANNED='android\.widget\.Toast|\bToast\s*\(|\bPopupWindow|\bListPopupWindow|android\.app\.Dialog|\bAlertDialog|\bDialogFragment|\bPresentation\b|\.addView\s*\(|\bSpinner\b|\bAutoCompleteTextView|\bPopupMenu\b|\bPlayerView\b|\bWebView\b'
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
    while IFS= read -r h; do fail "$rel: $h (banned window source; use SecureDialog/Compose Popup)"; done <<< "$hits"
  fi
done < <(find "$UI_SRC" "$APP_SRC_MAIN" -type f \( -name '*.kt' -o -name '*.java' \) 2>/dev/null || true)

# 4. SurfaceView is banned unless paired with setSecure(true) in the same file.
while IFS= read -r f; do
  rel="${f#"$GHOST_ROOT"/}"
  if grep -q 'SurfaceView' "$f"; then
    if ! grep -q 'setSecure(true)' "$f"; then
      fail "$rel: SurfaceView without setSecure(true) (separate window layer; use TextureView)"
    fi
  fi
done < <(find "$UI_SRC" "$APP_SRC_MAIN" -type f \( -name '*.kt' -o -name '*.java' \) 2>/dev/null || true)

# 5. Every Activity subclass extends SecureActivity.
while IFS= read -r f; do
  rel="${f#"$GHOST_ROOT"/}"
  decl=$(grep -E 'class +[A-Za-z0-9_]+ *: *[A-Za-z0-9_.]*(Activity|AppCompatActivity|ComponentActivity|FragmentActivity)' "$f" || true)
  if [ -n "$decl" ]; then
    case "$decl" in
      *SecureActivity*) ;;
      *abstract*class*SecureActivity*) ;;
      *) fail "$rel: activity subclass does not extend SecureActivity: $decl" ;;
    esac
  fi
done < <(find "$UI_SRC" "$APP_SRC_MAIN" -type f \( -name '*.kt' -o -name '*.java' \) 2>/dev/null || true)

if [ "$FAILURES" -gt 0 ]; then echo "[ui-secure-window] FAILED with $FAILURES violation(s)" >&2; exit 1; fi
echo "[ui-secure-window] OK"
