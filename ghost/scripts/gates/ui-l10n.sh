#!/usr/bin/env bash
# Gate G-U12 (Phase 13 design faza13-ux.md §13.1, §9.4; R13-1): every user-visible string is a
# resource, in Romanian and English, with matching placeholders.
#
#   every string key of android/ui's `values` exists in `values-ro` with the same placeholders
#     (%1$s, %d, %n$ etc.), and vice versa
#   Romanian plurals declare one/few/other
#   no literal user-visible string in composables: a Text( "...") / stringResource-free
#     double-quoted argument named text/title/label/subtitle/body in android/ui production
#     sources fails (imports and non-composable strings are not user-visible; the check is a
#     heuristic floor, the semantic snapshots are the real regression gate)

set -euo pipefail
GATES_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GHOST_ROOT="${GHOST_ROOT:-$(cd "$GATES_DIR/../.." && pwd)}"
FAILURES=0
fail() { echo "GATE-FAIL: $*" >&2; FAILURES=$((FAILURES + 1)); }

# Every :ui module's res/values{,-ro} pair must key-match with identical placeholder sets.
while IFS= read -r vals; do
  mod=$(dirname "$vals")
  ro="$mod/values-ro"
  if [ ! -d "$ro" ]; then
    fail "${vals#"$GHOST_ROOT"/}: values without values-ro (Q9: Romanian ships at launch)"
    continue
  fi
  # Collect name -> placeholder signature from each values file of the default set.
  while IFS= read -r vf; do
    rel="${vf#"$mod"/}"
    rof="$ro/$(basename "$vf")"
    [ -f "$rof" ] || { fail "${vf#"$GHOST_ROOT"/}: no Romanian twin $rof"; continue; }
    keys_en=$(grep -oE '<(string|plurals) name="[^"]+"' "$vf" | sed 's/.*name="//;s/"//' | sort)
    keys_ro=$(grep -oE '<(string|plurals) name="[^"]+"' "$rof" | sed 's/.*name="//;s/"//' | sort)
    missing_ro=$(comm -23 <(printf '%s\n' "$keys_en") <(printf '%s\n' "$keys_ro"))
    missing_en=$(comm -13 <(printf '%s\n' "$keys_en") <(printf '%s\n' "$keys_ro"))
    [ -n "$missing_ro" ] && while IFS= read -r k; do fail "$rel: '$k' has no Romanian text"; done <<< "$missing_ro"
    [ -n "$missing_en" ] && while IFS= read -r k; do fail "$rof: '$k' has no English text"; done <<< "$missing_en"
    # Placeholder parity per common key (strings only; plurals checked for one/few/other below).
    for k in $keys_en; do
      en_line=$(grep -A 1 "<string name=\"$k\"" "$vf" | head -2 || true)
      ro_line=$(grep -A 1 "<string name=\"$k\"" "$rof" | head -2 || true)
      en_ph=$( (printf '%s' "$en_line" | grep -oE '%[0-9]*\$?[sdxf]' | sort | tr '\n' ' ') || true)
      ro_ph=$( (printf '%s' "$ro_line" | grep -oE '%[0-9]*\$?[sdxf]' | sort | tr '\n' ' ') || true)
      if [ "$en_ph" != "$ro_ph" ]; then
        fail "$rel: '$k' placeholder mismatch (en: '$en_ph' ro: '$ro_ph')"
      fi
    done
    # Romanian plurals must declare one/few/other.
    for pk in $(grep -oE '<plurals name="[^"]+"' "$rof" | sed 's/.*name="//;s/"//'); do
      body=$(awk "/<plurals name=\"$pk\"/,/<\/plurals>/" "$rof")
      for q in one few other; do
        printf '%s' "$body" | grep -q "<item quantity=\"$q\"" || fail "$rof: plural '$pk' lacks quantity '$q'"
      done
    done
  done < <(find "$mod/values" -maxdepth 1 -name '*.xml' 2>/dev/null || true)
done < <(find "$GHOST_ROOT/android/ui" -path '*/src/main/res/values' -type d 2>/dev/null || true)

# Vacuity floor: at least one values dir.
vals_count=$(find "$GHOST_ROOT/android/ui" -path '*/src/main/res/values' -type d 2>/dev/null | head -1)
[ -n "$vals_count" ] || fail "no res/values in :ui (empty scan refused)"

# No literal user-visible string in composables of android/ui.
while IFS= read -r f; do
  rel="${f#"$GHOST_ROOT"/}"
  hits=$(perl -e '
    require "'"$GATES_DIR"'/source-text.pl";
    my $t = read_text($ARGV[0]);
    my ($w) = views($t, "kotlin");
    my @bad;
    # Text( text = "..." ) style calls with a literal (strings-included view, so the literal is seen)
    while ($w =~ /\b(?:Text|SensitiveTextView)\s*\(\s*(?:text\s*=\s*)?"([^"]{2,})"/g) {
      push @bad, "literal text \"$1\" at line " . line_of(\$w, $-[0]);
    }
    print join("\n", @bad);
  ' "$f")
  if [ -n "$hits" ]; then
    while IFS= read -r h; do fail "$rel: $h (G-U12: strings are resources)"; done <<< "$hits"
  fi
done < <(find "$GHOST_ROOT/android/ui/src/main" -type f -name '*.kt' 2>/dev/null || true)

if [ "$FAILURES" -gt 0 ]; then echo "[ui-l10n] FAILED with $FAILURES violation(s)" >&2; exit 1; fi
echo "[ui-l10n] OK"
