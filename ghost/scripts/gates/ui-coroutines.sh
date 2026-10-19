#!/usr/bin/env bash
# Gate G-U9, the widened half (Phase 13 design faza13-ux.md §13.1; ADR-20, X-U8): the coroutine
# ban of messaging-no-network.sh (G-DM1, extended by Phase 11 to :media) applies to every module
# except :ui — where screen models are suspend-free by design but the adapter layer legitimately
# uses coroutines for the gateway plumbing — and to :app outside org.ghost.app.ui. A module added
# later (Phase 14's :update) is covered the day it exists, because this gate scans by exclusion,
# not by module list.
#
# The rule is the same two readings as messaging-no-network.sh: as written (a comment naming
# kotlinx.coroutines fails too) and as a whole file over source-text.pl's code-only view (any
# whitespace, newlines included, around each dot; comments and backtick quoting blanked).
#
# What this gate deliberately does not rescan: :messaging, :crypto-bridge and :media (covered by
# messaging-no-network.sh, including its network-class rules) and :ui (exempt). What it cannot
# see is the same declared list as the parent gate's.

set -euo pipefail
GATES_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GHOST_ROOT="${GHOST_ROOT:-$(cd "$GATES_DIR/../.." && pwd)}"
FAILURES=0
fail() { echo "GATE-FAIL: $*" >&2; FAILURES=$((FAILURES + 1)); }
command -v perl >/dev/null || { echo "perl not found" >&2; exit 2; }

checked=0
while IFS= read -r f; do
  [ -n "$f" ] || continue
  rel="${f#"$GHOST_ROOT"/}"
  case "$rel" in
    android/messaging/*|android/crypto-bridge/*|android/media/*|android/ui/*) continue ;;
    # The platform-test module (com.android.test, Q25) is tests by construction - it ships no
    # artifact, and its fakes implement the gateways' suspend interfaces; the ban's target is
    # production code.
    android/app-uitest/*) continue ;;
    android/app/*)
      case "$rel" in
        android/app/src/*/kotlin/org/ghost/app/ui/*) continue ;;
      esac
      ;;
  esac
  checked=$((checked + 1))
  hits=$(perl -e '
    require "'"$GATES_DIR"'/source-text.pl";
    my $t = read_text($ARGV[0]);
    my @pkgs = ("kotlinx.coroutines", "kotlin.coroutines");
    my $on_a_line = join "|", map { "\\b" . quotemeta($_) . "\\b" } @pkgs;
    my $spread = join "|", map { "\\b" . join("\\s*\\.\\s*", map { quotemeta } split /\./) . "\\b" } @pkgs;
    my @lines = split /\n/, $t, -1;
    for my $i (0 .. $#lines) {
      print "PKG line " . ($i + 1) . ": $lines[$i]\n" if $lines[$i] =~ /$on_a_line/;
    }
    my ($with, $code) = views($t, $ARGV[0] =~ /\.java$/ ? "java" : "kotlin");
    my %seen;
    while ($with =~ /$spread/g) {
      my $n = line_of(\$with, $-[0]);
      next if $seen{$n}++;
      print "PKG spread over lines near line $n\n";
    }
    while ($code =~ /\bsuspend\b/g) {
      my $n = line_of(\$code, $-[0]);
      print "SUS suspend in code at line $n\n";
    }
  ' "$f")
  if [ -n "$hits" ]; then
    while IFS= read -r h; do fail "$rel: $h"; done <<< "$hits"
  fi
done < <(find "$GHOST_ROOT/android" -path '*/build' -prune -o -type f \( -name '*.kt' -o -name '*.java' \) \
           \( -path '*/src/main/*' -o -path '*/src/release/*' -o -path '*/src/gate/*' -o -path '*/src/debug/*' \) -print 2>/dev/null | sort || true)

[ "$checked" -gt 0 ] || fail "no Android production sources found (vacuous pass refused)"

if [ "$FAILURES" -gt 0 ]; then echo "[ui-coroutines] FAILED with $FAILURES violation(s)" >&2; exit 1; fi
echo "[ui-coroutines] OK"
