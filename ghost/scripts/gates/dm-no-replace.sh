#!/usr/bin/env bash
# Gate G-DM4 (Phase 9 design §16.1, §13.6 "REPLACE guards"; S0′ gate slice, §22.33): **DM SQL never
# resolves a conflict by replacing a row.** Every `dm_*` and `olm_*` table carries a `*_no_replace`
# guard (a `BEFORE INSERT` trigger that aborts on a key conflict), because a REPLACE deletes the old
# row and inserts a new one: the delete cascades (an `olm_prekey_gen` replace takes its
# `olm_prekey_used` reuse tuples with it, which is the D2b state a replayed first flight needs, §7.6),
# fires no UPDATE trigger (so the monotonic and state-machine triggers never see it) and silently
# rewrites history the checkpoint and the crash oracle rely on. The guards make a REPLACE fail at
# run time; this gate makes it fail at review time, before any test has to reach the statement.
#
# Refused forms, case-insensitive, with any whitespace between the words:
#   `INSERT OR REPLACE`, `UPDATE OR REPLACE` (any `OR REPLACE`), `REPLACE INTO` (SQLite's alias of
#   `INSERT OR REPLACE`), `ON CONFLICT REPLACE` (the conflict clause of a column or table constraint)
#   and the upsert `ON CONFLICT (…) DO UPDATE`. `INSERT OR IGNORE`, `ON CONFLICT DO NOTHING` and the
#   SQL function `replace(x, y, z)` are not conflict resolution by replacement and pass.
#
# What counts as DM SQL. Only **string literals** are read — SQL lives in literals, and prose about
# a REPLACE in a comment or a KDoc (the guards' own documentation needs to name what they refuse)
# is not a statement. A small lexer skips `//` and nested `/* */` comments and character literals,
# reads plain strings (escapes, `${…}` templates with nested strings) and `"""` raw strings, and
# joins literals separated only by `+`, whitespace or line breaks into one **group**: a statement
# split as `"… ON CONFLICT(a) " + "DO UPDATE …"` is matched as one text. A group is DM SQL when
#   (1) it is in a production source of `android/messaging` or `android/crypto-bridge` (every SQL
#       string of the DM stores is DM SQL), or
#   (2) it is inside migration 5 of `android/storage/.../Schema.kt` — from `fun migration5Tables(`
#       to `val expectedTables` — where `replaceGuard` builds trigger names from templates, or
#   (3) it names a DM table (`dm_…` or `olm_…`) anywhere else under `android/*/src/main` (a later
#       migration that alters a DM table, a DAO in another module).
# `:sync`'s own upserts (cursors, capabilities, the directory) and `:storage`'s pre-DM tables are not
# DM SQL and are not read against this rule.
#
# Vacuity: `android/messaging/src/main` must exist and hold at least one SQL group, and Schema.kt must
# carry both region markers with a `CREATE TABLE dm_` between them; otherwise the gate fails rather
# than pass over a moved schema.
#
# Usage: dm-no-replace.sh        (scans GHOST_ROOT, default: the ghost/ monorepo)
# Self-test: scripts/gates/self-test.sh points GHOST_ROOT at test-harness/gates/negative-dm-replace-*.
source "$(dirname "${BASH_SOURCE[0]}")/common.sh"
GHOST_ROOT="$(cd "$GHOST_ROOT" && pwd)"

report="$(GHOST_ROOT="$GHOST_ROOT" perl -e '
use strict; use warnings;
my $root = $ENV{GHOST_ROOT};
my $schema_rel = "android/storage/src/main/kotlin/org/ghost/storage/Schema.kt";
my @forms = (
  [qr/\bOR\s+REPLACE\b(?!\s*\()/i, "OR REPLACE"],
  [qr/\bREPLACE\s+INTO\b/i, "REPLACE INTO"],
  [qr/\bON\s+CONFLICT\s+REPLACE\b/i, "ON CONFLICT REPLACE"],
  [qr/\bON\s+CONFLICT\b[^;]*?\bDO\s+UPDATE\b/is, "ON CONFLICT ... DO UPDATE"],
);
my $sqlish = qr/\b(?:SELECT|INSERT|UPDATE|DELETE|CREATE)\b/i;

# Returns the literal groups of one source as [first line, text, per-character line numbers].
sub groups {
  my ($src) = @_;
  my @out;
  my ($i, $line, $n) = (0, 1, length $src);
  my ($text, @lines, $start) = ("", ());
  my $open = 0;                       # a group is being collected
  my $close = sub { if ($open) { push @out, [$start, $text, [@lines]]; } $open = 0; $text = ""; @lines = (); };
  my $append = sub { my ($c, $l) = @_; if (!$open) { $open = 1; $start = $l; } $text .= $c; push @lines, $l; };
  # Reads a string starting at $i (after its opening quotes); $raw is 1 for """ strings.
  my $read_string;
  $read_string = sub {
    my ($raw, $collect) = @_;
    while ($i < $n) {
      my $c = substr($src, $i, 1);
      if ($raw && substr($src, $i, 3) eq "\"\"\"") {
        my $q = 0; $q++ while $i + $q < $n && substr($src, $i + $q, 1) eq "\"";
        for (1 .. $q - 3) { $collect->("\"", $line) } $i += $q; return;
      }
      if (!$raw && $c eq "\"") { $i++; return; }
      if (!$raw && $c eq "\\") { $collect->(substr($src, $i, 2), $line); $i += 2; next; }
      if ($c eq "\$" && substr($src, $i + 1, 1) eq "{") {
        # A template expression: code with balanced braces, which may hold nested strings. Its
        # text is kept, nested literals included, so a table name built as ${table} and a clause
        # chosen as ${if (x) "OR REPLACE" else ""} are both read with the statement around them.
        $collect->("\${", $line); $i += 2; my $depth = 1;
        while ($i < $n && $depth > 0) {
          my $d = substr($src, $i, 1);
          if ($d eq "\"") {
            my $r = substr($src, $i, 3) eq "\"\"\"";
            $i += $r ? 3 : 1; $read_string->($r, $collect);
            next;
          }
          $depth++ if $d eq "{"; $depth-- if $d eq "}";
          $collect->($d, $line); $line++ if $d eq "\n"; $i++;
        }
        next;
      }
      $collect->($c, $line); $line++ if $c eq "\n"; $i++;
    }
  };
  while ($i < $n) {
    my $c = substr($src, $i, 1);
    my $two = substr($src, $i, 2);
    if ($two eq "//") { $i++ while $i < $n && substr($src, $i, 1) ne "\n"; next; }
    if ($two eq "/*") {
      my $depth = 0;
      while ($i < $n) {
        my $t = substr($src, $i, 2);
        if ($t eq "/*") { $depth++; $i += 2; next; }
        if ($t eq "*/") { $depth--; $i += 2; last if $depth == 0; next; }
        $line++ if substr($src, $i, 1) eq "\n"; $i++;
      }
      next;
    }
    if ($c eq "\"") {
      my $raw = substr($src, $i, 3) eq "\"\"\"";
      $i += $raw ? 3 : 1;
      $read_string->($raw, $append);
      next;
    }
    if ($c eq "\x27") {
      # A character literal: skip it whole so a quote character never opens a string. The closing
      # quote is searched for (not assumed two bytes on): the source is read as bytes, and a
      # non-ASCII character is more than one.
      my $from = $i + (substr($src, $i + 1, 1) eq "\\" ? 3 : 2);
      my $j = index($src, "\x27", $from);
      $i = $j < 0 ? $n : $j + 1;
      $close->();
      next;
    }
    if ($c eq "\n") { $line++; $i++; next; }
    if ($c =~ /[\s+]/) { $i++; next; }
    $close->();
    $i++;
  }
  $close->();
  return @out;
}

sub files_under {
  my ($dir) = @_;
  return () unless -d $dir;
  my @f = split /\n/, `find "$dir" -type f \\( -name "*.kt" -o -name "*.java" \\) 2>/dev/null | sort`;
  return grep { length } @f;
}

# One violation per line of a group, naming every form found on it (`INSERT OR REPLACE INTO` is
# both `OR REPLACE` and `REPLACE INTO`, and is one statement). Template delimiters are blanked
# first, offsets kept, so `OR ${"REPLACE"}` reads as the `OR REPLACE` it builds.
sub check {
  my ($rel, $g) = @_;
  my ($start, $text, $lines) = @$g;
  (my $plain = $text) =~ s/\$\{/  /g;
  $plain =~ s/\}/ /g;
  my (%names, @order);
  for my $f (@forms) {
    my ($re, $name) = @$f;
    while ($plain =~ /$re/g) {
      my $line = $lines->[$-[0]];
      push @order, $line unless $names{$line};
      push @{ $names{$line} }, $name unless grep { $_ eq $name } @{ $names{$line} || [] };
    }
  }
  for my $line (@order) {
    print "VIOLATION $rel:$line: ", join(", ", @{ $names{$line} }), " in DM SQL (G-DM4: DM rows are never replaced; the REPLACE guards of design 13.6)\n";
  }
}

my %dm_module = map { $_ => 1 } ("messaging", "crypto-bridge");
my ($dm_sql_groups, $region_found, $region_tables) = (0, 0, 0);
my @mains = grep { length } split /\n/, `find "$root/android" -maxdepth 3 -type d -path "*/src/main" 2>/dev/null | sort`;
print "VACUOUS android/messaging/src/main: missing (the gate would pass vacuously)\n" unless -d "$root/android/messaging/src/main";
for my $main (@mains) {
  (my $module = $main) =~ s{^\Q$root\E/android/([^/]+)/src/main$}{$1};
  my @sets = ($main);
  if ($dm_module{$module}) { for my $s (qw(gate debug release)) { push @sets, "$root/android/$module/src/$s" } }
  for my $set (@sets) {
    for my $file (files_under($set)) {
      (my $rel = $file) =~ s{^\Q$root\E/}{};
      open my $fh, "<", $file or do { print "VIOLATION $rel: unreadable\n"; next };
      local $/; my $src = <$fh>; close $fh;
      my ($from, $to) = (0, 0);
      if ($rel eq $schema_rel) {
        my @l = split /\n/, $src, -1;
        for my $k (0 .. $#l) {
          $from = $k + 1 if !$from && $l[$k] =~ /fun migration5Tables\(/;
          $to = $k + 1 if $from && !$to && $l[$k] =~ /val expectedTables\b/;
        }
        if ($from && $to) { $region_found = 1 }
        else { print "VACUOUS $rel: the migration 5 markers (fun migration5Tables, val expectedTables) are missing\n" }
      }
      for my $g (groups($src)) {
        my ($start, $text) = @$g;
        my $in_region = $from && $to && $start >= $from && $start < $to;
        $region_tables++ if $in_region && $text =~ /CREATE\s+TABLE\s+dm_/i;
        my $dm = $dm_module{$module} || $in_region || $text =~ /\b(?:dm|olm)_[a-z0-9_]+/;
        next unless $dm;
        $dm_sql_groups++ if $module eq "messaging" && $text =~ $sqlish;
        check($rel, $g);
      }
    }
  }
}
print "VACUOUS android/messaging/src/main: no SQL string found (the gate would pass vacuously)\n" if -d "$root/android/messaging/src/main" && !$dm_sql_groups;
print "VACUOUS $schema_rel: missing (the gate would pass vacuously)\n" unless -f "$root/$schema_rel";
print "VACUOUS $schema_rel: no CREATE TABLE dm_ between the migration 5 markers (the gate would pass vacuously)\n" if $region_found && !$region_tables;
print "SUMMARY $dm_sql_groups DM SQL strings in android/messaging\n";
')" || fail "dm-no-replace.sh lexer stopped (exit $?)"

while IFS= read -r line; do
  case "$line" in
    VIOLATION\ *) fail "${line#VIOLATION }" ;;
    VACUOUS\ *) fail "${line#VACUOUS }" ;;
    SUMMARY\ *) echo "[dm-no-replace] ${line#SUMMARY }" ;;
  esac
done <<< "$report"
finish dm-no-replace
