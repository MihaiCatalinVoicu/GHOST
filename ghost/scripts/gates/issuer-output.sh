#!/usr/bin/env bash
# Gate (Phase 8 design §6.5, §14.1, §19.17 point 4, §19.20 point 5; ADR-26 point 7): what the
# issuer crates may write.
#   - ghost/issuer/crates/service: only src/status.rs, src/store.rs, src/journal.rs and
#     src/payout.rs (the payout batch export, design §9.5) create, open for writing, rename,
#     truncate, link or remove files or directories (a redb database is written by
#     Database::create, Database::open and Builder::new().create), and no module writes to stdout
#     or stderr: the issuer keeps no logs, operators read status.json.
#   - ghost/issuer/crates/ops: only src/report.rs writes to the console (fixed vocabulary) and only
#     src/output.rs writes files.
#   - every other issuer crate writes neither files nor to the console.
# Build scripts and tests are outside the scan (src/ only), as in every other gate.
#
# The regexes see qualified paths (`fs::write`, `File::create`, `io::stdout`, `stdout()`). An import
# hides the path from the call site, so every `use` declaration (joined across lines, as rustfmt
# wraps long groups) under std or tokio `fs`/`io` is checked too (S12 review
# GATE-ISSUER-OUTPUT-BRACE): a brace group, a glob or a rename that brings in a writing `fs` function
# (or renames `fs`, `self` or `File`) is a file write, and one that brings in `stdout`/`stderr` or
# globs `io` is console output. A plain `use std::fs::write;` is already matched by the regexes.
source "$(dirname "${BASH_SOURCE[0]}")/common.sh"
WRITE_REGEX='\bFile::(create|create_new|options)\b|\bOpenOptions\b|\bDirBuilder\b|\bfs::(write|copy|rename|remove_file|remove_dir|remove_dir_all|create_dir|create_dir_all|hard_link|soft_link|symlink|symlink_file|symlink_dir|set_permissions)\b|\bDatabase::(create|open|builder)\b|\bBuilder::new\(\)\s*\.\s*create|\.set_len\(|\bNamedTempFile\b|\btempfile::'
CONSOLE_REGEX='\b(println!|print!|eprintln!|eprint!|dbg!)|\b(std::)?io::(stdout|stderr)\b|\bstdout\(\)|\bstderr\(\)'
# Prints "W:<line>:<declaration>" or "C:<line>:<declaration>" for each such `use` declaration of $1
# (the line is the declaration's first).
use_hits() {
  perl -ne '
    if (!defined $s && /^\s*(?:pub(?:\([^)]*\))?\s+)?use\s/) { $s = $.; $t = ""; }
    next unless defined $s;
    $t .= $_;
    next unless /;/;
    (my $u = $t) =~ s/\s+/ /g;
    $u =~ s/^ //;
    my $hidden = $u =~ /[{*]|\bas\b/;
    my $root = $u =~ /\b(?:std|tokio)\b/;
    if ($hidden && $root && $u =~ /\bfs\b/
        && ($u =~ /\bfs::\*|\bfs::\{[^}]*\*/
            || $u =~ /\b(?:write|copy|rename|remove_file|remove_dir|remove_dir_all|create_dir|create_dir_all|hard_link|soft_link|symlink|symlink_file|symlink_dir|set_permissions)\b/
            || $u =~ /\b(?:self|fs|File)\s+as\b/)) {
      print "W:$s:$u\n";
    }
    if ($hidden && $root && $u =~ /\bio\b/
        && ($u =~ /\bio::\*|\bio::\{[^}]*\*/ || $u =~ /\b(?:stdout|stderr)\b/)) {
      print "C:$s:$u\n";
    }
    undef $s;
  ' "$1"
}
while IFS= read -r f; do
  [ -n "$f" ] || continue
  rel="${f#"$GHOST_ROOT"/}"
  case "$rel" in
    issuer/crates/service/src/status.rs | issuer/crates/service/src/store.rs | \
      issuer/crates/service/src/journal.rs | issuer/crates/service/src/payout.rs | \
      issuer/crates/ops/src/output.rs) may_write=1 ;;
    *) may_write=0 ;;
  esac
  case "$rel" in
    issuer/crates/ops/src/report.rs) may_print=1 ;;
    *) may_print=0 ;;
  esac
  if [ "$may_write" = 0 ]; then
    hits="$(grep -nP -- "$WRITE_REGEX" "$f" || true)"
    [ -z "$hits" ] || while IFS= read -r line; do fail "$f:$line: writes a file outside the issuer's output modules"; done <<< "$hits"
  fi
  if [ "$may_print" = 0 ]; then
    hits="$(grep -nP -- "$CONSOLE_REGEX" "$f" || true)"
    [ -z "$hits" ] || while IFS= read -r line; do fail "$f:$line: writes to the console outside ops/src/report.rs"; done <<< "$hits"
  fi
  hits="$(use_hits "$f")"
  [ -z "$hits" ] || while IFS= read -r hit; do
    kind="${hit%%:*}"
    rest="${hit#*:}"
    line="${rest%%:*}"
    decl="${rest#*:}"
    if [ "$kind" = W ] && [ "$may_write" = 0 ]; then
      fail "$f:$line: imports a file write outside the issuer's output modules: $decl"
    elif [ "$kind" = C ] && [ "$may_print" = 0 ]; then
      fail "$f:$line: imports console output outside ops/src/report.rs: $decl"
    fi
  done <<< "$hits"
done < <(find "$GHOST_ROOT/issuer" -path '*/target' -prune -o -type f -name '*.rs' -path '*/src/*' -print 2>/dev/null || true)
finish issuer-output
