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
source "$(dirname "${BASH_SOURCE[0]}")/common.sh"
WRITE_REGEX='\bFile::(create|create_new|options)\b|\bOpenOptions\b|\bDirBuilder\b|\bfs::(write|copy|rename|remove_file|remove_dir|remove_dir_all|create_dir|create_dir_all|hard_link|soft_link|symlink|symlink_file|symlink_dir|set_permissions)\b|\bDatabase::(create|open|builder)\b|\bBuilder::new\(\)\s*\.\s*create|\.set_len\(|\bNamedTempFile\b|\btempfile::'
CONSOLE_REGEX='\b(println!|print!|eprintln!|eprint!|dbg!)|\b(std::)?io::(stdout|stderr)\b|\bstdout\(\)|\bstderr\(\)'
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
done < <(find "$GHOST_ROOT/issuer" -path '*/target' -prune -o -type f -name '*.rs' -path '*/src/*' -print 2>/dev/null || true)
finish issuer-output
