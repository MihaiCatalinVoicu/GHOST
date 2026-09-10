#!/usr/bin/env bash
# Gate (§11.1, ADR-10): no free-form logging primitives on the production path. Structured,
# allowlisted telemetry goes through a dedicated module reviewed under the logging policy.
source "$(dirname "${BASH_SOURCE[0]}")/common.sh"
KT_REGEX='\bLog\.[dievw]\(|\bprintln\(|\bprint\(|printStackTrace\(|System\.(out|err)\b|\bTimber\b|android\.util\.Log'
RS_REGEX='\b(println!|print!|eprintln!|eprint!|dbg!)'
while IFS= read -r f; do
  [ -n "$f" ] || continue
  hits="$(grep -nP -- "$KT_REGEX" "$f" || true)"
  [ -z "$hits" ] || while IFS= read -r line; do fail "$f:$line"; done <<< "$hits"
done < <(android_main_files)
while IFS= read -r f; do
  [ -n "$f" ] || continue
  hits="$(grep -nP -- "$RS_REGEX" "$f" || true)"
  [ -z "$hits" ] || while IFS= read -r line; do fail "$f:$line"; done <<< "$hits"
done < <(rust_src_files)
finish no-logging
