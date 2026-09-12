#!/usr/bin/env bash
# Gate (§11.1, ADR-10): no free-form logging primitives on the production path. Structured,
# allowlisted telemetry goes through a dedicated module reviewed under the logging policy.
source "$(dirname "${BASH_SOURCE[0]}")/common.sh"
KT_REGEX='\bLog\.[dievw]\(|\bprintln\(|\bprint\(|printStackTrace\(|System\.(out|err)\b|\bTimber\b|android\.util\.Log'
RS_REGEX='\b(println!|print!|eprintln!|eprint!|dbg!)'
# One exemption (Phase 8 design §14.1, §19.17; ADR-26 point 7): the report module of the operator
# tools, the only one that prints, keeps println!/eprintln! for its fixed-vocabulary lines; print!,
# eprint! and dbg! stay banned there. The path is exact: a report.rs anywhere else is not exempt.
OPS_REPORT="$GHOST_ROOT/issuer/crates/ops/src/report.rs"
RS_REPORT_REGEX='\b(print!|eprint!|dbg!)'
while IFS= read -r f; do
  [ -n "$f" ] || continue
  hits="$(grep -nP -- "$KT_REGEX" "$f" || true)"
  [ -z "$hits" ] || while IFS= read -r line; do fail "$f:$line"; done <<< "$hits"
done < <(android_main_files)
while IFS= read -r f; do
  [ -n "$f" ] || continue
  regex="$RS_REGEX"
  [ "$f" != "$OPS_REPORT" ] || regex="$RS_REPORT_REGEX"
  hits="$(grep -nP -- "$regex" "$f" || true)"
  [ -z "$hits" ] || while IFS= read -r line; do fail "$f:$line"; done <<< "$hits"
done < <(rust_src_files)
finish no-logging
