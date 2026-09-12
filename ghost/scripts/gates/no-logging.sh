#!/usr/bin/env bash
# Gate (§11.1, ADR-10): no free-form logging primitives on the production path. Structured,
# allowlisted telemetry goes through a dedicated module reviewed under the logging policy.
source "$(dirname "${BASH_SOURCE[0]}")/common.sh"
KT_REGEX='\bLog\.[dievw]\(|\bprintln\(|\bprint\(|printStackTrace\(|System\.(out|err)\b|\bTimber\b|android\.util\.Log'
RS_REGEX='\b(println!|print!|eprintln!|eprint!|dbg!)'
# Phase 8 (design §6.5, §14.1; ADR-26): logging frameworks are banned in every Rust source of the
# production path (issuer, relay and client-core; the S1 scan found no use in relay or
# client-core): the paths `tracing::` and `log::`, the bare macros info!, warn!, error!, debug!,
# trace!, event!, span! (compile_error! and other names ending in them are not matched), and
# bringing either crate in under any name (`use tracing as t;`, `extern crate log as l;`), after
# which `t::info!` would match nothing else.
RS_LOG_REGEX='\b(tracing|log)::|(?<![A-Za-z0-9_:.])(info|warn|error|debug|trace|event|span)!|\b(use|extern\s+crate)\s+(::)?(tracing|log)\b'
# The issuer keeps no logs at all: no issuer crate may depend on a logging crate, in any
# dependency table, under its own name or renamed (`t = { package = "tracing" }`).
LOG_CRATES='tracing|tracing-[A-Za-z0-9_-]+|log|env_logger|log4rs|slog|fern|simplelog'
LOG_DEPENDENCY_REGEX="^[[:space:]]*($LOG_CRATES)[[:space:]]*(=|\\.)|^[[:space:]]*\\[[^]]*dependencies\\.($LOG_CRATES)\\]|package[[:space:]]*=[[:space:]]*\"($LOG_CRATES)\""
# One exemption (Phase 8 design §14.1, §19.17; ADR-26 point 7): the report module of the operator
# tools, the only one that prints, keeps println!/eprintln! for its fixed-vocabulary lines; print!,
# eprint!, dbg! and every logging macro stay banned there. The path is exact: a report.rs anywhere
# else is not exempt.
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
  hits="$(grep -nP -- "$regex|$RS_LOG_REGEX" "$f" || true)"
  [ -z "$hits" ] || while IFS= read -r line; do fail "$f:$line"; done <<< "$hits"
done < <(rust_src_files)
while IFS= read -r m; do
  [ -n "$m" ] || continue
  hits="$(grep -nE -- "$LOG_DEPENDENCY_REGEX" "$m" || true)"
  [ -z "$hits" ] || while IFS= read -r line; do fail "$m:$line: logging crate in an issuer manifest"; done <<< "$hits"
done < <(find "$GHOST_ROOT/issuer" -path '*/target' -prune -o -type f -name Cargo.toml -print 2>/dev/null || true)
finish no-logging
