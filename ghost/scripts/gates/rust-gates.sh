#!/usr/bin/env bash
# Rust gates (ADR-10): format, lint as errors, tests, cargo-deny (licenses/bans/sources/advisories).
source "$(dirname "${BASH_SOURCE[0]}")/common.sh"
cd "$GHOST_ROOT"
cargo fmt --all -- --check || fail "rustfmt"
cargo clippy --workspace --all-targets -- -D warnings || fail "clippy"
cargo test --workspace || fail "cargo test"
if command -v cargo-deny >/dev/null; then cargo deny check || fail "cargo deny"; else echo "cargo-deny missing (install: cargo install cargo-deny)" >&2; FAILURES=$((FAILURES+1)); fi
finish rust-gates
