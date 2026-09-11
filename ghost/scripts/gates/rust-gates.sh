#!/usr/bin/env bash
# Rust gates (ADR-10): format, lint as errors, tests, cargo-deny (licenses/bans/sources/advisories),
# the client package allowlist (T7) and the Arti feature policy.
source "$(dirname "${BASH_SOURCE[0]}")/common.sh"
cd "$GHOST_ROOT"
cargo fmt --all -- --check || fail "rustfmt"
cargo clippy --locked --workspace --all-targets -- -D warnings || fail "clippy"
cargo test --locked --workspace || fail "cargo test"
if command -v cargo-deny >/dev/null; then cargo deny check || fail "cargo deny"; else echo "cargo-deny missing (install: cargo install cargo-deny)" >&2; FAILURES=$((FAILURES+1)); fi
bash "$GATES_DIR/rust-client-allowlist.sh" || fail "rust-client-allowlist"
bash "$GATES_DIR/rust-feature-policy.sh" || fail "rust-feature-policy"
bash "$GATES_DIR/clippy-clearnet-fixture.sh" || fail "clippy-clearnet-fixture"
finish rust-gates
