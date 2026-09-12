#!/usr/bin/env bash
# Rust gates (ADR-10): format, lint as errors, tests, cargo-deny (licenses/bans/sources/advisories),
# the client package allowlist (T7), the Arti feature policy with the per-version rsa scopes and
# the crypto version pins (ADR-22), and the Entitlement Schedule (runs ghost-issuer-ops; needs the
# git history).
source "$(dirname "${BASH_SOURCE[0]}")/common.sh"
cd "$GHOST_ROOT"
cargo fmt --all -- --check || fail "rustfmt"
cargo clippy --locked --workspace --all-targets -- -D warnings || fail "clippy"
cargo test --locked --workspace || fail "cargo test"
# The issuer crash suite runs in the release profile (Phase 8 design §19.17 point 2; CI job rust).
cargo test --locked --release -p ghost-issuer --test crash || fail "issuer crash suite (release)"
if command -v cargo-deny >/dev/null; then cargo deny check || fail "cargo deny"; else echo "cargo-deny missing (install: cargo install cargo-deny)" >&2; FAILURES=$((FAILURES+1)); fi
bash "$GATES_DIR/rust-client-allowlist.sh" || fail "rust-client-allowlist"
bash "$GATES_DIR/rust-feature-policy.sh" || fail "rust-feature-policy"
bash "$GATES_DIR/rust-crypto-pins.sh" || fail "rust-crypto-pins"
bash "$GATES_DIR/entitlement-schedule.sh" || fail "entitlement-schedule"
bash "$GATES_DIR/clippy-clearnet-fixture.sh" || fail "clippy-clearnet-fixture"
finish rust-gates
