#!/usr/bin/env bash
# Rust gates (ADR-10): format, lint as errors, tests, cargo-deny (licenses/bans/sources/advisories),
# the client package allowlist (T7), the Arti feature policy with the per-version rsa scopes and
# the crypto version pins (ADR-22), the licence gates G-L1 (Rust notices), G-R5 and G-L4 (ADR-37), the
# Entitlement Schedule (runs ghost-issuer-ops; needs the git history), and Phase 10's channel crate:
# its tests on their own (a workspace build unifies openmls/test-utils from ghost-client-mls-kat into
# it), V10-6 (mls-determinism.sh) and the graph gates G-M4 and G-M8 (G-M1 and G-M2 are clauses of the
# allowlist and the feature policy; G-M3 runs in run-all.sh; G-M9 needs a build's messages: the CI job).
source "$(dirname "${BASH_SOURCE[0]}")/common.sh"
cd "$GHOST_ROOT"
cargo fmt --all -- --check || fail "rustfmt"
cargo clippy --locked --workspace --all-targets -- -D warnings || fail "clippy"
cargo test --locked --workspace --exclude ghost-client-mls || fail "cargo test"
cargo test --locked -p ghost-client-mls || fail "cargo test -p ghost-client-mls"
cargo test --locked -p ghost-client-mls --features jni-bridge,test-vectors --lib -- jni:: testvec:: \
  || fail "cargo test -p ghost-client-mls (its JNI layer, slice S2b)"
bash "$GHOST_ROOT/scripts/ci/mls-determinism.sh" || fail "mls-determinism (V10-6)"
# The issuer crash suite runs in the release profile (Phase 8 design §19.17 point 2; CI job rust).
cargo test --locked --release -p ghost-issuer --test crash || fail "issuer crash suite (release)"
if command -v cargo-deny >/dev/null; then cargo deny check || fail "cargo deny"; else echo "cargo-deny missing (install: cargo install cargo-deny)" >&2; FAILURES=$((FAILURES+1)); fi
bash "$GATES_DIR/rust-client-allowlist.sh" || fail "rust-client-allowlist"
bash "$GATES_DIR/rust-feature-policy.sh" || fail "rust-feature-policy"
bash "$GATES_DIR/rust-crypto-pins.sh" || fail "rust-crypto-pins"
# The S0′ gate slice (Phase 9 design §16.1, §22.33): G-R4's graph half, G-R7 (against HEAD~1 unless
# GHOST_GOLDEN_BASE names another base) and G-R8. G-R3 needs a build's outputs: the CI jobs run it.
bash "$GATES_DIR/dm-rust-no-logging.sh" || fail "dm-rust-no-logging"
bash "$GATES_DIR/dm-golden-lock.sh" || fail "dm-golden-lock"
bash "$GATES_DIR/dm-vendored-clock-log.sh" || fail "dm-vendored-clock-log"
bash "$GATES_DIR/mls-rust-no-logging.sh" || fail "mls-rust-no-logging"
bash "$GATES_DIR/mls-vendored-clock-log.sh" || fail "mls-vendored-clock-log"
# Phase 11's media crate (design faza11-media.md §16.1 G-M7; slice S1): G-R4's graph half and G-R8 for
# its graph (G-R1 and G-R2 are clauses of the allowlist and the feature policy above; its tests run
# with the workspace's).
bash "$GATES_DIR/media-rust-no-logging.sh" || fail "media-rust-no-logging"
bash "$GATES_DIR/media-vendored-clock-log.sh" || fail "media-vendored-clock-log"
# Licence gates (ADR-37; Phase 9 design §2.10.2): notices of the shipped Rust graphs (G-L1), source
# headers (G-R5), MPL-2.0 sources and their bundle (G-L4).
bash "$GATES_DIR/license-notices.sh" rust || fail "license-notices (rust)"
bash "$GATES_DIR/rust-license-headers.sh" || fail "rust-license-headers"
mpl_bundle="$(mktemp -d)"
bash "$GATES_DIR/mpl-sources.sh" --bundle "$mpl_bundle" || fail "mpl-sources"
rm -rf "$mpl_bundle"
bash "$GATES_DIR/entitlement-schedule.sh" || fail "entitlement-schedule"
# G-D11 (Phase 14, slice S6f): the wire transcript is a golden artifact — the generator drives
# every client RPC over loopback TCP and the committed file must diff equal to a regeneration
# (the wire half of NI-U5's two-release comparison harness).
bash "$GATES_DIR/wire-transcript.sh" || fail "wire-transcript"
# G-D6 (Phase 14 design §12.1): ghost-client-update in the shipped graph with no feature of
# its own (the mutants switch, G-R2's method) and the crate's source purity (no fs/net/clock/log).
bash "$GATES_DIR/update-rust-purity.sh" || fail "update-rust-purity"
bash "$GATES_DIR/clippy-clearnet-fixture.sh" || fail "clippy-clearnet-fixture"
finish rust-gates
