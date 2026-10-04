# Negative fixture for the Rust source finder of `scripts/gates/common.sh` (no-logging.sh)

Used by `scripts/gates/self-test.sh` with `GHOST_ROOT` pointing here (Phase 10 review of S2a, F4).
The finder once pruned every directory named `target` and exempted every file named `main.rs`, so
code under `src/target/` or in a module file `src/x/main.rs` was never read. Exactly two violations:
`client-core/fx/src/target/mod.rs:3` (`eprintln!`) and `client-core/fx/src/x/main.rs:3` (a standard
stream handle); the crate's own `src/main.rs` stays exempt.
