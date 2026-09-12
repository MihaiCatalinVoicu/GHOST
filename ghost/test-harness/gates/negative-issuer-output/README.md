# Negative fixtures for issuer-output.sh

Each file mirrors a module of `ghost/issuer/crates/*/src` (Phase 8 design §6.5, §14.1, §19.17
point 4). `scripts/gates/self-test.sh` runs `issuer-output.sh` with `GHOST_ROOT` pointed here and
requires every forbidden write to be reported by file and line, and the allowed ones (a file write
in `status.rs`, `store.rs` and `ops/src/output.rs`, a console line in `ops/src/report.rs`) not to
be. Nothing here is compiled or shipped.
