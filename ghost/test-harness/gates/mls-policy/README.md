# Fixtures for the channel clauses of rust-feature-policy.sh (G-M2, G-R2)

Used by `scripts/gates/self-test.sh` (Phase 10 design faza10-forum.md §3.2, §12.1, §13.1; slice S2a)
through the gate's hooks. `stub-nonempty` and `stub-extra` stand in for the `openmls_sqlite_storage`
stand-in (`GHOST_POLICY_STUB_DIR`): the reviewed manifest and README with a non-empty `lib.rs`, and
with a build script beside an empty one. `sources` is a source root (`GHOST_POLICY_MLS_SOURCES`):
`mls/src/group.rs` names the memory storage across a line, calls `build_with_new_signer` and
`store_pending_proposal` across lines (three violations) and mentions forbidden names in a comment,
a string and a longer identifier (none counts); `mls/src/target/mod.rs` calls `export_group_info` in a
module directory named `target`, which is read (review of S2a, F4: only the root's own `target`,
`mls-kat`, `mls-spike` and `dm-spike` are skipped); `mls-kat/` holds the same calls and is skipped (the
test-only KAT crate). `shipped-config.toml` is a build configuration that names `getrandom_backend`
(`GHOST_POLICY_SHIPPED_CONFIGS`). `fork/` (review of S2a, F7): `Cargo.toml` patches `openmls` with a path fork
beside the stand-in, patches from a git URL and has a `[replace]` (`GHOST_POLICY_ROOT_MANIFEST`: four
violations), and `Cargo.lock` holds a path package outside the workspace, a git source and a registry
package without its checksum (`GHOST_POLICY_LOCK`: three). Nothing here is compiled or shipped.
