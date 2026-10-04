# `openmls_sqlite_storage` 0.3.0 — GHOST stand-in (never compiled)

**Why this exists (design `docs/design/faza10-forum.md` §3.2 "Lock resolution", S0-1, Q40 (a);
narrowed by §19.30 F-6).** `openmls` 0.9.0 declares the *optional* dependency
`openmls_sqlite_storage` 0.3.0 (its forbidden `sqlite-provider` feature), which requires
`rusqlite ^0.37` → `libsqlite3-sys ^0.35` (`links = "sqlite3"`). `ghost-client-net` links
`libsqlite3-sys` 0.37.0 (Arti's directory cache). Cargo resolves an optional dependency that an
enabled feature names, even weakly (`openmls_sqlite_storage?/…`: OpenMLS's PQ and draft-extension
features do), and `links` values must be unique in the resolve, so with such a feature the workspace
does not resolve with the real crate. `ghost/Cargo.toml` therefore patches the name to this
directory:

```toml
[patch.crates-io]
openmls_sqlite_storage = { path = "third_party/openmls-sqlite-storage-stub" }
```

With the features gate G-M2 allows, no feature names the storage, the lock resolves without the
stand-in, and Cargo records the patch as `[[patch.unused]]` and warns that it was not used (S2a
measured both, §19.30 F-6). It stays as Q40 (a) decided.

**What it is.** A manifest of the same name and version, GHOST's own licence, `publish = false`, no
dependency, an empty `src/lib.rs`, and the four feature names `openmls` forwards to it declared
empty. It is a manifest-level stand-in for a forbidden feature, not a modification of OpenMLS's
code: no graph of the workspace enables `sqlite-provider`, so the package is never compiled.

**What checks it (gate G-M2, `scripts/gates/rust-feature-policy.sh`).** The SHA-256 of
`Cargo.toml` and of `src/lib.rs`, that the directory holds nothing else but this README, and that
`cargo tree -i openmls_sqlite_storage` over every graph of the workspace prints nothing.

**When it goes.** When upstream relaxes `rusqlite = "0.37"` (design §18 F-5), or when the owner drops
it on §19.30 F-6's evidence; the alternative of Q40 (pinning Arti's `libsqlite3-sys` to 0.35 with
SQLite 3.50.2) was not chosen.
