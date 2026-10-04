# media-crate-purity.sh fixtures (gate G-M7, Phase 11 design faza11-media.md §13.1, §16.1)

Each directory is a GHOST_ROOT holding a minimal `client-core/media` crate. `good/` must pass (it has
the near misses: banned names in comments and strings, `core::time`, a `'static` lifetime, a
`use std::collections`, the registry's static in `src/registry.rs`, `crate-type = ["rlib"]`); every
other directory breaks exactly one rule and must fail for that rule's reason
(`scripts/gates/self-test.sh` checks the message).

The directories `io-nested-import`, `io-glob-import`, `io-extern-crate`, `io-std-path`, `state-alias`,
`state-once`, `path-attribute`, `include-macro`, `forbid-in-string`, `package-build`, `package-links`,
`spaced-features`, `spaced-dependencies`, `crate-type` and `bin-target` are the evasions the review of
slice S1 found: each passed the gate's first version.
