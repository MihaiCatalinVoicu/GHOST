# media-crate-purity.sh fixtures (gate G-M7, Phase 11 design faza11-media.md §13.1, §16.1)

Each directory is a GHOST_ROOT holding a minimal `client-core/media` crate. `good/` must pass (it has
the near misses: banned names in comments and strings, `core::time`, the registry's static in
`src/registry.rs`); every other directory breaks exactly one rule and must fail for that rule's
reason (`scripts/gates/self-test.sh` checks the message).
