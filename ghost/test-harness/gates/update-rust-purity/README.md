# Fixture roots for `update-rust-purity.sh` (G-D6)

Each directory mirrors ghost/'s layout (`client-core/rust-dependency-allowlist.txt`,
`client-core/update/src/`) plus a saved `cargo tree` output (`tree.txt`, the
GHOST_D6_TREE hook — the fixtures cannot run cargo). Run by `scripts/gates/self-test.sh`.

| Root | Expected |
|---|---|
| `clean` | passes: one allowlist entry, the crate in the shipped graph with no feature of its own, pure sources |
| `feature` | fails: the `mutants` feature is enabled in the shipped graph |
| `absent` | fails: the crate left the shipped graph (the clause would hold vacuously) |
| `impure` | fails: a source gains `println!` (the purity scan) |
