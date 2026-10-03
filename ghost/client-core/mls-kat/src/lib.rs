//! `ghost-client-mls-kat` (test-only; design `docs/design/faza10-forum.md` §10.1, §12.2; S0-13): no
//! code of its own. Its integration tests are the MLS WG passive-client replay through `GhostKv`
//! (`tests/passive_client.rs`, the only place with `openmls/test-utils`, gate G-M2) and the
//! independent replay of the channel vector files (`tests/spec_replay.rs`), which shares no code
//! with `ghost-client-mls`. Nothing depends on this package: it is outside every shipped and host
//! graph.
