# Fixtures of the `spikes/` exemption of the JNI source halves (G-R6, G-M6)

`common.sh`'s `jni_rust_files` skips the one directory `spikes/` directly under the scan root:
evidence tooling (the Phase 11 S0 media spike has a crash-probe crate that exports a `Java_…` symbol
on purpose), never linked into a shipped library; each gate's library half still reads what a built
library exports. Two scan roots, each holding the same export:

- `exempt/`: under `spikes/media-s0/…` — both gates accept it.
- `nested/`: under `client-core/spikes/…` — not the exempt path, so both gates report the export.

`exempt/vectors-entry.rs` writes `MlsVectors.run`, the one test entry point G-M6 requires of its scan
root, so that root is otherwise clean. `exempt/media-surface.rs` (slice S2) writes the media surface
`MEDIA_CLOSED_LIST` requires of a G-R6 scan root — the gate's media half (G-M5) reads emission from
the same scan, so a root pointed at this tree must emit sealBegin through sniff exactly.
