# Scanner fixtures for G-R8 (dm-vendored-clock-log.sh, test-harness/vendored-scan)

Used by `scripts/gates/self-test.sh` (Phase 9 design §22.33 item 16). Each `.rs` file is copied into a
throwaway crate of its own (`src/lib.rs`, a generated `Cargo.toml`) and scanned for
`aarch64-linux-android`; no manifest is committed here, so no workspace ever sees these crates.

| File | What the scan must list |
|---|---|
| `streams.rs` | exactly one site: `stderr clock-log`, line 6 (`writeln!(std::io::stderr(), …)`, no print macro) |
| `unix-socket.rs` | exactly one site: `UnixStream network`, line 5 (`std::os::unix::net` is not `std::net` to a token scan) |
| `clean.rs` | no site: `write!` to a `Formatter`, `writeln!` to a buffer, the words in strings and comments |
| `clock-epoch.rs` | four sites: `UNIX_EPOCH` and `std::time` at the import (line 3), `UNIX_EPOCH` and `elapsed` at the read (line 6); before the Phase 10 review of S2a (F5) only the import was listed |
