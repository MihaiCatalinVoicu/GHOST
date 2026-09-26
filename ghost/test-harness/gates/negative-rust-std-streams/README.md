# Negative fixture for no-logging.sh (G-R4's source half): a standard stream without a print macro

Used by `scripts/gates/self-test.sh` with `GHOST_ROOT` pointing here (Phase 9 design §22.33 item 16).
`client-core/dm/src/lib.rs` writes to the process's error stream with `writeln!`, which no print
macro of the old list named. Exactly one violation, line 7.
