# Negative fixture for the dm-no-fts gate: a virtual table

Used by `scripts/gates/self-test.sh` with `GHOST_ROOT` pointing here. `VirtualTableSchema.kt`,
under `android/storage/src/main`, creates a virtual table over the message bodies — R-M4's one
forbidden statement (Phase 9 design §13.6, §10.7; mutant ME-18). The fixture also carries an
ordinary `CREATE TABLE`, so the gate's vacuity guard is satisfied and the rejection is about the
virtual table alone. It names no `fts` token, so the two halves of G-DM6 stay single-purpose:
the token fixture is `negative-dm-fts-token`. Nothing here is compiled or shipped.
