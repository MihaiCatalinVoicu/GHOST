# Negative fixture for the dm-no-fts gate: a virtual table split across lines

Used by `scripts/gates/self-test.sh` with `GHOST_ROOT` pointing here. `SplitVirtualTableSchema.kt`,
under `android/storage/src/main`, creates a virtual table whose `CREATE VIRTUAL` and `TABLE` sit on
different lines — the shape every DDL statement of the real `Schema.kt` has, and the one a
line-oriented `grep` cannot match. It exists so the gate's whitespace-normalised pass is proven
rather than assumed (Phase 9 design §13.6 R-M4, §10.7; mutant ME-18).

The module is `rtree`, so the `fts` token half of the gate reports nothing here and the statement
half is proven on its own. The fixture also carries an ordinary `CREATE TABLE`, so the vacuity
guard is satisfied and the rejection is about the virtual table alone. Nothing here is compiled or
shipped.
