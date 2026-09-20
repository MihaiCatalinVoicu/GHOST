# Negative fixture for the dm-no-fts gate: the `fts` token

Used by `scripts/gates/self-test.sh` with `GHOST_ROOT` pointing here. `SearchIndexSchema.kt`,
under `android/storage/src/main`, reaches a full-text index without writing
`CREATE VIRTUAL TABLE` — it names the module in a pragma and writes the shadow table by hand —
which is why G-DM6 rejects the token as well as the statement (Phase 9 design §13.6 R-M4; mutant
ME-18). Exactly three lines carry the token, the fixture holds no virtual table, and it carries an
ordinary `CREATE TABLE` so the vacuity guard is satisfied: the two halves of the gate stay
single-purpose, the statement half being `negative-dm-fts-virtual`.

`shifts`, `drafts` and `lifts` appear on purpose: the token match must not fire on a word that
merely ends in those three letters. Nothing here is compiled or shipped.
