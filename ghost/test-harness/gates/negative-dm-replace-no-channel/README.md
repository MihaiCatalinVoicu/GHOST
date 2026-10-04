# Negative fixture for the dm-no-replace gate (G-DM4): the migration 5 region without a channel table

Used by `scripts/gates/self-test.sh` (Phase 10 design `faza10-forum.md` section 9, "Migration 7"; slice S3).
`Schema.kt` keeps the two migration 5 markers and a `dm_` table between them but no `ch_` table, as if migration 7
had moved out of the region the gate reads: the gate must say so (1 violation) rather than pass over the channel
tables. Nothing here is compiled or shipped.
