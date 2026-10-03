# Negative fixture for the dm-no-replace gate (G-DM4): REPLACE on the two migration-6 sync tables

Used by `scripts/gates/self-test.sh` (Phase 10 design `faza10-forum.md` §9, "Migration 6"; slice S1a).
`CapabilityStore.kt` holds an upsert on `relay_register_capability` (line 17) and an `INSERT OR REPLACE`
on `sync_namespace_fund` (line 23): 2 violations. Both tables carry REPLACE guards, so their writers are
an UPDATE followed by an INSERT, which the file also shows and which must not count. The upsert on
`relay_capability` (a v2 table, upserted by design), a longer table name that only starts like one of the
two, and the prose in the KDoc must not count either. Nothing here is compiled or shipped.
