# Negative fixture for the dm-no-replace gate (G-DM4): REPLACE in the DM schema

Used by `scripts/gates/self-test.sh` (Phase 9 design §22.33). `Schema.kt` holds a constraint conflict
clause (line 18) and a template-built REPLACE (line 27) inside migration 5, and an upsert on a DM table
in a later migration (line 32): 3 violations. The pre-DM REPLACE of line 14 and the sync upsert of
`CursorStore.kt` are not DM SQL and must not count. Nothing here is compiled or shipped.
