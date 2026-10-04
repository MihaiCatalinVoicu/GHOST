# Negative fixture for the dm-no-replace gate (G-DM4): REPLACE on the channel tables of migration 7

Used by `scripts/gates/self-test.sh` (Phase 10 design `faza10-forum.md` §9, "Migration 7", §13.1; slice S3).
`ChannelMirrorStore.kt`, a store outside `:messaging`, holds an upsert on `mls_global_kv` (line 16), an
`INSERT OR REPLACE` on `ch_post` (line 19) and a `REPLACE INTO` on `mls_kv` (line 22); `Schema.kt` holds
an `INSERT OR REPLACE` on `ch_channel` in a later migration (line 25): 4 violations in all. The channel
tables carry REPLACE guards, so their writers are an UPDATE followed by an INSERT guarded by `WHERE NOT
EXISTS`, which the file also shows and which must not count; neither must a table that only ends like a
channel table (`launch_log`, `research_kv`), a word that only starts with `ch` (`chart_cache`), the pre-channel
REPLACE on `revocations`, or the prose in the KDoc. Nothing here is compiled or shipped.
