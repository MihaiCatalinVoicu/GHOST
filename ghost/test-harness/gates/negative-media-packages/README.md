# Negative fixture for the scopes of the source gates: the media store package

Used by `scripts/gates/self-test.sh` with `GHOST_ROOT` pointing here (Phase 11 design `faza11-media.md` section 13.1
("`:media` references no `org.ghost.network`, `java.net`, `javax.net`, socket or HTTP class and no coroutines"), section
13.6 ("G-DM4 and G-DM6 cover the media SQL") and section 16.1, the row of the existing gates; slice S3).
`LeakyMediaStore.kt`, in `org.ghost.media.store` of the new module `android/media`, holds one violation of each source gate:

| line | construct | gate | violations |
|---|---|---|---|
| 3 | `import java.net.Socket` | `kotlin-clearnet.sh` (1), `messaging-no-network.sh` G-DM1 (2: the package and the class) | 3 |
| 11 | a string that names a stand-in | `anti-placeholder.sh` | 1 |
| 14 | `println(...)` | `no-logging.sh` | 1 |
| 19 | `catch (e: Exception)` | `sync-no-catch-all.sh` (against an allowlist that lists nothing) | 1 |
| 24 | `INSERT OR REPLACE INTO media_blob` | `dm-no-replace.sh` G-DM4 | 1 |
| 25 | `CREATE VIRTUAL TABLE ... USING fts5(...)` | `dm-no-fts.sh` G-DM6 (the statement and the token) | 2 |

The other files are the clean minimum each gate needs not to pass vacuously (`:messaging` with an SQL string,
`:crypto-bridge`, `:sync`, `:entitlement`, a `Schema.kt` with the migration 5 markers and a `dm_`, a `ch_` and a `media_`
table between them). A gate whose scope named the DM modules one by one, or the packages of `:messaging`, would pass this
tree. The second half of each gate is the run against the real tree. Nothing here is compiled or shipped.
