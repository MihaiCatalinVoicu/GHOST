# Negative fixture for the scopes of the source gates: the channel packages and the channel crate

Used by `scripts/gates/self-test.sh` with `GHOST_ROOT` pointing here (Phase 10 design `faza10-forum.md`
§13.1, the row of the hygiene gates "scopes cover `client-core/mls` and the channel packages"; slice S3).
`LeakyChannelStore.kt`, in `org.ghost.messaging.channel.store`, holds one violation of each source gate:

| line | construct | gate | violations |
|---|---|---|---|
| 3 | `import java.net.Socket` | `kotlin-clearnet.sh` (1), `messaging-no-network.sh` G-DM1 (2: the package and the class) | 3 |
| 11 | a string that names a stand-in | `anti-placeholder.sh` | 1 |
| 14 | `println(…)` | `no-logging.sh` | 1 |
| 19 | `catch (e: Exception)` | `sync-no-catch-all.sh` (against an allowlist that lists nothing) | 1 |
| 24 | `INSERT OR REPLACE INTO ch_post` | `dm-no-replace.sh` G-DM4 | 1 |
| 25 | `CREATE VIRTUAL TABLE … USING fts5(…)` | `dm-no-fts.sh` G-DM6 (the statement and the token) | 2 |

`client-core/mls/src/lib.rs` holds a `TODO` without a ticket (`anti-placeholder.sh`) and a `println!`
(`no-logging.sh`): the channel crate is read by the two gates that read Rust. The other files are the clean
minimum each gate needs not to pass vacuously (both DM modules, `:sync`, `:entitlement`, a `Schema.kt` with the
migration 5 markers). Nothing here is compiled or shipped.
