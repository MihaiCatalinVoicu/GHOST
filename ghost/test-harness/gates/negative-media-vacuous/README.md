# Negative fixture for the gates whose scope names `:media`: the module moved away

Used by `scripts/gates/self-test.sh` with `GHOST_ROOT` pointing here (Phase 11 design `faza11-media.md` section 13.1
and section 16.1, the row of the existing gates; slice S3). `:messaging`, `:crypto-bridge`, `:sync` and
`:entitlement` are clean and complete, `Schema.kt` carries the migration 5 markers with a `dm_`, a `ch_` and a
`media_` table between them, and `android/media` is missing. Three gates read `:media` since slice S3 and each must
fail for that reason alone, rather than pass over a module it no longer reads:

| gate | violations |
|---|---|
| `messaging-no-network.sh` (G-DM1) | 1: `android/media/src/main: missing` |
| `sync-no-catch-all.sh` | 1: `android/media/src/main: missing` |
| `dm-no-replace.sh` (G-DM4) | 1: `android/media/src/main: missing` |

Nothing here is compiled or shipped.
