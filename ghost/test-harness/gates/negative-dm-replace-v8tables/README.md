# Negative fixture for the dm-no-replace gate (G-DM4): REPLACE on the media tables of migration 8

Used by `scripts/gates/self-test.sh` (Phase 11 design `faza11-media.md` section 13.6, "G-DM4 and G-DM6 cover the media
SQL"; slice S3). Nine violations in three places:

| file | line | construct | rule |
|---|---|---|---|
| `android/media/.../store/ReplacingMediaStore.kt` | 10 | upsert on `media_blob` | the media module is read whole |
| | 12 | `INSERT OR REPLACE` on `media_fragment` | |
| | 14 | `INSERT OR REPLACE` on `scratch`, a table that is no media table | the module, not the table name |
| | 16 | `ContentValues` | the conflict-algorithm APIs in a DM module |
| | 18 | `insertWithOnConflict(..., 5)` | |
| `android/sync/.../store/MediaMirrorStore.kt` | 9 | upsert on `media_outbound_op` | a store outside the media module, found by the table name |
| | 11 | `INSERT OR REPLACE` on `MEDIA_OBJECT` | the name is matched without regard to case |
| | 13 | `REPLACE INTO` on `Media_Upload` | |
| `android/storage/.../Schema.kt` | 26 | `INSERT OR REPLACE` on `media_object` in a later migration | outside the migration 5 region |

What must not count: the guarded UPDATE-then-INSERT form the real DAOs use, `INSERT OR IGNORE`, `ON CONFLICT DO NOTHING`,
the `replace()` SQL function, a table that only ends like a media table (`social_media_cache`), a word that only starts
like one (`mediate_log`), the prose in the KDoc, and the pre-DM `INSERT OR REPLACE INTO revocations`. Nothing here is
compiled or shipped.
