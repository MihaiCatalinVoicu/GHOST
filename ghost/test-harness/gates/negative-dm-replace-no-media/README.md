# Negative fixture for the dm-no-replace gate (G-DM4): the media module and its tables are not read

Used by `scripts/gates/self-test.sh` (Phase 11 design `faza11-media.md` section 13.6, "G-DM4 and G-DM6 cover the media
SQL"; slice S3). `Schema.kt` keeps the two migration 5 markers with a `dm_` and a `ch_` table between them but no
`media_` table, as if migration 8 had moved out of the region the gate reads, and the `:media` store holds no SQL string,
as if its SQL had moved out of the module the gate reads whole: the gate must say both (2 violations) rather than pass
over the media tables. Nothing here is compiled or shipped.
