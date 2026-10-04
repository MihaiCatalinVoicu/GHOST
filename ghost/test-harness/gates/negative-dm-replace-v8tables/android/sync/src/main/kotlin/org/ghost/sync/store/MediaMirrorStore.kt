package org.ghost.sync.store

/**
 * G-DM4 negative fixture (Phase 11, slice S3): the media tables named outside the media module, which only their
 * names reveal. Three violations; everything after them must not count.
 */
internal class MediaMirrorStore {
    fun upsertOperation(): String =
        "INSERT INTO media_outbound_op(operation_id) VALUES (?) ON CONFLICT(operation_id) DO UPDATE SET operation_id = excluded.operation_id"

    fun shoutingReplace(): String = "INSERT OR REPLACE INTO MEDIA_OBJECT(object_id) VALUES (?)"

    fun mixedCase(): String = "REPLACE INTO Media_Upload(object_id) VALUES (?)"

    fun guardedUpdate(): String = "UPDATE media_blob SET retain_until_day = ? WHERE blob_hash = ?"

    fun guardedInsert(): String =
        "INSERT INTO media_blob(blob_hash, file_name) SELECT ?, ? WHERE NOT EXISTS (SELECT 1 FROM media_blob WHERE blob_hash = ?)"

    fun ignore(): String = "INSERT OR IGNORE INTO media_blob(blob_hash) VALUES (?)"

    fun doNothing(): String = "INSERT INTO media_blob(blob_hash) VALUES (?) ON CONFLICT DO NOTHING"

    fun rename(): String = "SELECT replace(file_name, 'a', 'b') FROM media_blob"

    fun endsLikeAMediaTable(): String = "INSERT OR REPLACE INTO social_media_cache(k) VALUES (?)"

    fun startsLikeOne(): String = "INSERT OR REPLACE INTO mediate_log(k) VALUES (?)"
}
