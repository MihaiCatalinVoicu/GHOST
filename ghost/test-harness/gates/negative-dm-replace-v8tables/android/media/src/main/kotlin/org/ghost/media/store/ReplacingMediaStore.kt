package org.ghost.media.store

/**
 * G-DM4 negative fixture (Phase 11, slice S3): the media store is read whole, so every literal in it is DM SQL
 * whatever table it names, and the conflict-algorithm APIs are refused in it. Five violations; the guarded
 * UPDATE-then-INSERT form, INSERT OR IGNORE and the replace() function below must not count.
 */
internal class ReplacingMediaStore {
    fun upsertBlob(): String =
        "INSERT INTO media_blob(blob_hash, file_name) VALUES (?, ?) ON CONFLICT(blob_hash) DO UPDATE SET file_name = excluded.file_name"

    fun replaceFragment(): String = "INSERT OR REPLACE INTO media_fragment(object_id, ordinal) VALUES (?, ?)"

    fun scratch(): String = "INSERT OR REPLACE INTO scratch(x) VALUES (?)"

    fun values() = ContentValues()

    fun algorithm(db: Any) = db.insertWithOnConflict("media_blob", null, values(), 5)

    fun updateBlob(): String = "UPDATE media_blob SET retain_until_day = ? WHERE blob_hash = ?"

    fun insertBlob(): String =
        "INSERT INTO media_blob(blob_hash, file_name) SELECT ?, ? WHERE NOT EXISTS (SELECT 1 FROM media_blob WHERE blob_hash = ?)"

    fun ignore(): String = "INSERT OR IGNORE INTO media_blob(blob_hash) VALUES (?)"

    fun rename(): String = "SELECT replace(file_name, 'a', 'b') FROM media_blob"
}
