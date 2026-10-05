package org.ghost.media.store

/** The clean minimum the media scopes of the source gates need: a store that names no network, no catch-all and no conflict clause. */
internal class CleanMediaStore {
    fun update(): String = "UPDATE media_blob SET retain_until_day = ? WHERE blob_hash = ?"

    fun insert(): String =
        "INSERT INTO media_blob(blob_hash, file_name) SELECT ?, ? WHERE NOT EXISTS (SELECT 1 FROM media_blob WHERE blob_hash = ?)"
}
