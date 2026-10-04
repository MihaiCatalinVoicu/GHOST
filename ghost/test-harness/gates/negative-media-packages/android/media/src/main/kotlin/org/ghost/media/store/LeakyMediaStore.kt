package org.ghost.media.store

import java.net.Socket

/**
 * Negative fixture for the scopes of the source gates (Phase 11, slice S3, design faza11-media.md section 13.1 and
 * section 16.1, the row of the existing gates): one violation of each, in the package of the media store. A gate that
 * read only the DM modules by name would pass this file.
 */
internal class LeakyMediaStore {
    val label = "placeholder row"

    fun report() {
        println("media row")
    }

    fun guarded(): Int = try {
        1
    } catch (e: Exception) {
        0
    }

    companion object {
        const val PUT = "INSERT OR REPLACE INTO media_blob(blob_hash) VALUES (?)"
        const val INDEX = "CREATE VIRTUAL TABLE media_blob_index USING fts5(name)"
    }
}
