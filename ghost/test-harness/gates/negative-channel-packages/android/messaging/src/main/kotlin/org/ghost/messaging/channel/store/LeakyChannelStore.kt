package org.ghost.messaging.channel.store

import java.net.Socket

/**
 * Negative fixture for the scopes of the source gates (Phase 10, slice S3, design faza10-forum.md
 * section 13.1, the row of the hygiene gates): one violation of each, in the package of the channel
 * stores. A gate that read only the DM packages by name would pass this file.
 */
internal class LeakyChannelStore {
    val label = "placeholder row"

    fun report() {
        println("channel row")
    }

    fun guarded(): Int = try {
        1
    } catch (e: Exception) {
        0
    }

    companion object {
        const val PUT = "INSERT OR REPLACE INTO ch_post(op_id) VALUES (?)"
        const val INDEX = "CREATE VIRTUAL TABLE ch_post_index USING fts5(body)"
    }
}
