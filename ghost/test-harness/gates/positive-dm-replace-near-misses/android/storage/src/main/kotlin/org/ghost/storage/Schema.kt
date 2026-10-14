package org.ghost.storage

// Vacuity only: migration 5 holds one DM table between its markers.
object Schema {
    fun migration5Tables(): List<String> = listOf(
        "CREATE TABLE dm_message (message_id BLOB PRIMARY KEY)",
        "CREATE TABLE ch_channel (channel_id BLOB PRIMARY KEY)", "CREATE TABLE media_object (object_id BLOB PRIMARY KEY)",
    )

    val expectedTables: Set<String> = setOf("dm_message")
}
