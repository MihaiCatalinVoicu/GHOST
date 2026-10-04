package org.ghost.storage

object Schema {
    private fun migration5Tables(): List<String> = listOf(
        "CREATE TABLE dm_held (held_id BLOB PRIMARY KEY)",
        "CREATE TABLE ch_channel (channel_id BLOB PRIMARY KEY)",
    )

    val expectedTables: Set<String> = setOf("dm_held")
}
