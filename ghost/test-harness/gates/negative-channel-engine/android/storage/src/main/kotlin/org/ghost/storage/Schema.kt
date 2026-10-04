package org.ghost.storage

/** Only what the DM SQL gates need to find: the migration 5 markers with a DM table and a channel table between them. */
object Schema {
    private fun migration5Tables(): List<String> = listOf(
        "CREATE TABLE dm_contact (contact_id BLOB PRIMARY KEY)",
        "CREATE TABLE ch_channel (channel_id BLOB PRIMARY KEY)",
    )

    val expectedTables: Set<String> = setOf("dm_contact", "ch_channel")
}
