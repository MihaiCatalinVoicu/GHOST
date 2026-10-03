package org.ghost.storage

/** Only the markers G-DM4 needs: a migration 5 region with a DM table in it. Nothing here is compiled. */
object Schema {
    private fun migration5Tables(): List<String> = listOf(
        "CREATE TABLE dm_contact (contact_id BLOB PRIMARY KEY)",
    )

    val expectedTables: Set<String> = setOf("dm_contact")
}
