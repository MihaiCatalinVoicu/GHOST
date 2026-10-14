package org.ghost.storage

/**
 * G-DM4 negative fixture (Phase 11, slice S3). The migration 5 region holds a DM table, a channel table and a media table
 * (the vacuity the gate needs). Expected in this file: 1 violation, on line 26: a REPLACE on a media table in a later
 * migration, outside the region, which only the table name reveals. The pre-DM REPLACE on line 14 is not DM SQL and must
 * not be reported.
 */
object Schema {
    val migrations = listOf(migration1(), migration5Tables(), migration9())

    private fun migration1(): List<String> = listOf(
        "CREATE TABLE revocations (identity_public_key BLOB PRIMARY KEY, certificate BLOB)",
        "INSERT OR REPLACE INTO revocations(identity_public_key, certificate) VALUES (?, ?)",
    )

    private fun migration5Tables(): List<String> = listOf(
        "CREATE TABLE dm_contact (contact_id BLOB PRIMARY KEY)",
        "CREATE TABLE ch_channel (channel_id BLOB PRIMARY KEY)",
        "CREATE TABLE media_object (object_id BLOB PRIMARY KEY)",
    )

    val expectedTables: Set<String> = setOf("dm_contact", "ch_channel", "media_object")

    private fun migration9(): List<String> = listOf(
        "INSERT OR REPLACE INTO media_object(object_id) VALUES (x'00')",
    )
}
