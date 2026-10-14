package org.ghost.storage

/**
 * G-DM4 negative fixture (Phase 10, slice S3). The migration 5 region holds a DM table and a channel
 * table (the vacuity the gate needs). Expected in this file: 1 violation, on line 25: a REPLACE on a
 * channel table in a later migration, outside the region, which only the table name reveals. The
 * pre-channel REPLACE on line 14 is not DM SQL and must not be reported.
 */
object Schema {
    val migrations = listOf(migration1(), migration5Tables(), migration8())

    private fun migration1(): List<String> = listOf(
        "CREATE TABLE revocations (identity_public_key BLOB PRIMARY KEY, certificate BLOB)",
        "INSERT OR REPLACE INTO revocations(identity_public_key, certificate) VALUES (?, ?)",
    )

    private fun migration5Tables(): List<String> = listOf(
        "CREATE TABLE dm_contact (contact_id BLOB PRIMARY KEY)",
        "CREATE TABLE ch_channel (channel_id BLOB PRIMARY KEY)", "CREATE TABLE media_object (object_id BLOB PRIMARY KEY)",
    )

    val expectedTables: Set<String> = setOf("dm_contact", "ch_channel")

    private fun migration8(): List<String> = listOf(
        "INSERT OR REPLACE INTO ch_channel(channel_id) VALUES (x'00')",
    )
}
