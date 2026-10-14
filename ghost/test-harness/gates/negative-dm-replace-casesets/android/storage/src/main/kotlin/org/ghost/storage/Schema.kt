package org.ghost.storage

/**
 * G-DM4 negative fixture (Phase 10, slice S3 review). The migration 5 region holds a DM table and a channel
 * table (the vacuity the gate needs); nothing in this file is a violation.
 */
object Schema {
    val migrations = listOf(migration1(), migration5Tables())

    private fun migration1(): List<String> = listOf(
        "CREATE TABLE revocations (identity_public_key BLOB PRIMARY KEY, certificate BLOB)",
    )

    private fun migration5Tables(): List<String> = listOf(
        "CREATE TABLE dm_contact (contact_id BLOB PRIMARY KEY)",
        "CREATE TABLE ch_channel (channel_id BLOB PRIMARY KEY)", "CREATE TABLE media_object (object_id BLOB PRIMARY KEY)",
    )

    val expectedTables: Set<String> = setOf("dm_contact", "ch_channel")
}
