package org.ghost.storage

/**
 * G-DM4 negative fixture. Expected: 3 violations, on lines 18, 27 and 32: a constraint conflict
 * clause and a template-built REPLACE inside migration 5, and an upsert on a DM table in a later
 * migration. The pre-DM REPLACE on line 14 is not DM SQL and must not be reported.
 */
object Schema {
    val migrations = listOf(migration1(), migration5Tables(), migration6())

    private fun migration1(): List<String> = listOf(
        "CREATE TABLE revocations (identity_public_key BLOB PRIMARY KEY, certificate BLOB)",
        // Not DM SQL: Phase 3's revocation cache.
        "INSERT OR REPLACE INTO revocations(identity_public_key, certificate) VALUES (?, ?)",
    )

    private fun migration5Tables(): List<String> = listOf(
        "CREATE TABLE dm_contact (contact_id BLOB PRIMARY KEY ON CONFLICT REPLACE)",
        guard("dm_contact"),
        replaceAll("dm_contact"),
    )

    private fun guard(table: String): String =
        """CREATE TRIGGER ${table}_no_replace BEFORE INSERT ON $table
                BEGIN SELECT RAISE(ABORT, '$table rows are never replaced'); END"""

    private fun replaceAll(table: String): String = "INSERT OR ${"REPLACE"} INTO $table SELECT * FROM $table"

    val expectedTables: Set<String> = setOf("dm_contact")

    private fun migration6(): List<String> = listOf(
        "INSERT INTO dm_contact(contact_id) VALUES (x'00') ON CONFLICT(contact_id) DO UPDATE SET contact_id = excluded.contact_id",
    )
}
