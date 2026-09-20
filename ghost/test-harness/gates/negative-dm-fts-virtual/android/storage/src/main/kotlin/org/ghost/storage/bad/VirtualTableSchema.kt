package org.ghost.storage.bad

/**
 * A migration that builds a virtual table over DM content. `secure_delete` does not scrub a
 * virtual table's shadow tables, so an expired message would leave its words behind (design
 * §10.7, R-M4, T25, T33; mutant ME-18), and G-DM6 must reject the statement.
 *
 * Exactly one line below is the violation. The ordinary table above it is here so the gate's
 * vacuity guard sees a `CREATE TABLE`, and this fixture names no search module, so the statement
 * half is proven on its own.
 */
object VirtualTableSchema {
    val statements: List<String> = listOf(
        """CREATE TABLE dm_message_shadow (
                  message_id BLOB PRIMARY KEY NOT NULL,
                  body_env   BLOB NOT NULL
                ) WITHOUT ROWID""",
        "CREATE VIRTUAL TABLE dm_message_search USING rtree(message_id, lo, hi)",
    )
}
