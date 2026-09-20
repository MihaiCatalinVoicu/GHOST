package org.ghost.storage.bad

/**
 * The same forbidden statement as the single-line fixture beside this one, written the way every
 * DDL statement of the real `Schema.kt` is written: a multi-line raw string, with the line break
 * falling between `VIRTUAL` and `TABLE`. `grep` is line oriented, so the line-by-line expression
 * cannot see it and only the newline-squashed pass does (design §13.6 R-M4, §10.7; mutant ME-18).
 *
 * The module is `rtree`, so the token half of the gate reports nothing here and the statement half
 * is proven on its own. The ordinary `CREATE TABLE` above it is there so the gate's vacuity guard
 * is satisfied and the rejection is about the virtual table alone. Nothing here is compiled or
 * shipped.
 */
object SplitVirtualTableSchema {
    val statements: List<String> = listOf(
        """CREATE TABLE dm_message_shadow (
                  message_id BLOB PRIMARY KEY NOT NULL,
                  body_env   BLOB NOT NULL
                ) WITHOUT ROWID""",
        """CREATE VIRTUAL
             TABLE dm_message_search USING rtree(message_id, lo, hi)""",
    )
}
