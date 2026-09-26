package org.ghost.messaging.store

/**
 * G-DM4 negative fixture. Expected: 5 violations, on lines 19, 20, 21, 23 and 26. Nothing in a
 * comment counts: INSERT OR REPLACE INTO dm_contact written here in prose is not a statement.
 */
internal class ReplacingStore(private val sql: Sql, private val replace: Boolean) {
    // UPDATE OR REPLACE dm_message in a line comment: not a statement either.
    /* A block comment /* nested */ with REPLACE INTO dm_seen inside: still a comment. */
    private val link = "ghost://contact/" // a string holding a double slash does not open a comment
    private val quote = '"' // a quote character does not open a string
    private val decoys = listOf(
        "SELECT replace(body_env, x'00', x'01') FROM dm_message WHERE a = 1 OR replace(b, 'c', 'd') = 'e'",
        "INSERT OR IGNORE INTO dm_seen(tag, until_day) VALUES (?, ?)",
        "INSERT INTO dm_seen(tag) VALUES (?) ON CONFLICT DO NOTHING",
    )

    fun write() {
        sql.exec("INSERT OR REPLACE INTO dm_contact(contact_id) VALUES (?)")
        sql.exec("UPDATE OR REPLACE dm_message SET state = ? WHERE message_id = ?")
        sql.exec("REPLACE INTO dm_seen(tag, until_day) VALUES (?, ?)")
        sql.exec(
            "INSERT INTO dm_self(id) VALUES (?) ON CONFLICT(id) " +
                "DO UPDATE SET id = excluded.id",
        )
        sql.exec("INSERT ${if (replace) "OR REPLACE" else ""} INTO dm_held(held_id) VALUES (?)")
    }

    interface Sql {
        fun exec(statement: String)
    }
}
