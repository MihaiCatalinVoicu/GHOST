package org.ghost.messaging.nearmiss

/**
 * Nothing here replaces a row. The prose may name insertWithOnConflict(..., 5), ContentValues and
 * CONFLICT_REPLACE: comments are not code.
 */
internal object NearMisses {
    val statements = listOf(
        "SELECT replace(message_id, x'00', x'01') FROM dm_message",
        "INSERT OR IGNORE INTO dm_message(message_id) VALUES (?)",
        "INSERT INTO dm_message(message_id) VALUES (?) ON CONFLICT(message_id) DO NOTHING",
        "SELECT 1 FROM dm_message WHERE message_id = ? OR " + "message_id IS NULL",
        "CREATE TRIGGER dm_message_no_replace BEFORE INSERT ON dm_message " +
            "BEGIN SELECT RAISE(ABORT, 'dm_message rows are never replaced'); END",
    )

    fun label(name: String) = name.replace("_", "-")
}
