package org.ghost.messaging.evasion

// The API that replaces by name. Expected: line 6.
internal object ReplaceOrThrow {
    fun put(db: net.zetetic.database.sqlcipher.SQLiteDatabase) {
        db.replaceOrThrow("dm_message", "message_id", null)
    }
}
