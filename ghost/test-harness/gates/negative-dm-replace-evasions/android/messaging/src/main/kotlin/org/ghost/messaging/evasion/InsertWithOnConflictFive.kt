package org.ghost.messaging.evasion

// The Android API with the algorithm as an int; 5 is CONFLICT_REPLACE. Expected: line 6.
internal object InsertWithOnConflictFive {
    fun put(db: net.zetetic.database.sqlcipher.SQLiteDatabase) {
        db.insertWithOnConflict("dm_message", "message_id", null, 5)
    }
}
