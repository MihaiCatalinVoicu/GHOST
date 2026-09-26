package org.ghost.messaging.evasion

// The algorithm as the named constant, handed to whatever takes an int. Expected: line 5.
internal object ConflictReplaceConstant {
    val algorithm: Int = net.zetetic.database.sqlcipher.SQLiteDatabase.CONFLICT_REPLACE
}
