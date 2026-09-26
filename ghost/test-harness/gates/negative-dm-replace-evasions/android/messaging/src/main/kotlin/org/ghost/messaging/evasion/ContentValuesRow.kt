package org.ghost.messaging.evasion

// The row type every conflict API takes, and the one SQLiteDatabase.replace needs. Expected: line 5.
internal object ContentValuesRow {
    val row = android.content.ContentValues()
}
