package org.ghost.storage.bad

/** A production source with no SQL in it: the gate must report that it scanned nothing useful. */
object NoSql {
    fun describe(): String = "the schema lives somewhere else now"
}
