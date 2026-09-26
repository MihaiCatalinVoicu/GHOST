package org.ghost.messaging.bad

// Negative fixture: a DM step that swallows what it did not expect. Two violations (lines 8, 14).
internal class SwallowingStep(private val work: () -> Unit) {
    fun run() {
        try {
            work()
        } catch (e: Exception) {
            Unit
        }
    }

    fun quietly(): Boolean =
        runCatching { work() }.isSuccess
}
