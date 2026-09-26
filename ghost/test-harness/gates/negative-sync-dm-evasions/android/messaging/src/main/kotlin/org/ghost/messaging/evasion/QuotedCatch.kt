package org.ghost.messaging.evasion

// A backtick-quoted parameter name. Expected: line 5.
internal object QuotedCatch {
    fun run(block: () -> Unit) { try { block() } catch (`e`: Exception) { } }
}
