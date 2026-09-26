package org.ghost.messaging.evasion

// A comment inside the parentheses. Expected: line 5.
internal object CommentInCatch {
    fun run(block: () -> Unit) { try { block() } catch (e: /* anything */ Throwable) { } }
}
