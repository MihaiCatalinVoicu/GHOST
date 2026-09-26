package org.ghost.messaging.evasion

// An annotation on the catch parameter. Expected: line 5.
internal object AnnotatedCatch {
    fun run(block: () -> Unit) { try { block() } catch (@Suppress("TooGenericExceptionCaught") e: Exception) { } }
}
