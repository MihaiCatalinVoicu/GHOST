package org.ghost.messaging.evasion

// The qualified type written across lines. Expected: line 5.
internal object SplitType {
    fun run(block: () -> Unit) { try { block() } catch (e: java
        .lang.Throwable) { } }
}
