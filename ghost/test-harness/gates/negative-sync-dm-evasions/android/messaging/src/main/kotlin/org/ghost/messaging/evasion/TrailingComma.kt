package org.ghost.messaging.evasion

// A trailing comma after the parameter. Expected: line 5.
internal object TrailingComma {
    fun run(block: () -> Unit) { try { block() } catch (e: Exception,) { } }
}
