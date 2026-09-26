package org.ghost.messaging.evasion

// A suspending function type with a receiver: no suspend fun anywhere. Expected: line 5.
internal class Step {
    private val onCommit: suspend Step.() -> Unit = {}
}
