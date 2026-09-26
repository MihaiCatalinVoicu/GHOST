package org.ghost.messaging.evasion

// The modifier and the fun keyword on two lines, which is legal Kotlin. Expected: line 5.
internal object SuspendSplit {
    suspend
    fun send(envelope: ByteArray): Int = envelope.size
}
