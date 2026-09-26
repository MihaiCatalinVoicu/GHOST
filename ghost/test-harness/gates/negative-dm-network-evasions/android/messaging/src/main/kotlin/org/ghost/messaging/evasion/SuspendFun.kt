package org.ghost.messaging.evasion

// A suspending function: a coroutine without any import. Expected: line 4.
internal suspend fun send(envelope: ByteArray): Int = envelope.size
