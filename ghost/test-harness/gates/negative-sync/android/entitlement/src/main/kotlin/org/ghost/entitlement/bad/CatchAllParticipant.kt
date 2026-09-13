package org.ghost.entitlement.bad

// The session participant must not swallow a JVM error either; the gate must reject every line below.
object CatchAllParticipant {
    fun exception(block: () -> Unit) {
        try { block() } catch (e: Exception) { }
    }

    fun kotlinError(block: () -> Unit) {
        try { block() } catch (e: kotlin.Error) { }
    }

    fun recover(block: () -> Unit) = runCatching { block() }.recoverCatching { }
}
