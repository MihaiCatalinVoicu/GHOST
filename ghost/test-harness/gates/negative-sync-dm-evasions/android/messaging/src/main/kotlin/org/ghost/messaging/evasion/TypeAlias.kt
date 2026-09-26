package org.ghost.messaging.evasion

// An alias of Throwable; the catch that names it matches no catch-all type. Expected: line 4.
internal typealias Oops = Throwable

internal object TypeAlias {
    fun run(block: () -> Unit) { try { block() } catch (e: Oops) { } }
}
