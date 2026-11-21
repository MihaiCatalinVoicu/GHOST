package org.ghost.app.ui

import org.ghost.ui.gateway.LockGateway

/** Synchronous bridge for the debug-only instrumentation, in the UI adapter layer that owns coroutines. */
object GateLock {
    fun configureIfNeeded(lock: LockGateway, digits: CharArray) {
        kotlinx.coroutines.runBlocking {
            if (!lock.isConfigured()) lock.setPin(digits)
        }
    }
}
