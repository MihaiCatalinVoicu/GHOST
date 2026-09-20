package org.ghost.messaging.engine

/** The allowed step, so the fixture is not vacuous: one real caller must exist. */
internal class OwnerSteps(private val sync: SyncPorts) {
    fun keeper(tx: Any) {
        sync.capabilities.put(tx, 1, 2, 3)
    }
}
