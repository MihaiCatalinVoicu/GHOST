package org.ghost.messaging.engine

/** The allowed step, so the fixture is not vacuous: one real caller must exist. */
internal class OwnerSteps(private val sync: SyncPorts) {
    fun regrows(tx: Any) {
        sync.registrations.request(tx, 1, 2, 3)
    }
}
