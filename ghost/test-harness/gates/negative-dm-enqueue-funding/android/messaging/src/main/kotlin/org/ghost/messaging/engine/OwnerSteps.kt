package org.ghost.messaging.engine

/**
 * The allowed step, so the fixture is not vacuous: real callers must exist, one of them of
 * `Funding.set` (an allowed file may fund; the rule is about where the call may be written).
 */
internal class OwnerSteps(private val sync: SyncPorts) {
    fun keeper(tx: Any) {
        sync.capabilities.put(tx, 1, 2, 3)
    }

    fun fund(tx: Any, ns: Any) {
        sync.funding.set(tx, ns, true)
    }
}
