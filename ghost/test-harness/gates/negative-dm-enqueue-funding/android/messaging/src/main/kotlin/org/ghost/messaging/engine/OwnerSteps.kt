package org.ghost.messaging.engine

/**
 * The allowed step, so the fixture is not vacuous: real callers must exist. Since Phase 10 slice S4
 * an allowed file may enqueue and install but not fund (`Funding.set` has a file list of its own in
 * the gate, and it is empty), so the call in `fund` is the fourth violation and `keeper`'s is none.
 */
internal class OwnerSteps(private val sync: SyncPorts) {
    fun keeper(tx: Any) {
        sync.capabilities.put(tx, 1, 2, 3)
    }

    fun fund(tx: Any, ns: Any) {
        sync.funding.set(tx, ns, true)
    }
}
