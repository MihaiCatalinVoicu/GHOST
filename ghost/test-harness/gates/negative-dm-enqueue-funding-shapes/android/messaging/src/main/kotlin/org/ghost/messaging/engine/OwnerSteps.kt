package org.ghost.messaging.engine

/**
 * G-DM2 negative fixture (Phase 10, slice S4): `Funding.set` has a file list of its own, and it is
 * empty, so a step that may enqueue and install may still not fund. The funding rule reads the shapes
 * the restricted rule reads: six violations, one per shape, and two decoys in `keeper` that are none
 * (an install, a `set` on a map, a `setRelays` of another port).
 */
internal class OwnerSteps(private val sync: SyncPorts, private val ledger: Funding) {
    private val slots = HashMap<Int, Int>()

    fun keeper(tx: Any, ns: Any) {
        sync.capabilities.put(tx, 1, 2, 3)
        slots.set(1, 2)
        sync.namespaces.setRelays(tx, ns, 3)
    }

    fun fund(tx: Any, ns: Any) {
        val f = sync.funding
        f.set(tx, ns, true)
        ledger.set(tx, ns, false)
        sync.funding.run {
            set(tx, ns, true)
        }
        val later = sync.funding::set
        (sync.funding).set(tx, ns, false)
        sync.funding
            ?.set(tx, ns, true)
    }
}
