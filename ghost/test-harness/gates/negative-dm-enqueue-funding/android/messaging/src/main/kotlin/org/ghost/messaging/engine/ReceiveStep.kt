package org.ghost.messaging.engine

/**
 * G-DM2 negative fixture (Phase 10, slice S1a): `Funding.set` is the switch that makes the planner
 * redeem registration capabilities and the registration step run for a namespace, so a RECV step that
 * funds one because a blob arrived makes a funder's redemptions and registrations depend on what was
 * in the inbox (T40). The three shapes below are the ones the gate has to see: the port by its
 * conventional name, through a local alias, and injected under a name of the author's choosing.
 */
internal class ReceiveStep(private val sync: SyncPorts, private val ledger: Funding) {
    fun receive(tx: Any, blob: Any, ns: Any) {
        // 1. The port by its conventional name.
        sync.funding.set(tx, ns, true)
        // 2. A local alias of the port.
        val f = sync.funding
        f.set(tx, ns, false)
        // 3. A constructor-injected port: only its declared type shows what it is.
        ledger.set(tx, ns, true)
    }

    /** Not a violation: a re-offer of deferred rows writes local times and makes no relay call. */
    fun settle(tx: Any, ns: Any) {
        sync.inbox.reofferDeferred(tx, ns)
    }
}
