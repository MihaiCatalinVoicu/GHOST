package org.ghost.messaging.channel.engine

/**
 * G-M5 negative fixture (Phase 10, slice S4): G-DM2's evasions, in CH-RECV. Seven violations: a receiver on the line
 * above its call (reported at the receiver's line, 10), a local alias (13), a scope function (14), a safe call (15), a port injected as its type (16),
 * a callable reference (17) and a parenthesized receiver (18).
 */
internal class ChannelReceiveStep(private val sync: ChannelSyncPorts, private val ledger: Funding) {
    fun consume(tx: Any, ns: Any, blob: Any) {
        sync.outbox
            .enqueue(tx, blob)
        val o = sync.outbox
        o.enqueue(tx, blob)
        with(sync.namespaces) { register(tx, ns) }
        sync.capabilities?.put(tx, ns)
        ledger.set(tx, ns, true)
        val fund = sync.funding::set
        (sync.registrations).keep(tx, ns)
    }
}
