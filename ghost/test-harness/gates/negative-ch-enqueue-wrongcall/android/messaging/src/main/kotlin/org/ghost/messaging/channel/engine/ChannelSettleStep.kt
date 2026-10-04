package org.ghost.messaging.channel.engine

/**
 * G-M5 negative fixture (Phase 10, slice S4): a step on the table makes a call that is not its own. CH-SETTLE may
 * enqueue its own winning commit's Welcomes and must never fund (design 7.5 item 7): one violation, line 10.
 */
internal class ChannelSettleStep(private val sync: ChannelSyncPorts) {
    fun settle(tx: Any, ns: Any, blob: Any) {
        sync.outbox.enqueue(tx, blob)
        sync.funding.set(tx, ns, true)
    }
}
