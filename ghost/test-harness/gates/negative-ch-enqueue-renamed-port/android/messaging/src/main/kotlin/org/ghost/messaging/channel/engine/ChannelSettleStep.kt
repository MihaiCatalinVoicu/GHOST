package org.ghost.messaging.channel.engine

/**
 * G-M5 negative fixture (§19.38): CH-SETTLE funds through the renamed port — `ChannelSyncPorts.fund`, a `Funding` under
 * a name of the author's choosing. One violation, line 10.
 */
internal class ChannelSettleStep(private val sync: ChannelSyncPorts) {
    fun settle(tx: Any, ns: Any, blob: Any) {
        sync.outbox.enqueue(tx, blob)
        sync.fund.set(tx, ns, true)
    }
}
