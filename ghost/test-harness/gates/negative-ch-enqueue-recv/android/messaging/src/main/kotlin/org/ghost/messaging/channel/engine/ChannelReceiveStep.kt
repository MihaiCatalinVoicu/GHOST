package org.ghost.messaging.channel.engine

/**
 * G-M5 negative fixture (Phase 10, slice S4): CH-RECV makes no relay-visible call (T40). Two violations,
 * an enqueue and a registration; the inbox's local writes below are none.
 */
internal class ChannelReceiveStep(private val sync: ChannelSyncPorts) {
    fun consume(tx: Any, ns: Any, blob: Any) {
        sync.outbox.enqueue(tx, blob)
        sync.namespaces.register(tx, ns)
    }

    fun later(tx: Any, ns: Any, hash: Any) {
        sync.inbox.defer(tx, ns, hash, 60)
        sync.inbox.reofferDeferred(tx, ns)
    }
}
