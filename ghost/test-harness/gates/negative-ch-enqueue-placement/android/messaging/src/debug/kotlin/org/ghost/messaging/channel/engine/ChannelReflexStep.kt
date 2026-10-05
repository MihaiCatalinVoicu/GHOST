package org.ghost.messaging.channel.engine

/** G-M5 negative fixture (§19.38): a channel step in the `debug` source set, which ships too. One violation, line 6. */
internal class ChannelReflexStep(private val sync: ChannelSyncPorts) {
    fun go(tx: Any, blob: Any) {
        sync.outbox.enqueue(tx, blob)
    }
}
