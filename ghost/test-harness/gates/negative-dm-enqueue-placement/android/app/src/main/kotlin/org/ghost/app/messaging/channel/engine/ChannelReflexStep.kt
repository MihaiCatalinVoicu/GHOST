package org.ghost.app.messaging.channel.engine

/**
 * G-DM2 negative fixture (§19.38): an `:app` file under a channel engine package path. G-DM2 leaves the channel engine's
 * own directory in `:messaging` to G-M5, and nothing else: one violation, line 9.
 */
internal class ChannelReflexStep(private val sync: Any) {
    fun reflex(tx: Any, blob: Any) {
        sync.outbox.enqueue(tx, blob)
    }
}
