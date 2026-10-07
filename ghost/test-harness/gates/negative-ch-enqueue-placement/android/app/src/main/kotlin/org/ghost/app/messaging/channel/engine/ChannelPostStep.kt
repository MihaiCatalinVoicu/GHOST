package org.ghost.app.messaging.channel.engine

/**
 * G-M5 negative fixture (§19.38): a file named like an allowed step, in `:app` under a channel engine package path. The
 * table's entries are files of the channel engine's own directory: this one may make no call. One violation, line 9.
 */
internal class ChannelPostStep(private val sync: Any) {
    fun go(tx: Any, blob: Any) {
        sync.outbox.enqueue(tx, blob)
    }
}
