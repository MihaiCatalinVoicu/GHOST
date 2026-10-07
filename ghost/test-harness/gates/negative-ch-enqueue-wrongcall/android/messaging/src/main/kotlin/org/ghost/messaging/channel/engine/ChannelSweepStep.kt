package org.ghost.messaging.channel.engine

/**
 * G-M5 negative fixture (Phase 10, slice S4): CH-SWEEP removes an expired join's namespace and enqueues nothing.
 * The ports are injected under names of the author's choosing, so only their types show what they are: one
 * violation, line 11.
 */
internal class ChannelSweepStep(private val names: Namespaces, private val ob: Outbox) {
    fun sweep(tx: Any, n: Any, blob: Any) {
        names.remove(tx, n)
        ob.enqueue(tx, blob)
    }
}
