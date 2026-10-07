package org.ghost.messaging.channel.engine

/**
 * G-DM2 negative fixture (Phase 10, slice S4): the restricted calls of the channel engine's files are G-M5's
 * (`ch-enqueue-callers.sh`, which lists them per step), so G-DM2 does not report the enqueue on line 10; its facade and
 * step rules still read these files, so a channel step that drives a DM send is reported: one violation, line 11.
 */
internal class ChannelPostStep(private val sync: ChannelSyncPorts, private val sendStep: SendStep) {
    fun post(tx: Any, blob: Any) {
        sync.outbox.enqueue(tx, blob)
        sendStep.flushPending()
    }
}
