package org.ghost.messaging.engine

/**
 * G-M5 negative fixture (Phase 10, slice S4): the DM's RECV drives a channel settle. The step rule reads every
 * production source of :messaging and :app, not only the channel package: one violation, line 9.
 */
internal class ReceiveStep(private val settle: ChannelSettleStep) {
    fun receive() {
        settle.settleDue()
    }
}
