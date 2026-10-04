package org.ghost.messaging.channel.engine

/**
 * G-M5 negative fixture (Phase 10, slice S4): CH-JOIN reaches a relay through a step object instead of a port (the
 * S8 review's step rule of G-DM2, for the channel steps). Two violations, lines 9 and 10.
 */
internal class ChannelJoinStep(private val postStep: ChannelPostStep, private val passStep: ChannelPassStep) {
    fun join(tx: Any, channel: ByteArray) {
        postStep.compose(tx)
        passStep.admit(channel)
    }
}
