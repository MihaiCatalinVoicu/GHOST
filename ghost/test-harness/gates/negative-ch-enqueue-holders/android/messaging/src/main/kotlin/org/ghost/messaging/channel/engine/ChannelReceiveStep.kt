package org.ghost.messaging.channel.engine

/*
 * G-M5 negative fixture (Phase 10 design §19.38, the review of S4): CH-RECV reaches a relay-visible call through a step
 * entry point the second rule does not list — a post, a settle, an accept, the engine's own post — so the third rule
 * refuses the file that names the step. Five violations here: the constructor's two step classes (10, 11), a function
 * taking two (19), two lines that write a step property (20, 21); a sixth is `:app`'s import (Reflex.kt, 3). (15: none.)
 */
internal class ChannelReceiveStep(
    private val posts: ChannelPostStep,
    private val engine: ChannelEngine,
) {
    fun consume(c: ByteArray, id: Any) {
        posts.post(c, 1, null, null, null, null)
        val kind = ChannelPostStep.KIND_POST
        engine.post(id, c, null)
    }

    fun reflex(settleStep: ChannelSettleStep, acceptStep: ChannelAcceptStep, c: ByteArray, link: ByteArray) {
        settleStep.settle(c)
        acceptStep.accept(link, null)
    }
}
