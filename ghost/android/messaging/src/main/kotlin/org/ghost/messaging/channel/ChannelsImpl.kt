package org.ghost.messaging.channel

import org.ghost.messaging.channel.engine.ChannelEngine
import org.ghost.messaging.channel.engine.ChannelPostStep
import org.ghost.messaging.channel.engine.ChannelRejoinStep

import org.ghost.messaging.api.ChannelActionResult
import org.ghost.messaging.api.ChannelId
import org.ghost.messaging.api.Channels
import org.ghost.messaging.api.CreateResult
import org.ghost.messaging.api.InviteResult
import org.ghost.messaging.api.PostId
import org.ghost.messaging.api.PostResult

/**
 * Phase 13 §3.2: the public [Channels] facade over the internal [ChannelEngine] — the mapping the
 * facade exists for is only the result shapes (the engine's step enums stay inside the module);
 * the calls themselves are the engine's actor-posted surface, nothing more.
 */
internal class ChannelsImpl(private val engine: ChannelEngine) : Channels {
    override fun channels(): List<org.ghost.messaging.api.ChannelSummary> = engine.summaries()

    override fun posts(channel: ChannelId, limit: Int): List<org.ghost.messaging.api.ChannelPostSummary> =
        engine.posts(channel, limit)

    override fun members(channel: ChannelId): List<org.ghost.messaging.api.ChannelMemberSummary> =
        engine.members(channel)

    override fun fingerprint(channel: ChannelId): org.ghost.messaging.api.ChannelFingerprint? =
        engine.fingerprint(channel)

    override fun remove(channel: ChannelId, member: ByteArray): ChannelActionResult = when (engine.remove(channel, member)) {
        ChannelEngine.RemoveResult.REMOVED -> ChannelActionResult.DONE
        ChannelEngine.RemoveResult.NOTHING -> ChannelActionResult.NOT_A_MEMBER
        ChannelEngine.RemoveResult.UNAVAILABLE -> ChannelActionResult.UNAVAILABLE
    }

    override fun reveal(channel: ChannelId, member: ByteArray): ChannelActionResult = when (engine.reveal(channel, member)) {
        org.ghost.messaging.channel.engine.ChannelRevealStep.RevealResult.REVEALED -> ChannelActionResult.DONE
        org.ghost.messaging.channel.engine.ChannelRevealStep.RevealResult.NOTHING -> ChannelActionResult.NOT_A_MEMBER
        org.ghost.messaging.channel.engine.ChannelRevealStep.RevealResult.UNAVAILABLE -> ChannelActionResult.UNAVAILABLE
    }

    override fun create(
        name: ByteArray,
        timerCode: Int,
        sizeClass: Int,
        passwordRequired: Boolean,
    ): CreateResult = engine.create(name, timerCode, sizeClass, passwordRequired)

    override fun invite(channel: ChannelId, expiryDays: Int, password: CharArray?): InviteResult =
        engine.invite(channel, expiryDays, password)

    override fun accept(link: ByteArray, password: CharArray?) = engine.accept(link, password)

    override fun post(channel: ChannelId, text: ByteArray, replyTo: PostId?): PostResult =
        engine.post(channel, text, replyTo)

    override fun leave(channel: ChannelId): ChannelActionResult = when (engine.leave(channel)) {
        ChannelPostStep.LeaveResult.LEFT -> ChannelActionResult.DONE
        ChannelPostStep.LeaveResult.UNAVAILABLE -> ChannelActionResult.UNAVAILABLE
        ChannelPostStep.LeaveResult.NOTHING, ChannelPostStep.LeaveResult.NOT_ALLOWED -> ChannelActionResult.NOT_A_MEMBER
    }

    override fun rejoin(channel: ChannelId): ChannelActionResult = when (engine.rejoin(channel)) {
        ChannelRejoinStep.ResyncResult.REQUESTED -> ChannelActionResult.DONE
        ChannelRejoinStep.ResyncResult.UNAVAILABLE -> ChannelActionResult.UNAVAILABLE
        ChannelRejoinStep.ResyncResult.REINVITE_NEEDED,
        ChannelRejoinStep.ResyncResult.NOTHING,
        -> ChannelActionResult.NOT_A_MEMBER
    }
}
