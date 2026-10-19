package org.ghost.messaging.api

/**
 * Phase 13 §3.2: the UI's channel facade — the actor-posted surface of the channel engine (Phase
 * 10), exposed to `:app` without leaking the engine's internal types. The UI's ChannelGateway
 * adapts this; every user action here is relay-visible traffic of §2.4's list.
 */
interface Channels {
    fun create(name: ByteArray, timerCode: Int, sizeClass: Int, passwordRequired: Boolean): CreateResult

    fun invite(channel: ChannelId, expiryDays: Int, password: CharArray?): InviteResult

    fun accept(link: ByteArray, password: CharArray?): AcceptResult

    fun post(channel: ChannelId, text: ByteArray, replyTo: PostId?): PostResult

    fun leave(channel: ChannelId): ChannelActionResult

    /** §6.7's CH-REJOIN, the user-invoked resync of a stalled channel. */
    fun rejoin(channel: ChannelId): ChannelActionResult
}

/** The simple outcomes of [Channels.leave] and [Channels.rejoin] at the facade edge. */
enum class ChannelActionResult { DONE, NOT_A_MEMBER, UNAVAILABLE }
