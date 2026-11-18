package org.ghost.messaging.api

/**
 * Phase 13 §3.2: the UI's channel facade — the actor-posted surface of the channel engine (Phase
 * 10), exposed to `:app` without leaking the engine's internal types. The UI's ChannelGateway
 * adapts this; every user action here is relay-visible traffic of §2.4's list.
 */
interface Channels {
    /** The local list read: id, decrypted name and protection flag; no relay traffic. */
    fun channels(): List<ChannelSummary>

    /** The newest local posts, decrypted on the actor; no fetch is triggered by opening a channel. */
    fun posts(channel: ChannelId, limit: Int): List<ChannelPostSummary>

    /** The current MLS roster and its out-of-band fingerprint, all local reads. */
    fun members(channel: ChannelId): List<ChannelMemberSummary>
    fun fingerprint(channel: ChannelId): ChannelFingerprint?

    fun remove(channel: ChannelId, member: ByteArray): ChannelActionResult
    fun reveal(channel: ChannelId, member: ByteArray): ChannelActionResult

    fun create(name: ByteArray, timerCode: Int, sizeClass: Int, passwordRequired: Boolean): CreateResult

    fun invite(channel: ChannelId, expiryDays: Int, password: CharArray?): InviteResult

    fun accept(link: ByteArray, password: CharArray?): AcceptResult

    fun post(channel: ChannelId, text: ByteArray, replyTo: PostId?): PostResult

    fun leave(channel: ChannelId): ChannelActionResult

    /** §6.7's CH-REJOIN, the user-invoked resync of a stalled channel. */
    fun rejoin(channel: ChannelId): ChannelActionResult
}

/** One roster member; the pseudonym is copied at the facade boundary. */
class ChannelMemberSummary(pseudonym: ByteArray, val committer: Boolean, val mine: Boolean = false) {
    private val id: ByteArray = pseudonym.copyOf()
    val pseudonym: ByteArray get() = id.copyOf()
    override fun toString(): String = "ChannelMemberSummary(committer=$committer)"
}

/** CO-12's exact out-of-band value: epoch and the first 8 authenticator bytes. */
class ChannelFingerprint(val epoch: Long, code: ByteArray) {
    private val bytes: ByteArray = code.copyOf()
    init { require(bytes.size == 8) { "the fingerprint code is 8 bytes" } }
    val code: ByteArray get() = bytes.copyOf()
    override fun toString(): String = "ChannelFingerprint(epoch=$epoch)"
}

/** One post read model; [body] is deliberately absent from [toString]. */
class ChannelPostSummary(
    opId: ByteArray,
    val body: String,
    val mine: Boolean,
    val authorMinute: Long,
    val state: String,
    val kind: Int,
) {
    private val id: ByteArray = opId.copyOf()
    val opId: ByteArray get() = id.copyOf()
    override fun toString(): String = "ChannelPostSummary(mine=$mine, state=$state, kind=$kind)"
}

/** A channel-list row; the name never appears in [toString]. */
class ChannelSummary(
    channelId: ByteArray,
    val name: String,
    val passwordProtected: Boolean,
) {
    private val id: ByteArray = channelId.copyOf()
    val channelId: ByteArray get() = id.copyOf()
    override fun toString(): String = "ChannelSummary(password=$passwordProtected)"
}

/** The simple outcomes of [Channels.leave] and [Channels.rejoin] at the facade edge. */
enum class ChannelActionResult { DONE, NOT_A_MEMBER, UNAVAILABLE }
