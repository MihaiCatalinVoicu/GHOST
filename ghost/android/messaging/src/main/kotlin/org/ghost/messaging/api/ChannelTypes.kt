package org.ghost.messaging.api

/*
 * The value types of the channel facade (Phase 10 design §10.3, "`Channels` facade for Phase 13 (normative
 * signatures)"). The facade itself is Phase 13's; the channel engine of slice S4 answers with these types, so the
 * shapes §10.3 fixes are the ones the engine already returns. Every type that names a channel, a post or a link renders
 * without it (T3).
 */

/** A channel: its 32-byte id, which is also the MLS group id (§5.1). Equality by content; never rendered. */
class ChannelId(bytes: ByteArray) {
    private val raw: ByteArray = bytes.copyOf()

    init {
        require(raw.size == SIZE) { "a channel id is 32 bytes" }
    }

    fun toByteArray(): ByteArray = raw.copyOf()

    override fun equals(other: Any?): Boolean = other is ChannelId && other.raw.contentEquals(raw)

    override fun hashCode(): Int = raw.contentHashCode()

    override fun toString(): String = "ChannelId(redacted)"

    companion object {
        const val SIZE: Int = 32
    }
}

/** A post: its 16-byte op id (§5.1). */
class PostId(bytes: ByteArray) {
    private val raw: ByteArray = bytes.copyOf()

    init {
        require(raw.size == SIZE) { "a post id is 16 bytes" }
    }

    fun toByteArray(): ByteArray = raw.copyOf()

    override fun equals(other: Any?): Boolean = other is PostId && other.raw.contentEquals(raw)

    override fun hashCode(): Int = raw.contentHashCode()

    override fun toString(): String = "PostId(redacted)"

    companion object {
        const val SIZE: Int = 16
    }
}

/** `Channels.create` (§10.3): CREATED with the new channel, or why not. */
class CreateResult(val status: Status, val channel: ChannelId?) {
    enum class Status { CREATED, LIMIT_REACHED, NO_REPLICAS, CRYPTO_UNAVAILABLE, INVALID, STORAGE_FULL }

    override fun toString(): String = "CreateResult($status)"
}

/**
 * `Channels.createInvite` (§10.3): the link (`ghost://channel/…`, ASCII) — a bearer secret, and for a password channel
 * shown once and never kept (Q50 (a)) — or why not. The caller owns the array and may zero it.
 */
class InviteResult(val status: Status, val link: ByteArray?) {
    enum class Status { CREATED, NOT_ALLOWED, NOT_MEMBER, LIMIT_REACHED, PASSWORD_REQUIRED, INVALID, CRYPTO_UNAVAILABLE, NO_REPLICAS, STORAGE_FULL }

    override fun toString(): String = "InviteResult($status)"
}

/** `Channels.acceptInvite` (§10.3). */
enum class AcceptResult {
    PENDING,
    INVALID,
    EXPIRED,
    UNSUPPORTED_SUITE,
    ALREADY_MEMBER,
    LIMIT_REACHED,
    PASSWORD_REQUIRED,
    WRONG_PASSWORD,
    CRYPTO_UNAVAILABLE,
    NO_REPLICAS,
    STORAGE_FULL,
}

/**
 * `Channels.post` and `react` (§10.3), and the retry of a failed post (§6.11). Beyond §10.3's list: `NO_REPLICAS` (the DM
 * send's), `LIMIT_REACHED` (a channel already holds the 256 pending posts of §6.3.5) and `NOT_FAILED` (a retry of a post that
 * is not an own failed one) — recorded in §19.37 —, and `INVALID` (an empty post, text that is not UTF-8, a target that is
 * no post id: §19.38; `TOO_LARGE` is a text or a grapheme longer than §5.5 allows, and nothing else).
 */
enum class PostResult { QUEUED, TOO_LARGE, NOT_MEMBER, STORAGE_FULL, CRYPTO_UNAVAILABLE, NO_REPLICAS, LIMIT_REACHED, NOT_FAILED, INVALID }
