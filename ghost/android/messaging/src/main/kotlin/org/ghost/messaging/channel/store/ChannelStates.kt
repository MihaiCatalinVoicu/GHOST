package org.ghost.messaging.channel.store

/**
 * The closed lists of the channel tables as types (Phase 10 design §9, §6.11). Each machine states its legal
 * edges once, here; the triggers of migration 7 state them again in SQL, and `ChannelStateMachinesTest` runs
 * every pair through both, so the two cannot drift.
 */

/** `ch_channel.state` (§6.11, Channel, member view). */
internal enum class ChannelState(val sql: String) {
    JOINING("joining"),
    ACTIVE("active"),
    LEAVING("leaving"),
    LEFT("left"),
    REMOVED("removed"),
    REPLACED("replaced"),
    RESYNC_NEEDED("resync_needed"),
    REINVITE_NEEDED("reinvite_needed"),
    JOIN_EXPIRED("join_expired"),
    ;

    /**
     * The edges of §6.11: `joining -> active | join_expired`, `active -> leaving | removed | replaced |
     * resync_needed | reinvite_needed`, `leaving -> left | removed`, `resync_needed -> active |
     * reinvite_needed`, `reinvite_needed | replaced -> active` (the restore's Welcome), and a new invitation
     * re-enters `joining` from a channel that was left, removed, replaced or expired (§6.2.2). The same state
     * is no edge and no change.
     */
    fun allows(to: ChannelState): Boolean = this == to || when (this) {
        JOINING -> to == ACTIVE || to == JOIN_EXPIRED
        ACTIVE -> to == LEAVING || to == REMOVED || to == REPLACED || to == RESYNC_NEEDED || to == REINVITE_NEEDED
        LEAVING -> to == LEFT || to == REMOVED
        RESYNC_NEEDED -> to == ACTIVE || to == REINVITE_NEEDED
        REINVITE_NEEDED -> to == ACTIVE
        REPLACED -> to == ACTIVE || to == JOINING
        LEFT, REMOVED, JOIN_EXPIRED -> to == JOINING
    }

    companion object {
        fun of(sql: String): ChannelState = entries.single { it.sql == sql }
    }
}

/** `ch_generation.state` (§6.5, §6.11): `pending_switch -> current -> draining`, then the row is deleted. */
internal enum class GenerationState(val sql: String) {
    PENDING_SWITCH("pending_switch"),
    CURRENT("current"),
    DRAINING("draining"),
    ;

    fun allows(to: GenerationState): Boolean =
        this == to || (this == PENDING_SWITCH && to == CURRENT) || (this == CURRENT && to == DRAINING)

    companion object {
        fun of(sql: String): GenerationState = entries.single { it.sql == sql }
    }
}

/** `ch_epoch.state` (§6.11, Epoch): `open -> final`, sticky. */
internal enum class EpochState(val sql: String) {
    OPEN("open"),
    FINAL("final"),
    ;

    fun allows(to: EpochState): Boolean = this == to || (this == OPEN && to == FINAL)

    companion object {
        fun of(sql: String): EpochState = entries.single { it.sql == sql }
    }
}

/**
 * `ch_post.state` (§6.11, Post (outgoing) and Post (incoming)): `queued -> sent | degraded | failed |
 * indeterminate`, `failed -> queued` (the user's retry), `unread -> read`.
 */
internal enum class PostState(val sql: String, val outgoing: Boolean) {
    QUEUED("queued", true),
    SENT("sent", true),
    DEGRADED("degraded", true),
    FAILED("failed", true),
    INDETERMINATE("indeterminate", true),
    UNREAD("unread", false),
    READ("read", false),
    ;

    fun allows(to: PostState): Boolean = this == to || when (this) {
        QUEUED -> to == SENT || to == DEGRADED || to == FAILED || to == INDETERMINATE
        FAILED -> to == QUEUED
        UNREAD -> to == READ
        SENT, DEGRADED, INDETERMINATE, READ -> false
    }

    companion object {
        fun of(sql: String): PostState = entries.single { it.sql == sql }
    }
}

/** `ch_post.direction`, `ch_reveal.direction`. */
internal enum class Direction(val sql: String) {
    OUT("out"),
    IN("in"),
    ;

    companion object {
        fun of(sql: String): Direction = entries.single { it.sql == sql }
    }
}

/** `ch_join.type` and `ch_join_request.type` (§6.2): the KeyPackage's purpose. */
internal enum class JoinType(val sql: String) {
    JOIN("join"),
    REJOIN("rejoin"),
    RESTORE("restore"),
    ;

    /** A rejoin has no invite (§6.7); a join and a restore are admitted by one (§6.2.4, §6.12). */
    val hasInvite: Boolean get() = this != REJOIN

    companion object {
        fun of(sql: String): JoinType = entries.single { it.sql == sql }
    }
}

/** `ch_outbound_op.purpose`: what a Phase 7 operation of the channel carries. */
internal enum class OpPurpose(val sql: String) {
    POST("post"),
    COMMIT("commit"),
    WELCOME("welcome"),
    JOIN("join"),
    REJOIN("rejoin"),
    REQUEST("request"),
    ;

    companion object {
        fun of(sql: String): OpPurpose = entries.single { it.sql == sql }
    }
}

/** `ch_request.kind`: a committer's pending work that is no join request (§6.6, §6.5). */
internal enum class RequestKind(val sql: String) {
    LEAVE("leave"),
    REMOVE("remove"),
    POLICY("policy"),
    CLASS("class"),
    ;

    companion object {
        fun of(sql: String): RequestKind = entries.single { it.sql == sql }
    }
}
