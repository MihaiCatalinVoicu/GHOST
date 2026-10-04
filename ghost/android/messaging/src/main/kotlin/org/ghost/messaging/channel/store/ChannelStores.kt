package org.ghost.messaging.channel.store

/**
 * The channel DAOs of `:messaging` (Phase 10 design §10.1, `…messaging.channel.store`: "DAOs over `ch_*`,
 * `mls_*` (every read applies the expiry filter)"), in one place for the engine that slices S4 to S9 build.
 *
 * Nothing here is a second source of truth: each store is stateless and holds no connection, and every method
 * takes the `SqlExecutor` of a read or the `SyncTransaction` of a write from its caller (§10.4: each transaction
 * is exactly one `SyncDatabase.transaction`). The tables each store owns:
 *
 * | Store | Tables |
 * |---|---|
 * | [channels] | `ch_channel`, `ch_liveness`, `ch_schedule` |
 * | [generations] | `ch_generation` |
 * | [epochs] | `ch_epoch`, `ch_epoch_log`, `ch_fork_signal` |
 * | [candidates] | `ch_candidate` |
 * | [posts] | `ch_post`, `ch_reaction`, `ch_pending_post`, `ch_seen`, `ch_reveal`, `ch_outbound_op` |
 * | [joins] | `ch_join`, `ch_join_request`, `ch_kp_seen` |
 * | [invites] | `ch_invite_issued`, `ch_invite_own`, `ch_sponsor` |
 * | [members] | `ch_member_seen`, `ch_member_refresh`, `ch_request`, `ch_box_key` |
 * | [mls] | `mls_kv`, `mls_global_kv` |
 */
internal class ChannelStores {
    val channels = ChannelStore()
    val generations = GenerationStore()
    val epochs = EpochStore()
    val candidates = CandidateStore()
    val posts = PostStore()
    val joins = JoinStore()
    val invites = InviteStore()
    val members = MemberStore()
    val mls = MlsKvStore()

    override fun toString(): String = "ChannelStores"
}
