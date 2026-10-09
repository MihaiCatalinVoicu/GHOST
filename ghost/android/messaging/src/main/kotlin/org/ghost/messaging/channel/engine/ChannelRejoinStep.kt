package org.ghost.messaging.channel.engine

import org.ghost.crypto.bridge.ChannelCrypto
import org.ghost.crypto.bridge.MlsOutcome
import org.ghost.messaging.channel.store.ChannelState
import org.ghost.messaging.channel.store.GenerationState
import org.ghost.messaging.channel.store.GenerationStore
import org.ghost.messaging.channel.store.JoinType
import org.ghost.messaging.channel.store.OpPurpose
import org.ghost.messaging.engine.DmTime
import org.ghost.storage.StorageFullException
import org.ghost.sync.api.InsufficientReplicasException
import org.ghost.sync.api.NamespaceId
import org.ghost.sync.api.OperationId
import org.ghost.sync.api.OutboundBlob

/**
 * **`CH-REJOIN`** (Phase 10 design §6.7, §19.3; slice S7), two parts — the member-side answer (the
 * rejoin Welcome) is `CH-JOIN`'s ([ChannelJoinStep.joinWelcome]): it makes no relay-visible call,
 * so the receive step may name it (gate G-M5's third rule, the `ChannelJoinStep` precedent).
 *
 * **The resync user action ([resync]).** A user action — the UI's `resync` on `split_suspected`,
 * `partition_suspected` or `stale_suspected`, or the member's next action in a `resync_needed`
 * channel; never a reflex. A fresh KeyPackage for the same pseudonym (purpose rejoin, `GhostKpBind`),
 * `rejoin_sig` over (channel_id, the target generation, the trusted day, the last final epoch and its
 * winner hash, SHA-256 of the KeyPackage) and one `JoinRequest(type = rejoin)` per generation namespace
 * the member listens to (current and draining; a fork at a rotating commit leaves the two sides with
 * different new generations, and only the older one is shared) — each copy signed for the generation of
 * the namespace it is sealed into (§19.3 rule 1) and sealed in mode 0x12 under that generation's `JK_g`.
 * The old state and the KeyPackage's private keys stay until a Welcome arrives or 7 days pass.
 *
 * **The sweep's rejoin half ([sweepRejoins]).** A rejoin attempt expires at day + 7 unanswered: the
 * sweep sends a fresh request (a fresh KeyPackage and signature, the give-up day kept). At day + 14
 * (the deadline, `ch_join.rejoin_deadline_day`) an unanswered rejoin ends at `reinvite_needed` — any
 * member's new invite then admits the pseudonym as a restore (§6.7). A channel that recovered in the
 * meantime (progress returned it to `active`) just loses the pending rejoin state.
 *
 * **The stale clock's bound**: a resync after `stale_suspected` works while the committers still list
 * the member's namespace — the drain is `day(switch_hour) + 14` from the commit the member never saw,
 * and the member's `last_committer_commit_day` (the last commit it merged) bounds the quiet from
 * below, so the resync that computes `day > last_committer_commit_day + 14` goes straight to
 * `reinvite_needed` — the committers can no longer hear the old namespace (declared: the true switch
 * day can be a day later than the member's bound, and an attempt past the drain dies unanswered at the
 * 14-day deadline anyway).
 *
 * Gate G-M5 lists this file for `Outbox.enqueue` (`CH-REJOIN` and the sweep's re-send).
 */
internal class ChannelRejoinStep(
    private val env: ChannelEnv,
    private val sync: ChannelSyncPorts,
) {
    private val stores = env.stores

    /** What [resync] did (§10.3's `Result` shape; the facade maps it in Phase 13). */
    enum class ResyncResult {
        /** The requests are out, one per listened generation namespace; the rejoin state is recorded. */
        REQUESTED,

        /** The committers can no longer hear the member's namespace: the channel is `reinvite_needed`. */
        REINVITE_NEEDED,

        /** Nothing sent: not a member in a resyncable state, or no final epoch to claim. */
        NOTHING,

        /** The context or the content key is not available. */
        UNAVAILABLE,
    }

    // ------------------------------------------------------------------------------------------- CH-REJOIN

    /**
     * The resync user action (§6.7): builds the rejoin attempt. The native half first (the KeyPackage
     * and one signed request per listened generation), then **one transaction** (the rejoin state, the
     * KeyPackage's rows, the box key and one op per namespace). A stale member past its committers'
     * drain goes to `reinvite_needed` with nothing sent.
     */
    fun resync(channelId: ByteArray): ResyncResult {
        val now = env.now()
        val day = DmTime.day(now)
        if (env.keys.content() == null) return ResyncResult.UNAVAILABLE
        val row = env.database.transaction { tx ->
            val channel = stores.channels.channel(tx.sql, channelId)
            if (channel == null || (channel.state != ChannelState.ACTIVE && channel.state != ChannelState.RESYNC_NEEDED)) {
                null
            } else {
                channel
            }
        } ?: return ResyncResult.NOTHING
        // §6.7: a resync after stale_suspected works while the committers still drain the member's
        // namespace; past the bound the honest answer is `reinvite_needed`.
        if (row.staleSuspected && row.lastCommitterCommitDay != null &&
            day > row.lastCommitterCommitDay + ChannelSettleStep.DRAIN_DAYS
        ) {
            env.database.transaction { tx ->
                val fresh = stores.channels.channel(tx.sql, channelId)
                if (fresh != null && (fresh.state == ChannelState.ACTIVE || fresh.state == ChannelState.RESYNC_NEEDED)) {
                    stores.channels.transition(tx, channelId, fresh.state, ChannelState.REINVITE_NEEDED)
                }
            }
            return ResyncResult.REINVITE_NEEDED
        }
        val opened = env.contexts.open(channelId) ?: return ResyncResult.UNAVAILABLE
        if (!opened.pseudonym.contentEquals(row.myPseudonym)) return ResyncResult.UNAVAILABLE
        val last = env.database.transaction { tx -> stores.epochs.lastLogged(tx.sql, channelId) }
            ?: return ResyncResult.NOTHING
        val keyPackage = opened.crypto.keyPackage(channelId, PURPOSE_REJOIN, day.toInt()).valueOrNull()
            ?: return ResyncResult.UNAVAILABLE
        val generations = env.database.transaction { tx ->
            stores.generations.live(tx.sql, channelId, day)
                .filter { it.state != GenerationState.PENDING_SWITCH }
        }
        if (generations.isEmpty()) return ResyncResult.NOTHING
        val floor = ChannelTime.floor(row.sizeClass)
        val sealed = ArrayList<Pair<GenerationStore.GenerationRow, ByteArray>>()
        try {
            for (generation in generations) {
                val body = when (
                    val b = opened.crypto.rejoinRequest(
                        channelId, generation.generation.toInt(), day.toInt(), last.epoch, last.winnerHash,
                        keyPackage.keyPackage,
                    )
                ) {
                    is MlsOutcome.Ok -> b.value
                    is MlsOutcome.Refused -> return ResyncResult.UNAVAILABLE
                }
                val blob = when (
                    val s = opened.crypto.seal(
                        channelId, generation.jkEnv, ChannelCrypto.KEY_CLASS_JOIN, generation.namespaceId,
                        floor, ChannelCrypto.MODE_JOIN, ChannelCrypto.SealOrder.NONE, body,
                    )
                ) {
                    is MlsOutcome.Ok -> s.value
                    is MlsOutcome.Refused -> return ResyncResult.UNAVAILABLE
                }
                sealed += generation to blob
            }
            env.database.transaction { tx ->
                val fresh = stores.channels.channel(tx.sql, channelId)
                if (fresh == null || (fresh.state != ChannelState.ACTIVE && fresh.state != ChannelState.RESYNC_NEEDED)) {
                    return@transaction
                }
                // A fresh attempt replaces the pending one (the old KeyPackage's rows die by their day).
                stores.joins.deleteJoinsOfType(tx, channelId, JoinType.REJOIN)
                stores.joins.insertJoin(
                    tx, channelId, keyPackage.kpRef, JoinType.REJOIN, null, fresh.generation, day + RESEND_DAYS,
                    rejoinDeadlineDay = day + GIVE_UP_DAYS,
                )
                // §6.7 keeps the KeyPackage's private keys until the give-up deadline, not the 7-day
                // re-send (the review of S7, §19.44 FIX 2): a completion on days 8-14 still joins.
                stores.mls.apply(
                    tx, channelId, MlsRows.changes(keyPackage.changes),
                    globalDeleteAfterDay = day + GIVE_UP_DAYS, keyPackagesOnly = true,
                )
                stores.members.insertBoxKey(tx, channelId, keyPackage.boxPk, keyPackage.boxEnv)
                for ((generation, blob) in sealed) {
                    val operationId = env.random.bytes(OperationId.SIZE)
                    sync.outbox.enqueue(
                        tx,
                        OutboundBlob(
                            OperationId(operationId), NamespaceId(generation.namespaceId), blob,
                            ChannelTime.handshakeTtl(fresh.timerCode),
                            deadlineEpochSeconds = ChannelTime.handshakeDeadline(DmTime.floorMinute(now)),
                        ),
                    )
                    stores.posts.insertOp(tx, operationId, channelId, OpPurpose.REJOIN, blobHash(blob))
                }
            }
            return ResyncResult.REQUESTED
        } catch (e: InsufficientReplicasException) {
            return ResyncResult.NOTHING
        } catch (e: StorageFullException) {
            return ResyncResult.UNAVAILABLE
        } finally {
            for ((_, blob) in sealed) blob.fill(0)
        }
    }

    // ---------------------------------------------------------------------------------------- the sweep

    /**
     * The rejoin rows past their attempt day (§6.7): at day + 7 a fresh request (a fresh KeyPackage and
     * signature, the give-up day kept); at day + 14, past `rejoin_deadline_day`, the unanswered rejoin
     * ends at `reinvite_needed` and the KeyPackage's private keys go — except on a channel that recovered
     * in band: §6.7 ("a channel that recovered loses only the pending state", §19.44) — a member whose
     * stale rejoin every committer refused on the live-leaf check kept merging commits, so the give-up
     * takes only the row and the keys, the state stays `active`. Each row one transaction; returns how
     * many it finished.
     */
    fun sweepRejoins(): Int {
        val now = env.now()
        val day = DmTime.day(now)
        val expired = env.database.transaction { tx ->
            stores.joins.expiredJoins(tx.sql, day, ChannelSweepStep.BATCH).filter { it.type == JoinType.REJOIN }
        }
        var done = 0
        for (join in expired) {
            val deadline = join.rejoinDeadlineDay ?: continue
            if (day > deadline) {
                env.database.transaction { tx ->
                    val channel = stores.channels.channel(tx.sql, join.channelId) ?: return@transaction
                    // The exact recovery rule (§19.44): the give-up transitions only a channel that is
                    // still cut off — no commit merged since the attempt began. An `active` channel
                    // that merged a commit in that window recovered in band (the request was obsolete,
                    // refused by the committers' live-leaf check): it loses only the pending state.
                    val recovered = channel.lastCommitterCommitDay != null &&
                        channel.lastCommitterCommitDay >= deadline - GIVE_UP_DAYS
                    if (!(channel.state == ChannelState.ACTIVE && recovered)) {
                        when (channel.state) {
                            ChannelState.RESYNC_NEEDED ->
                                stores.channels.transition(tx, join.channelId, ChannelState.RESYNC_NEEDED, ChannelState.REINVITE_NEEDED)
                            ChannelState.ACTIVE ->
                                stores.channels.transition(tx, join.channelId, ChannelState.ACTIVE, ChannelState.REINVITE_NEEDED)
                            else -> Unit
                        }
                    }
                    stores.mls.deleteKeyPackages(tx, join.channelId)
                    stores.joins.deleteJoin(tx, join.channelId, join.kpRef)
                }
                done++
            } else if (resend(join, day, now)) {
                done++
            }
        }
        return done
    }

    /** The 7-day re-send: a fresh KeyPackage and request per listened generation, the deadline kept. */
    private fun resend(join: org.ghost.messaging.channel.store.JoinStore.JoinRow, day: Long, now: Long): Boolean {
        val deadline = join.rejoinDeadlineDay ?: return false
        val channelId = join.channelId
        val opened = env.contexts.open(channelId) ?: return false
        val last = env.database.transaction { tx -> stores.epochs.lastLogged(tx.sql, channelId) } ?: return false
        val channel = env.database.transaction { tx -> stores.channels.channel(tx.sql, channelId) } ?: return false
        if (channel.state != ChannelState.ACTIVE && channel.state != ChannelState.RESYNC_NEEDED) {
            env.database.transaction { tx -> stores.joins.deleteJoin(tx, channelId, join.kpRef) }
            return true
        }
        val keyPackage = opened.crypto.keyPackage(channelId, PURPOSE_REJOIN, day.toInt()).valueOrNull() ?: return false
        val generations = env.database.transaction { tx ->
            stores.generations.live(tx.sql, channelId, day).filter { it.state != GenerationState.PENDING_SWITCH }
        }
        if (generations.isEmpty()) return false
        val floor = ChannelTime.floor(channel.sizeClass)
        val sealed = ArrayList<Pair<GenerationStore.GenerationRow, ByteArray>>()
        try {
            for (generation in generations) {
                val body = when (
                    val b = opened.crypto.rejoinRequest(
                        channelId, generation.generation.toInt(), day.toInt(), last.epoch, last.winnerHash,
                        keyPackage.keyPackage,
                    )
                ) {
                    is MlsOutcome.Ok -> b.value
                    is MlsOutcome.Refused -> return false
                }
                val blob = when (
                    val s = opened.crypto.seal(
                        channelId, generation.jkEnv, ChannelCrypto.KEY_CLASS_JOIN, generation.namespaceId,
                        floor, ChannelCrypto.MODE_JOIN, ChannelCrypto.SealOrder.NONE, body,
                    )
                ) {
                    is MlsOutcome.Ok -> s.value
                    is MlsOutcome.Refused -> return false
                }
                sealed += generation to blob
            }
            env.database.transaction { tx ->
                val fresh = stores.channels.channel(tx.sql, channelId)
                // The attempt row is expired (this read selected it) — the unfiltered delete is its
                // existence check; a sweep that already finished it wrote nothing.
                if (fresh == null || (fresh.state != ChannelState.ACTIVE && fresh.state != ChannelState.RESYNC_NEEDED) ||
                    !stores.joins.deleteJoin(tx, channelId, join.kpRef)
                ) {
                    return@transaction
                }
                stores.joins.insertJoin(
                    tx, channelId, keyPackage.kpRef, JoinType.REJOIN, null, fresh.generation, day + RESEND_DAYS,
                    rejoinDeadlineDay = join.rejoinDeadlineDay,
                )
                // The fresh KeyPackage's keys live until the attempt's give-up deadline, exactly like
                // the first one's (§19.44 FIX 2) — the re-send refreshes the request, not the lifetime.
                stores.mls.apply(
                    tx, channelId, MlsRows.changes(keyPackage.changes),
                    globalDeleteAfterDay = deadline, keyPackagesOnly = true,
                )
                stores.members.insertBoxKey(tx, channelId, keyPackage.boxPk, keyPackage.boxEnv)
                for ((generation, blob) in sealed) {
                    val operationId = env.random.bytes(OperationId.SIZE)
                    sync.outbox.enqueue(
                        tx,
                        OutboundBlob(
                            OperationId(operationId), NamespaceId(generation.namespaceId), blob,
                            ChannelTime.handshakeTtl(fresh.timerCode),
                            deadlineEpochSeconds = ChannelTime.handshakeDeadline(DmTime.floorMinute(now)),
                        ),
                    )
                    stores.posts.insertOp(tx, operationId, channelId, OpPurpose.REJOIN, blobHash(blob))
                }
            }
            return true
        } catch (e: InsufficientReplicasException) {
            return false
        } catch (e: StorageFullException) {
            return false
        } finally {
            for ((_, blob) in sealed) blob.fill(0)
        }
    }

    private fun blobHash(blob: ByteArray): ByteArray =
        java.security.MessageDigest.getInstance("SHA-256").digest(blob)

    override fun toString() = "ChannelRejoinStep"

    companion object {
        /** `GhostKpBind.purpose` (§5.4): 1 join, 2 rejoin, 3 restore. */
        const val PURPOSE_REJOIN: Int = 2

        /** §6.7: an unanswered attempt re-sends after 7 days. */
        const val RESEND_DAYS: Long = 7

        /** §6.7: `REINVITE_NEEDED` after 14 days without a Welcome. */
        const val GIVE_UP_DAYS: Long = 14
    }
}
