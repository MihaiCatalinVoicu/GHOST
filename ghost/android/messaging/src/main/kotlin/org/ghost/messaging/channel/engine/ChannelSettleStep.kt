package org.ghost.messaging.channel.engine

import org.ghost.crypto.bridge.ChannelCrypto
import org.ghost.crypto.bridge.ChannelPolicy
import org.ghost.crypto.bridge.MlsChange
import org.ghost.crypto.bridge.MlsCode
import org.ghost.crypto.bridge.MlsField
import org.ghost.crypto.bridge.MlsOutcome
import org.ghost.messaging.channel.store.CandidateStore
import org.ghost.messaging.channel.store.ChannelState
import org.ghost.messaging.channel.store.EpochStore
import org.ghost.messaging.channel.store.GenerationState
import org.ghost.messaging.channel.store.OpPurpose
import org.ghost.messaging.engine.DmTime
import org.ghost.messaging.store.ContentCipher
import org.ghost.storage.StorageFullException
import org.ghost.sync.api.InsufficientReplicasException
import org.ghost.sync.api.NamespaceId
import org.ghost.sync.api.OperationId
import org.ghost.sync.api.OutboundBlob
import org.ghost.sync.api.SyncTransaction

/**
 * **`CH-SETTLE`** as slice S4 needs it (Phase 10 design §6.4 CO-3 … CO-5, §10.4), **one transaction**: the member settles
 * its current epoch at the settle point and merges the winner.
 *
 * **The settle point (CO-4 (i)).** `now ≥ anchor(e) + 20 min`, the anchor being the earliest, over the candidates held,
 * of the first sighting and the copy's relay store hour + 60 min (`ch_epoch.anchor_minute`, kept by `CH-RECV` and
 * `CH-PASS`). **CO-4 (ii) is not implemented** — "after (i) held, the member completed one listing pass over every relay
 * of the current generation's set" — because `:sync` gives its consumer no listing-pass signal (finding F-S4-1 of
 * §19.37); the full settle is slice S5's.
 *
 * **The winner (CO-3 without trial settles).** Among the valid candidates held, the lowest `(rank, SHA-256(commit))`;
 * the committer's **own** commit takes part only once a copy of it was verified at a relay (`ch_candidate.verified`, set
 * by `CH-OUTCOME`): an unverified own commit ranks below every foreign candidate, and alone it waits for its outcome. The
 * successor-sender count and the abandonment rule (`trialCount`, S0-17) are slice S5's: in this slice every count is 0,
 * which is CO-3's own rule when no held blob fails to open under the member's keys.
 *
 * **The merge (CO-5).** A foreign winner is first run again for its validation summary (the `GhostCommitAad` evidence of
 * its Adds, which the stored candidate does not keep), the own pending commit — if any — is cleared (`clearOwn`), and the
 * winner is merged (`settle`, which re-runs CO-2 natively); an own winner is merged from the pending commit. In the same
 * transaction: the change-set; the epoch final (`winner_hash` is the commit that ended it, §19.35 F-5), logged, and the
 * next epoch's keys; the position; a rotation's next generation as `pending_switch` (its switch is `CH-SWITCH`'s, S6); the
 * invites the winner's Adds consumed, their pending requests, the sponsor records and — for a committer — the
 * KeyPackages' tags; for an **own** winner its WELCOME blobs enqueued (§19.2) and its new leaf's box key; the policy
 * mirror; the committers digest forgotten when the winner changed `committers` (S0-15's voiding of invites needs the new
 * digest, which `roster` does not return: §19.37 F-S4-2, S5's); every candidate of the epoch deleted; the namespaces'
 * deferred blobs re-offered. A member the winner removes (`standing` 2) or replaces (3) records the state and the final
 * epoch; the rest of its departure is slice S6's.
 *
 * Gate G-M5 lists this file for `Outbox.enqueue` (the own winner's Welcomes).
 */
internal class ChannelSettleStep(
    private val env: ChannelEnv,
    private val sync: ChannelSyncPorts,
) {
    private val stores = env.stores

    /** Every channel whose settle point has come, each settled once; returns how many settled. */
    fun settleDue(): Int {
        val channels = env.database.transaction { tx ->
            stores.channels.channelsIn(tx.sql, ChannelState.ACTIVE) + stores.channels.channelsIn(tx.sql, ChannelState.LEAVING)
        }
        var settled = 0
        for (channel in channels) if (settle(channel.channelId)) settled++
        return settled
    }

    /**
     * The second the earliest settle point of an epoch with candidates comes (the actor's next wake), or null. An epoch
     * whose only candidate is the member's **own commit with no verified copy** is no wake (§19.38): CO-4 waits for that
     * commit's outcome, which arrives as a hint and runs the settle in that pass; a wake at its settle point could only
     * find it waiting still.
     */
    fun nextDue(): Long? {
        val day = DmTime.day(env.now())
        return env.database.transaction { tx ->
            (stores.channels.channelsIn(tx.sql, ChannelState.ACTIVE) + stores.channels.channelsIn(tx.sql, ChannelState.LEAVING))
                .mapNotNull { ch ->
                    val epoch = stores.epochs.open(tx.sql, ch.channelId, day) ?: return@mapNotNull null
                    val anchor = epoch.anchorMinute ?: return@mapNotNull null
                    val candidates = stores.candidates.candidates(tx.sql, ch.channelId, epoch.epoch)
                    if (candidates.none { !it.own || it.verified }) return@mapNotNull null
                    anchor + ChannelTime.SETTLE_WINDOW_SECONDS
                }
                .minOrNull()
        }
    }

    /** What the native settle produced, before the transaction that writes it. */
    private class Merge(
        val winner: CandidateStore.CandidateRow,
        val changes: List<MlsChange>,
        val settled: ChannelCrypto.Settled,
        val admitted: List<Admitted>,
        val welcomes: ChannelWelcomes.Framed?,
        val before: ChannelPolicy,
        val after: ChannelPolicy?,
        val committer: Boolean,
    )

    /** One admission the winner made: what the settle records about it. */
    private class Admitted(
        val inviteId: ByteArray,
        val member: ByteArray?,
        val sponsor: ByteArray,
        val kpRef: ByteArray,
        val kpDay: Long?,
    ) {
        override fun toString(): String = "Admitted(redacted)"
    }

    /** Settles [channelId]'s current epoch if its settle point has come; true when it did. */
    fun settle(channelId: ByteArray): Boolean {
        val content = env.keys.content() ?: return false
        val seenKey = env.keys.seenKey() ?: return false
        try {
            return settleWith(channelId, content, seenKey)
        } finally {
            seenKey.fill(0)
        }
    }

    private fun settleWith(channelId: ByteArray, content: ContentCipher, seenKey: ByteArray): Boolean {
        val now = env.now()
        val day = DmTime.day(now)
        val opened = env.contexts.open(channelId) ?: return false
        val snapshot = env.database.transaction { tx ->
            val channel = stores.channels.channel(tx.sql, channelId) ?: return@transaction null
            if (channel.state != ChannelState.ACTIVE && channel.state != ChannelState.LEAVING) return@transaction null
            val epoch = stores.epochs.open(tx.sql, channelId, day) ?: return@transaction null
            if (epoch.epoch != channel.epoch) return@transaction null
            val anchor = epoch.anchorMinute ?: return@transaction null
            if (now < anchor + ChannelTime.SETTLE_WINDOW_SECONDS) return@transaction null
            val candidates = stores.candidates.candidates(tx.sql, channelId, epoch.epoch)
            if (candidates.isEmpty()) {
                // The candidates went (an own commit cleared, CO-4): no settle point any more.
                stores.epochs.setAnchor(tx, channelId, epoch.epoch, null)
                return@transaction null
            }
            val generation = stores.generations.current(tx.sql, channelId, day)
            Triple(channel to epoch, candidates, (generation?.generation ?: channel.generation) to stores.mls.rows(tx.sql, channelId, day))
        } ?: return false
        val (channelAndEpoch, candidates, generationAndRows) = snapshot
        val (channel, epoch) = channelAndEpoch
        val (generation, kvRows) = generationAndRows
        val merge = merge(channelId, opened, content, epoch, candidates, generation, MlsRows.of(kvRows), day) ?: return false
        return try {
            env.database.transaction { tx -> write(tx, channelId, channel.timerCode, epoch, merge, content, seenKey, now, day) }
        } catch (e: InsufficientReplicasException) {
            // The own winner's Welcomes cannot be enqueued this week: nothing is written; the settle is tried again.
            false
        } catch (e: StorageFullException) {
            false
        }
    }

    /** The native half: the winner chosen, run and merged in memory; null when there is nothing to settle yet. */
    private fun merge(
        channelId: ByteArray,
        opened: ChannelContexts.Opened,
        content: ContentCipher,
        epoch: EpochStore.EpochRow,
        candidates: List<CandidateStore.CandidateRow>,
        generation: Long,
        stored: List<org.ghost.crypto.bridge.MlsRow>,
        day: Long,
    ): Merge? {
        val e = epoch.epoch
        val own = candidates.firstOrNull { it.own }
        val foreign = candidates.filter { !it.own }.sortedWith(ChannelReceiveStep.CANDIDATE_ORDER)
        val winner = when {
            foreign.isNotEmpty() ->
                if (own != null && own.verified && ChannelReceiveStep.CANDIDATE_ORDER.compare(own, foreign.first()) < 0) own else foreign.first()
            own != null && own.verified -> own
            // CO-4: an own commit with no verified copy waits for its outcome.
            else -> return null
        }
        val body = content.open(winner.bodyEnv, ChannelAd.candidate(channelId, e, winner.hash)) ?: return refuseWinner(channelId, e, winner)
        val before = opened.crypto.roster(channelId, stored, day.toInt()).valueOrNull() ?: return null
        val committer = before.context.committers.any { it.contentEquals(opened.pseudonym) }
        var rows = stored
        val changes = ArrayList<MlsChange>()
        val admitted: List<Admitted>
        var framed: ChannelWelcomes.Framed? = null
        val settled: ChannelCrypto.Settled
        if (winner.own) {
            val welcomeEnv = winner.welcomeEnv
            framed = if (welcomeEnv == null) null else content.open(welcomeEnv, ChannelAd.welcomes(channelId, e, winner.hash))?.let(ChannelWelcomes::decode)
            if (welcomeEnv != null && framed == null) return refuseWinner(channelId, e, winner)
            admitted = framed?.entries?.map { Admitted(it.inviteId, it.member, it.sponsor, it.kpRef, it.kpDay) } ?: emptyList()
            settled = when (val s = opened.crypto.settle(channelId, rows, ChannelCrypto.Winner.Own(body), generation.toInt(), day.toInt())) {
                is MlsOutcome.Ok -> s.value
                is MlsOutcome.Refused -> return if (s.code == MlsCode.CRYPTO_UNAVAILABLE || s.code == MlsCode.STATE_CORRUPT) null else refuseWinner(channelId, e, winner)
            }
        } else {
            // The winner's evidence, from a validation run whose change-set is discarded (CO-2).
            val summary = when (val r = opened.crypto.receive(channelId, rows, e, listOf(body), day.toInt())) {
                is MlsOutcome.Ok -> (r.value.items.singleOrNull() as? ChannelCrypto.Item.Commit)?.summary
                is MlsOutcome.Refused -> if (r.code == MlsCode.CRYPTO_UNAVAILABLE || r.code == MlsCode.STATE_CORRUPT) return null else null
            }
            if (summary == null || !summary.isValid) return refuseWinner(channelId, e, winner)
            admitted = summary.aad?.admits?.map { a ->
                val add = summary.adds.firstOrNull { it.bytes(MlsField.KP_REF).contentEquals(a.kpRef) }
                Admitted(
                    inviteId = a.inviteId,
                    member = add?.bytes(MlsField.PSEUDONYM),
                    sponsor = a.sponsor,
                    kpRef = a.kpRef,
                    kpDay = add?.recordOrNull(MlsField.KP_BIND)?.u32(MlsField.DAY),
                )
            } ?: emptyList()
            if (own != null) {
                // CO-4: another candidate wins, so the own pending commit is cleared before the winner is merged.
                val cleared = opened.crypto.clearOwn(channelId, rows, day.toInt()).valueOrNull() ?: return null
                changes += cleared
                rows = MlsRows.applied(rows, cleared)
            }
            settled = when (val s = opened.crypto.settle(channelId, rows, ChannelCrypto.Winner.Foreign(body), generation.toInt(), day.toInt())) {
                is MlsOutcome.Ok -> s.value
                is MlsOutcome.Refused -> return if (s.code == MlsCode.CRYPTO_UNAVAILABLE || s.code == MlsCode.STATE_CORRUPT) null else refuseWinner(channelId, e, winner)
            }
        }
        changes += settled.changes
        val after = if (settled.standing == STANDING_MEMBER) {
            opened.crypto.roster(channelId, MlsRows.applied(rows, settled.changes), day.toInt()).valueOrNull()?.context
        } else {
            null
        }
        return Merge(winner, changes, settled, admitted, framed, before.context, after, committer)
    }

    /** A winner the native side refuses at the settle (CO-2 re-run) or whose stored rows do not open: dropped, counted. */
    private fun refuseWinner(channelId: ByteArray, epoch: Long, winner: CandidateStore.CandidateRow): Merge? {
        env.database.transaction { tx -> stores.candidates.delete(tx, channelId, epoch, winner.hash) }
        env.counters.count(ChannelCounters.Reason.SETTLE_REFUSED)
        return null
    }

    private fun write(
        tx: SyncTransaction,
        channelId: ByteArray,
        timerCode: Int,
        epoch: EpochStore.EpochRow,
        merge: Merge,
        content: ContentCipher,
        seenKey: ByteArray,
        now: Long,
        day: Long,
    ): Boolean {
        val c = channelId
        val e = epoch.epoch
        val fresh = stores.channels.channel(tx.sql, c) ?: return false
        if (fresh.epoch != e || (fresh.state != ChannelState.ACTIVE && fresh.state != ChannelState.LEAVING)) return false
        stores.mls.apply(tx, c, MlsRows.changes(merge.changes))
        val settled = merge.settled
        val winner = merge.winner
        stores.epochs.finalize(tx, c, e, winner.hash, day, day + ChannelTime.retentionDays(fresh.timerCode))
        if (stores.epochs.logCount(tx.sql, c) >= EpochStore.MAX_LOG) stores.epochs.trimLog(tx, c, EpochStore.MAX_LOG - 1)
        stores.epochs.appendLog(tx, c, e, winner.hash, day)
        val next = settled.epoch
        if (settled.standing != STANDING_MEMBER || next == null) {
            // §6.6: removed (or replaced by a restore of its own pseudonym): the state is recorded, the departure is S6's.
            val to = if (settled.standing == STANDING_REPLACED && fresh.state == ChannelState.ACTIVE) ChannelState.REPLACED else ChannelState.REMOVED
            stores.channels.transition(tx, c, fresh.state, to)
        } else {
            makeRoom(tx, c, day)
            stores.epochs.insert(tx, c, next.epoch, next.kEnv, next.rEp)
            stores.channels.setPosition(tx, c, fresh.generation, next.epoch)
            settled.rotated?.let { g ->
                // §6.5: the next generation waits for its switch hour (CH-SWITCH, slice S6).
                val commitSeconds = settled.commitMinute * DmTime.MINUTE
                val switchHour = minOf(DmTime.ceilHour(commitSeconds + SWITCH_DELAY_SECONDS), DmTime.ceilHour(now + SWITCH_CLAMP_SECONDS))
                stores.generations.insert(
                    tx, c, g.generation, g.ns, GenerationState.PENDING_SWITCH, g.gEnv, g.jkEnv, g.rJoin, g.openEpoch,
                    switchHour = switchHour,
                )
            }
            if (winner.rank < NOT_A_COMMITTER) stores.channels.setLastCommitterCommitDay(tx, c, day)
            mirrorPolicy(tx, c, fresh.nameEnv, merge, content)
        }
        for (a in merge.admitted) {
            stores.invites.markConsumed(tx, c, a.inviteId)
            stores.joins.deleteRequestsOfInvite(tx, c, a.inviteId)
            a.member?.let { stores.invites.putSponsor(tx, c, it, a.sponsor, a.inviteId, day) }
            if (merge.committer && a.kpDay != null) {
                stores.joins.markKpSeen(tx, c, ChannelTags.keyPackageTag(seenKey, c, a.kpRef), a.kpDay + ChannelPassStep.KP_SEEN_DAYS)
            }
        }
        if (winner.own && settled.standing == STANDING_MEMBER) {
            val framed = merge.welcomes
            if (framed != null) {
                // §19.2: the Welcomes of the own winning commit, enqueued after its merge.
                for (w in framed.entries) {
                    val operationId = env.random.bytes(OperationId.SIZE)
                    sync.outbox.enqueue(
                        tx,
                        OutboundBlob(
                            OperationId(operationId), NamespaceId(w.ns), w.blob, ChannelTime.handshakeTtl(timerCode),
                            deadlineEpochSeconds = ChannelTime.handshakeDeadline(DmTime.floorMinute(now)),
                        ),
                    )
                    stores.posts.insertOp(tx, operationId, c, OpPurpose.WELCOME, w.kpRef)
                }
                // The update path's fresh leaf key replaces the current one (§19.17).
                val boxEnv = winner.boxEnv
                if (boxEnv != null) {
                    stores.members.currentBoxKey(tx.sql, c)?.let { stores.members.retireBoxKey(tx, c, it.boxPk, e) }
                    stores.members.insertBoxKey(tx, c, framed.boxPk, boxEnv)
                }
            }
        }
        stores.candidates.deleteEpoch(tx, c, e)
        for (g in stores.generations.live(tx.sql, c, day)) sync.inbox.reofferDeferred(tx, NamespaceId(g.namespaceId))
        return true
    }

    /**
     * The `ch_channel` mirror of the context (timer, class, password flag, name) and the committers digest, when the
     * winner changed them. The digest is forgotten, not recomputed here: the digest is a Rust derivation (G-DM3), and the
     * next pass reads it from `roster`'s output (§19.37 F-S4-2, closed in S5a) and persists it.
     */
    private fun mirrorPolicy(tx: SyncTransaction, c: ByteArray, nameEnv: ByteArray?, merge: Merge, content: ContentCipher) {
        val after = merge.after ?: return
        val before = merge.before
        val nameChanged = !after.name.contentEquals(before.name)
        if (after.timerCode != before.timerCode || after.sizeClass != before.sizeClass || after.flags != before.flags || nameChanged) {
            val env2 = if (!nameChanged) nameEnv else if (after.name.isEmpty()) null else env.seal(content, ChannelAd.name(c), after.name)
            stores.channels.setPolicy(tx, c, after.timerCode, after.sizeClass, after.flags and ChannelEnv.FLAG_PASSWORD != 0, env2)
        }
        val sameCommitters = after.committers.size == before.committers.size &&
            after.committers.indices.all { after.committers[it].contentEquals(before.committers[it]) }
        if (!sameCommitters) stores.channels.setCommittersDigest(tx, c, null)
    }

    /**
     * Room for the next epoch's row (the schema keeps 17: the current epoch and 16 past, S0-6): the channel's epochs past
     * their retention are deleted first, then — when the bound is still met — the oldest final one, whose secrets
     * OpenMLS no longer keeps either (`max_past_epochs(16)`). The full `CH-SWEEP` with `sweepPast` is slice S8's.
     */
    private fun makeRoom(tx: SyncTransaction, c: ByteArray, day: Long) {
        for (k in stores.epochs.expired(tx.sql, day, EpochStore.MAX_EPOCHS * 4)) {
            if (k.channelId.contentEquals(c)) {
                stores.epochs.deleteForkSignals(tx, c, k.epoch)
                stores.epochs.delete(tx, c, k.epoch)
            }
        }
        val retained = stores.epochs.retained(tx.sql, c, day)
        if (retained.size >= EpochStore.MAX_EPOCHS) {
            val oldest = retained.filter { it.finalDay != null }.minByOrNull { it.epoch } ?: return
            stores.epochs.deleteForkSignals(tx, c, oldest.epoch)
            stores.epochs.delete(tx, c, oldest.epoch)
        }
    }

    override fun toString(): String = "ChannelSettleStep"

    companion object {
        /** `settle`'s standing (§6.6): 1 member, 2 removed, 3 replaced. */
        const val STANDING_MEMBER: Int = 1
        const val STANDING_REPLACED: Int = 3

        /** CO-1: the rank of a member that is no committer. */
        const val NOT_A_COMMITTER: Int = 255

        /** §6.5: `switch_hour = ceil_hour(commit_minute + 30 min)`, clamped to at most the settle + 2 h. */
        const val SWITCH_DELAY_SECONDS: Long = 30 * DmTime.MINUTE
        const val SWITCH_CLAMP_SECONDS: Long = 2 * DmTime.HOUR
    }
}
