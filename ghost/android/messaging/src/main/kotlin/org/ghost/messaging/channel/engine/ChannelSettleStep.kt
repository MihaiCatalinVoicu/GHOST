package org.ghost.messaging.channel.engine

import org.ghost.crypto.bridge.ChannelCrypto
import org.ghost.crypto.bridge.ChannelPolicy
import org.ghost.crypto.bridge.HeldBlob
import org.ghost.crypto.bridge.MlsChange
import org.ghost.crypto.bridge.MlsCode
import org.ghost.crypto.bridge.MlsField
import org.ghost.crypto.bridge.MlsOutcome
import org.ghost.messaging.channel.store.CandidateStore
import org.ghost.messaging.channel.store.ChannelState
import org.ghost.messaging.channel.store.ChannelStore
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
 * **`CH-SETTLE`** (Phase 10 design §6.4 CO-3 … CO-6, §10.4), **one transaction**: the member settles
 * its current epoch at the settle point and merges the winner.
 *
 * **The settle point (CO-4).** (i) `now ≥ anchor(e) + 20 min`, the anchor being the earliest, over
 * the held candidates, of the member's first sighting of the candidate and the copy's relay store
 * hour + 60 min (`ch_epoch.anchor_minute`, kept by `CH-RECV`, `CH-OUTCOME` and the fetched-copy
 * branch of `CH-RECV`). For the member's **own** commit the creation pass is its first sighting of
 * the candidate, and the anchor only moves **earlier** from there — when a stored copy is
 * evidenced: the op's SENT/DEGRADED outcome, or a fetched copy recognised by its hash (D-4/D-5,
 * owner 2026-10-05) with its relay store hour + 60 min (D-4). (ii) after (i) held, one completed
 * listing pass over
 * **every** relay of the current generation's set since the window opened: `Inbox.listingTails`
 * (F-S4-1, S5a) must name every relay of `env.relaySet(ns, week)` with a tail at or after the
 * window's opening moment. The opening moment is read on the monotonic clock —
 * `monotonicNow − (now − windowOpen) × 1000` — the same elapsed-realtime source `:sync`'s read lane
 * records tails on (`DmClock.monotonicMillis` is wired to `SyncClock` in `:app`), so in the worlds,
 * whose two clocks advance in lockstep, the comparison says exactly "the pass completed at or
 * after the window opened" and is monotone in virtual time; a wall-clock step only re-asks the
 * question, conservatively after a forward step.
 *
 * **The winner (CO-3).** Among the valid candidates held, excluding the **abandoned** ones (the
 * candidate's own committer has an authenticated message among the held blobs that open under
 * another candidate's trial state), the winner **maximises the successor senders**, then minimises
 * `(rank, SHA-256(commit))`. Successor senders come from **trial settles**: when more than one
 * valid candidate is held and some held blob does not open under the member's current keys (the
 * inbox rows `CH-RECV` deferred — `Inbox.held`, S5's read), each candidate is tried in memory with
 * **one** `MlsNative.trialCount` call over the ≤ 32 held blobs (≤ 8 foreign candidates, plus the
 * one own-custody trial of CO-4 (a); nothing is written). Otherwise every count is 0 and CO-3 is
 * the plain `(rank, hash)` rule. The member's **own** candidate without a verified copy ranks
 * below every held foreign candidate unless it has **more** successor senders than that candidate
 * (§19.13); an own candidate with successor evidence but no verified copy is **adopted** (CO-4 (a),
 * MM-32's shape: others merged it and continued, which proves a copy existed).
 *
 * **Own-commit custody (CO-4 (a)–(c)).** At each settle point: (a) an own commit that wins with a
 * verified copy (op SENT/DEGRADED or a fetched copy, D-5) or with at least one successor sender in
 * its trial settle is merged (for an unverified own commit the trial runs whenever a held blob does
 * not open, even if it is the only candidate); (b) when another candidate wins, the pending commit
 * is cleared (`clearOwn`) before the winner merges; (c) when no copy can remain on any relay — the
 * op's deadline plus the handshake TTL has passed (`first_seen + 7 d + handshakeTTL`, §5.8's
 * deadline is the author minute + 7 d) — the pending commit is cleared and counted
 * (`OWN_COMMIT_CLEARED`); until then it stays pending.
 *
 * **The merge (CO-5).** A foreign winner is first run again for its validation summary (the
 * `GhostCommitAad` evidence of its Adds, which the stored candidate does not keep), the own pending
 * commit — if any — is cleared, and the winner is merged (`settle`, which re-runs CO-2); an own
 * winner merges from the pending commit. In the same transaction: the change-set; the epoch final
 * (`winner_hash` is the commit that ended it, §19.35 F-5), logged, and the next epoch's keys; a
 * rotation's next generation as `pending_switch` (its switch is `CH-SWITCH`'s, S6); the invites the
 * winner's Adds consumed, their pending requests, the sponsor records and — for a committer — the
 * KeyPackages' tags; for an **own** winner its WELCOME blobs enqueued (§19.2) and its new leaf's
 * box key; the policy mirror; when the winner changed `committers`, the new digest `roster` returns
 * (S5a) is persisted and **every unconsumed invite whose `committers_digest` no longer matches is
 * voided** (S0-15), and when it bumped `pw_version`, **every unconsumed invite of the older
 * version** (§19.29.3) — both counted (`INVITE_VOIDED`; the sponsor's UI reads the row's `void`);
 * every candidate of the epoch deleted; the namespaces' deferred blobs re-offered. A member the
 * winner removes (`standing` 2) or replaces (3) records the state and the final epoch; the rest of
 * its departure is slice S6's.
 *
 * Gate G-M5 lists this file for `Outbox.enqueue` (the own winner's Welcomes).
 */
internal class ChannelSettleStep(
    private val env: ChannelEnv,
    private val sync: ChannelSyncPorts,
    /** CO-11 (b): a foreign winner's merge is progress (the liveness window reads it). */
    private val liveness: ChannelLivenessStep? = null,
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
     * The second the earliest settle point of an epoch with candidates comes (the actor's next wake),
     * or null. An epoch whose only candidate is the member's **own commit with no verified copy** is
     * no wake (§19.38): CO-4 waits for that commit's copy evidence, which arrives as an outcome hint
     * or a fetched copy and runs the settle in that pass; a wake at its settle point could only find
     * it waiting still. The (ii) listing-pass check needs no term of its own: the relay sessions list
     * continuously, and every pass re-runs [settleDue].
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
        val afterDigest: ByteArray?,
        val committer: Boolean,
        /** The own candidate of the epoch, when one was held: its rank (CO-9's retry) and the new leaf's box key. */
        val own: CandidateStore.CandidateRow?,
        val ownBoxPk: ByteArray?,
        /** The members whose leaf the winner's update path refreshed (§6.6's `ch_member_refresh`): their pseudonyms. */
        val refreshed: List<ByteArray>,
        /** The member's own pseudonym: what the removed branch deletes its rows by (§8.5, §19.42). */
        val self: ByteArray,
        /** The members the winner removed (the pre-commit roster minus the post-commit one): their rows go at this merge. */
        val removed: List<ByteArray>,
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

    /** The snapshot one settle works from: taken in one transaction, the native half runs outside it. */
    private class Snapshot(
        val channel: ChannelStore.ChannelRow,
        val epoch: EpochStore.EpochRow,
        val candidates: List<CandidateStore.CandidateRow>,
        val generation: Long,
        val rows: List<org.ghost.crypto.bridge.MlsRow>,
        val liveNamespaces: List<ByteArray>,
    )

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
            // CO-4 (c): an own commit whose op's deadline plus the handshake TTL has passed with no
            // verified copy can exist on no relay any more: its pending commit is cleared here, at
            // the channel's settle check, before the candidates are read.
            custodyClear(tx, channelId, channel.timerCode, epoch.epoch, opened, now)
            val freshEpoch = stores.epochs.open(tx.sql, channelId, day) ?: return@transaction null
            val candidates = stores.candidates.candidates(tx.sql, channelId, freshEpoch.epoch)
            if (candidates.isEmpty()) {
                // The candidates went (an own commit cleared, CO-4): no settle point any more.
                if (freshEpoch.anchorMinute != null) stores.epochs.setAnchor(tx, channelId, freshEpoch.epoch, null)
                return@transaction null
            }
            val anchor = freshEpoch.anchorMinute ?: return@transaction null
            if (now < anchor + ChannelTime.SETTLE_WINDOW_SECONDS) return@transaction null
            // CO-4 (ii): one listing pass over every relay of the current generation's set since the
            // window opened (listingTails, F-S4-1/S5a). The window's opening moment is read on the
            // monotonic clock, the one the read lane records tails on.
            val generation = stores.generations.current(tx.sql, channelId, day) ?: return@transaction null
            val set = env.relaySet(generation.namespaceId, DmTime.week(now)) ?: return@transaction null
            val windowOpenMono = env.clock.monotonicMillis() - (now - anchor - ChannelTime.SETTLE_WINDOW_SECONDS) * 1000
            val tails = sync.inbox.listingTails(NamespaceId(generation.namespaceId))
            for (slot in set) {
                if ((tails[slot.relay] ?: Long.MIN_VALUE) < windowOpenMono) return@transaction null
            }
            Snapshot(
                channel = channel,
                epoch = freshEpoch,
                candidates = candidates,
                generation = generation.generation,
                rows = MlsRows.of(stores.mls.rows(tx.sql, channelId, day)),
                liveNamespaces = stores.generations.live(tx.sql, channelId, day).map { it.namespaceId },
            )
        } ?: return false
        // CO-3's held blobs: what the receive step deferred (nothing opens them under the member's
        // current keys), at most 32, one deterministic set at every member.
        val held = snapshot.liveNamespaces
            .flatMap { ns -> sync.inbox.held(NamespaceId(ns), now, HELD_BLOBS).map { h -> HeldBlob(ns, h.ciphertext) } }
            .sortedWith { a, b -> compareBytes(a.ns, b.ns).takeIf { it != 0 } ?: compareBytes(a.blob, b.blob) }
            .take(HELD_BLOBS)
        val merge = merge(channelId, opened, content, snapshot, held, day) ?: return false
        return try {
            env.database.transaction { tx -> write(tx, channelId, snapshot.channel.timerCode, snapshot.epoch, merge, content, seenKey, now, day) }
        } catch (e: InsufficientReplicasException) {
            // The own winner's Welcomes cannot be enqueued this week: nothing is written; the settle is tried again.
            false
        } catch (e: StorageFullException) {
            false
        }
    }

    /**
     * CO-4 (c): the own commit of [epoch], if it is still unverified and its op's deadline plus the
     * handshake TTL has passed (its `first_seen_minute` is the op's author minute; §5.8's handshake
     * deadline is the author minute + 7 d), is cleared: no copy can remain on any relay. The
     * transaction is the caller's; the native change-set applies only on `OK` (D5).
     */
    private fun custodyClear(
        tx: SyncTransaction,
        channelId: ByteArray,
        timerCode: Int,
        epoch: Long,
        opened: ChannelContexts.Opened,
        now: Long,
    ) {
        val day = DmTime.day(now)
        val own = stores.candidates.own(tx.sql, channelId, epoch) ?: return
        if (own.verified) return
        val clearAt = own.firstSeenMinute + CUSTODY_DEADLINE_SECONDS + ChannelTime.handshakeTtl(timerCode).seconds
        if (now < clearAt) return
        val rows = MlsRows.of(stores.mls.rows(tx.sql, channelId, day))
        when (val r = opened.crypto.clearOwn(channelId, rows, day.toInt())) {
            is MlsOutcome.Ok -> stores.mls.apply(tx, channelId, MlsRows.changes(r.value))
            is MlsOutcome.Refused -> throw IllegalStateException("channel clearOwn refused: ${r.refusal.code}")
        }
        stores.candidates.delete(tx, channelId, epoch, own.hash)
        if (stores.candidates.candidates(tx.sql, channelId, epoch).isEmpty()) {
            stores.epochs.setAnchor(tx, channelId, epoch, null)
        }
        env.counters.count(ChannelCounters.Reason.OWN_COMMIT_CLEARED)
    }

    /** The native half: the winner chosen (CO-3, with the trial settles), run and merged in memory; null when there is nothing to settle yet. */
    private fun merge(
        channelId: ByteArray,
        opened: ChannelContexts.Opened,
        content: ContentCipher,
        snapshot: Snapshot,
        held: List<HeldBlob>,
        day: Long,
    ): Merge? {
        val epoch = snapshot.epoch
        val e = epoch.epoch
        val candidates = snapshot.candidates
        val stored = snapshot.rows
        val own = candidates.firstOrNull { it.own }
        val foreign = candidates.filter { !it.own }.sortedWith(ChannelReceiveStep.CANDIDATE_ORDER)

        // CO-3: the trial settles. They run only when more than one valid candidate is held and some
        // held blob does not open under the member's current keys (every held row is one the receive
        // step deferred: nothing opens it under the current keys); and, for the own-custody verdict,
        // whenever an unverified own commit is held and a held blob does not open — even as the only
        // candidate. One trialCount call per candidate (≤ 8 foreign ones plus the own one), ≤ 32 held
        // blobs each; nothing is written.
        val counts = HashMap<List<Byte>, Int>()
        val movedOn = HashSet<List<Byte>>()
        if (held.isNotEmpty() && (candidates.size > 1 || (own != null && !own.verified))) {
            for (cand in foreign + listOfNotNull(own)) {
                val body = content.open(cand.bodyEnv, ChannelAd.candidate(channelId, e, cand.hash)) ?: return refuseWinner(channelId, e, cand)
                val arg = if (cand.own) ChannelCrypto.Winner.Own(body) else ChannelCrypto.Winner.Foreign(body)
                when (val t = opened.crypto.trialCount(channelId, stored, arg, held, day.toInt())) {
                    is MlsOutcome.Ok -> {
                        // CO-3: the successor senders exclude the candidate's own committer (the
                        // native side excludes the member itself); a committer's message under its
                        // own trial state is no abandonment — only under ANOTHER candidate's.
                        val successors = t.value.senders.filter { !it.contentEquals(cand.sender) }
                        counts[cand.hash.toList()] = successors.size
                        movedOn += successors.map { it.toList() }
                    }
                    is MlsOutcome.Refused -> return when (t.refusal.code) {
                        MlsCode.CRYPTO_UNAVAILABLE, MlsCode.STATE_CORRUPT -> null
                        else -> refuseWinner(channelId, e, cand)
                    }
                }
            }
        }

        // CO-3: abandoned candidates — their own committer has an authenticated message among the
        // held blobs that open under another candidate's trial state — are excluded (the member's own
        // candidate cannot be abandoned: its committer's own blobs are never fetched back).
        val viable = candidates.filter { it.sender.toList() !in movedOn }
        if (viable.isEmpty()) return null
        // CO-3: the winner maximises the successor senders, then minimises `(rank, hash)`; the
        // unverified-own demotion and the adoption rule sit between (EM-3's `better`, the rule the
        // conformance probe replays — S5c).
        val views = viable.map { Co3View(it.rank, it.hash.toList(), it.own, it.verified) }
        val picked = co3Pick(views, counts) ?: return null
        val winner = viable.first { it.hash.toList() == picked.hash }

        val body = content.open(winner.bodyEnv, ChannelAd.candidate(channelId, e, winner.hash)) ?: return refuseWinner(channelId, e, winner)
        val beforeRoster = opened.crypto.roster(channelId, stored, day.toInt()).valueOrNull() ?: return null
        val before = beforeRoster.context
        val committer = before.committers.any { it.contentEquals(opened.pseudonym) }
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
            settled = when (val s = opened.crypto.settle(channelId, rows, ChannelCrypto.Winner.Own(body), snapshot.generation.toInt(), day.toInt())) {
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
                // CO-4 (b): another candidate wins at a settle point, so the own pending commit is
                // cleared before the winner is merged.
                val cleared = opened.crypto.clearOwn(channelId, rows, day.toInt()).valueOrNull() ?: return null
                changes += cleared
                rows = MlsRows.applied(rows, cleared)
            }
            settled = when (val s = opened.crypto.settle(channelId, rows, ChannelCrypto.Winner.Foreign(body), snapshot.generation.toInt(), day.toInt())) {
                is MlsOutcome.Ok -> s.value
                is MlsOutcome.Refused -> return if (s.code == MlsCode.CRYPTO_UNAVAILABLE || s.code == MlsCode.STATE_CORRUPT) null else refuseWinner(channelId, e, winner)
            }
        }
        changes += settled.changes
        val afterRoster = if (settled.standing == STANDING_MEMBER) {
            opened.crypto.roster(channelId, MlsRows.applied(rows, settled.changes), day.toInt()).valueOrNull()
        } else {
            null
        }
        val ownBoxPk = afterRoster?.members?.firstOrNull { it.pseudonym.contentEquals(opened.pseudonym) }?.boxPk
        // §6.6: the winner's update path refreshes its committer's leaf with `refresh_epoch = e` (§6.8's
        // force_self_update is native for every commit): the members to stamp in `ch_member_refresh`.
        val refreshed = afterRoster?.members?.filter { it.refreshEpoch == e }?.map { it.pseudonym.copyOf() } ?: emptyList()
        // §8.5, the review of S6 (§19.42): the members the winner removed — the pre-commit roster minus the
        // post-commit one (a swap keeps its pseudonym, so a restore/rejoin is not a removal). Null for the
        // member the winner removed itself: its own settle takes the removed branch below, which deletes
        // its rows by its own pseudonym.
        val removed = afterRoster?.members?.let { after ->
            beforeRoster.members
                .filterNot { b -> after.any { it.pseudonym.contentEquals(b.pseudonym) } }
                .map { it.pseudonym.copyOf() }
        } ?: emptyList()
        return Merge(winner, changes, settled, admitted, framed, before, afterRoster?.context, afterRoster?.committersDigest, committer, own, ownBoxPk, refreshed, opened.pseudonym, removed)
    }

    /** Lexicographic byte order: the deterministic order of the held blobs and the trial keys. */
    private fun compareBytes(a: ByteArray, b: ByteArray): Int {
        val n = minOf(a.size, b.size)
        for (i in 0 until n) {
            val c = a[i].compareTo(b[i])
            if (c != 0) return c
        }
        return a.size.compareTo(b.size)
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
            // §6.6: removed (or replaced by a restore of its own pseudonym): the state is recorded, the
            // MLS state goes (§6.6 "deletes the MLS state"), and the departure keeps listening until the
            // drain ends. The deletion is the merge's, not the leave op's outcome's: a leaver whose op
            // resolved before the removing commit arrived must still merge it (recorded in §19.41).
            val to = if (settled.standing == STANDING_REPLACED && fresh.state == ChannelState.ACTIVE) ChannelState.REPLACED else ChannelState.REMOVED
            stores.channels.transition(tx, c, fresh.state, to)
            stores.mls.deleteGroupRows(tx, c)
            // §8.5, the review of S6 (§19.42): the removed member's rows go with the removal, in the same
            // transaction as its MLS state — the refresh and member-seen records and the sponsor
            // attribution of a member no longer in the channel are residue ("deleted at its removal").
            stores.members.deleteRefresh(tx, c, merge.self)
            stores.members.deleteMemberSeen(tx, c, merge.self)
            stores.invites.deleteSponsor(tx, c, merge.self)
            env.contexts.closeChannel(c)
            // §6.5 "What a removed member keeps": a removal rotates, and the removed member keeps listing
            // `ns_g` until the drain ends — `drain_until_day` is the day of the removing commit's switch hour
            // plus 14 (computed here from the commit's minute, so a member that learns of its removal late
            // ends the drain on the same day as everyone). The native side returns the rotation flag for a
            // removed member but no generation values (it has no next epoch), so the flag is the check.
            // A member removed while its previous generation still drains (a second rotation inside one
            // drain) ends the older drain at once — at most one draining generation per channel — and the
            // demotion of the current one waits for the sweep's removal of the older ([ChannelSweepStep],
            // the corner needs an op of the old namespace still open here; recorded in §19.41). The older
            // drain is read without the drain filter (the review of S6, §19.42): one whose end already
            // moved to before today is invisible to live() but its row still reads `draining`, and the
            // demotion's at-most-one-draining trigger would abort this transaction on it — the same
            // end-or-defer shape the switch takes, and the sweep owns the removal retry either way.
            if (settled.rotates) {
                val commitSeconds = settled.commitMinute * DmTime.MINUTE
                val switchHour = minOf(DmTime.ceilHour(commitSeconds + SWITCH_DELAY_SECONDS), DmTime.ceilHour(now + SWITCH_CLAMP_SECONDS))
                val older = stores.generations.live(tx.sql, c, day).firstOrNull { it.state == GenerationState.DRAINING }
                    ?: stores.generations.draining(tx.sql, c)
                if (older == null) {
                    stores.generations.demote(tx, c, fresh.generation, DmTime.day(switchHour) + DRAIN_DAYS)
                } else {
                    stores.generations.endDrainEarly(tx, c, older.generation, day)
                    sync.namespaces.setListening(tx, NamespaceId(older.namespaceId), false)
                }
            }
        } else {
            makeRoom(tx, c, day)
            stores.epochs.insert(tx, c, next.epoch, next.kEnv, next.rEp)
            stores.channels.setPosition(tx, c, fresh.generation, next.epoch)
            settled.rotated?.let { g ->
                // §6.5: the next generation waits for its switch hour (CH-SWITCH, slice S6). `own_rotation`
                // marks a generation the member's own commit opened: that member funds it at its switch.
                val commitSeconds = settled.commitMinute * DmTime.MINUTE
                val switchHour = minOf(DmTime.ceilHour(commitSeconds + SWITCH_DELAY_SECONDS), DmTime.ceilHour(now + SWITCH_CLAMP_SECONDS))
                stores.generations.insert(
                    tx, c, g.generation, g.ns, GenerationState.PENDING_SWITCH, g.gEnv, g.jkEnv, g.rJoin, g.openEpoch,
                    ownRotation = winner.own,
                    switchHour = switchHour,
                )
            }
            if (winner.rank < NOT_A_COMMITTER) stores.channels.setLastCommitterCommitDay(tx, c, day)
            // CO-11 (b): a foreign winner's merge is progress for every member that merged it.
            if (!winner.own && settled.standing == STANDING_MEMBER) liveness?.noteMerged(tx, c, content, day)
            mirrorPolicy(tx, c, fresh.nameEnv, merge, content)
            voidInvites(tx, c, merge)
            // §6.6: the committer's per-member refresh days (a committer's rows only — nobody else reads them).
            if (merge.committer) {
                for (p in merge.refreshed) stores.members.putRefresh(tx, c, p, day)
            }
            // §8.5, the review of S6 (§19.42): the winner's removed members' rows go at this merge, on
            // every staying member's device — the committer's idle-eviction scan reads `ch_member_refresh`,
            // and a removed member's stale row there would crowd out the real idler (the pass walks the
            // candidate set beyond one SQL round now, and this deletes them at the source).
            for (r in merge.removed) {
                stores.members.deleteRefresh(tx, c, r)
                stores.members.deleteMemberSeen(tx, c, r)
                stores.invites.deleteSponsor(tx, c, r)
            }
        }
        for (a in merge.admitted) {
            stores.invites.markConsumed(tx, c, a.inviteId)
            stores.joins.deleteRequestsOfInvite(tx, c, a.inviteId)
            a.member?.let {
                stores.invites.putSponsor(tx, c, it, a.sponsor, a.inviteId, day)
                // §6.6: a join is the joiner's last leaf refresh.
                if (merge.committer) stores.members.putRefresh(tx, c, it, day)
            }
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
            }
            // The update path's fresh leaf key replaces the current one (§19.17) — on every own winning
            // commit, Welcomes or none: a PCS, Remove or self-update commit refreshes the leaf too (§6.8's
            // force_self_update). The new leaf's box public key comes from the merged state (a welcome-less
            // commit keeps no `welcome_env` framing to read it from).
            val boxEnv = winner.boxEnv
            if (boxEnv != null && merge.ownBoxPk != null) {
                stores.members.currentBoxKey(tx.sql, c)?.let { stores.members.retireBoxKey(tx, c, it.boxPk, e) }
                stores.members.insertBoxKey(tx, c, merge.ownBoxPk, boxEnv)
            }
        } else if (!winner.own && merge.own != null && merge.own.rank == NOT_A_COMMITTER) {
            // CO-9: the self-update lost the tie-break — the retry fires at the next session after 24 h
            // (day-granular, what `ch_schedule.next_selfupdate_day` can say). A FAILED op (no copy could
            // exist) never reaches here: the candidate was cleared by custody, and the pass already armed
            // the next period's slot.
            val row = stores.channels.schedule(tx.sql, c)
            stores.channels.putSchedule(tx, c, day + 1, row?.lastOwnCommitDay ?: day, row?.nextPassMinute)
        }
        stores.candidates.deleteEpoch(tx, c, e)
        for (g in stores.generations.live(tx.sql, c, day)) sync.inbox.reofferDeferred(tx, NamespaceId(g.namespaceId))
        return true
    }

    /**
     * The `ch_channel` mirror of the context (timer, class, password flag, name) the winner changed.
     * The committers digest and the invite voiding are [voidInvites]'s: the digest is a Rust
     * derivation (G-DM3), read from `roster`'s output (§19.37 F-S4-2, closed in S5a).
     */
    private fun mirrorPolicy(tx: SyncTransaction, c: ByteArray, nameEnv: ByteArray?, merge: Merge, content: ContentCipher) {
        val after = merge.after ?: return
        val before = merge.before
        val nameChanged = !after.name.contentEquals(before.name)
        if (after.timerCode != before.timerCode || after.sizeClass != before.sizeClass || after.flags != before.flags || nameChanged) {
            val env2 = if (!nameChanged) nameEnv else if (after.name.isEmpty()) null else env.seal(content, ChannelAd.name(c), after.name)
            stores.channels.setPolicy(tx, c, after.timerCode, after.sizeClass, after.flags and ChannelEnv.FLAG_PASSWORD != 0, env2)
        }
    }

    /**
     * CO-5 (S0-15, §19.29.3): the winner's context is the member's new one — when it changed
     * `committers`, the new digest `roster` returned is persisted and every unconsumed invite whose
     * digest no longer matches is void (the sponsor's UI tells its user and offers a new one,
     * §19.29.2); when it bumped `pw_version`, every unconsumed invite of the older version is void
     * (a newly set password voids the open invites too). Counts only; the row's `void` is the
     * sponsor-visible state.
     */
    private fun voidInvites(tx: SyncTransaction, c: ByteArray, merge: Merge) {
        val after = merge.after ?: return
        val before = merge.before
        val digest = merge.afterDigest
        val sameCommitters = after.committers.size == before.committers.size &&
            after.committers.indices.all { after.committers[it].contentEquals(before.committers[it]) }
        if (!sameCommitters && digest != null) {
            stores.channels.setCommittersDigest(tx, c, digest)
            repeat(stores.invites.voidByDigest(tx, c, digest)) { env.counters.count(ChannelCounters.Reason.INVITE_VOIDED) }
        }
        if (after.pwVersion > before.pwVersion) {
            val includeOpen = before.pwVersion == 0
            repeat(stores.invites.voidByPassword(tx, c, after.pwVersion, includeOpen)) { env.counters.count(ChannelCounters.Reason.INVITE_VOIDED) }
        }
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

    /** A plain view of a viable candidate for [co3Pick] (the EM-3 conformance probe builds these directly). */
    internal class Co3View(
        val rank: Int,
        /** SHA-256 of the commit's bytes, as a list (the map's key). */
        val hash: List<Byte>,
        val own: Boolean,
        val verified: Boolean,
    ) {
        override fun toString(): String = "Co3View(rank=$rank, own=$own, verified=$verified)"
    }

    companion object {
        /** CO-3's `(rank, hash)` ascending order over the plain views (the fallback, inverted in [co3Pick]). */
        private val BY_RANK_HASH: Comparator<Co3View> =
            compareBy<Co3View> { it.rank }.thenComparator { a, b ->
                ChannelReceiveStep.compareUnsigned(a.hash.toByteArray(), b.hash.toByteArray())
            }

        /** `settle`'s standing (§6.6): 1 member, 2 removed, 3 replaced. */
        const val STANDING_MEMBER: Int = 1
        const val STANDING_REPLACED: Int = 3

        /**
         * CO-3's decision over the viable candidates (abandonment already applied), as the EM-3
         * model's `better` semantics run it (§19.34: maximise the successor senders, then minimise
         * `(rank, hash)`; S5b2's fix): the foreign best by that order; an own candidate with a
         * verified copy competes on the order; an **unverified** own candidate ranks below every
         * held foreign one unless it has strictly more successor senders (§19.13), and is adopted
         * as the only viable candidate on at least one successor sender (CO-4 (a)). The engine and
         * the model agree by construction — the conformance probe replays scripted sets over this
         * function (S5c).
         */
        fun co3Pick(viable: List<Co3View>, counts: Map<List<Byte>, Int>): Co3View? {
            fun successors(v: Co3View): Int = counts[v.hash] ?: 0
            // maxWith carries the comparison: more successors compare greater, the ascending
            // `(rank, hash)` order is inverted in the fallback.
            val byCo3 = Comparator<Co3View> { a, b ->
                val sa = successors(a)
                val sb = successors(b)
                if (sa != sb) sa - sb else BY_RANK_HASH.compare(b, a)
            }
            val own = viable.firstOrNull { it.own }
            val bestForeign = viable.filter { !it.own }.maxWithOrNull(byCo3)
            return when {
                own == null -> bestForeign
                bestForeign == null ->
                    if (own.verified || successors(own) >= 1) own else null
                !own.verified ->
                    if (successors(own) > successors(bestForeign)) own else bestForeign
                else -> listOf(own, bestForeign).maxWith(byCo3)
            }
        }

        /** CO-1: the rank of a member that is no committer. */
        const val NOT_A_COMMITTER: Int = 255

        /** §6.5: `switch_hour = ceil_hour(commit_minute + 30 min)`, clamped to at most the settle + 2 h. */
        const val SWITCH_DELAY_SECONDS: Long = 30 * DmTime.MINUTE
        const val SWITCH_CLAMP_SECONDS: Long = 2 * DmTime.HOUR

        /** §6.5 "Drain": 14 days — the 7-day store window plus 2σ of Phase 7's 3-day clock tolerance. */
        const val DRAIN_DAYS: Long = 14

        /** CO-3: at most 32 held blobs per trial settle (§6.3.5). */
        const val HELD_BLOBS: Int = 32

        /** CO-4 (c): §5.8's handshake op deadline is the author minute + 7 days; the copy can live one TTL past it. */
        const val CUSTODY_DEADLINE_SECONDS: Long = 7 * DmTime.DAY
    }
}
