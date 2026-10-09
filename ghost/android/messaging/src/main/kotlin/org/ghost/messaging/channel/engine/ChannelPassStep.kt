package org.ghost.messaging.channel.engine

import org.ghost.crypto.bridge.AdmitEvidence
import org.ghost.crypto.bridge.ChannelCrypto
import org.ghost.crypto.bridge.ChannelPolicy
import org.ghost.crypto.bridge.CommitRequest
import org.ghost.crypto.bridge.MlsCode
import org.ghost.crypto.bridge.MlsField
import org.ghost.crypto.bridge.MlsOutcome
import org.ghost.messaging.channel.store.ChannelState
import org.ghost.messaging.channel.store.JoinStore
import org.ghost.messaging.channel.store.JoinType
import org.ghost.messaging.channel.store.OpPurpose
import org.ghost.messaging.engine.DmTime
import org.ghost.storage.StorageFullException
import org.ghost.sync.api.InsufficientReplicasException
import org.ghost.sync.api.NamespaceId
import org.ghost.sync.api.OperationId
import org.ghost.sync.api.OutboundBlob
import java.nio.ByteBuffer

/**
 * **`CH-PASS`** (Phase 10 design §6.2.3, §6.2.4, §6.4 CO-7 … CO-9 and CO-14, §6.6, §6.8, §10.4), **one transaction**:
 * a member's pass over its channel — the full committer pass of slice S5b2, where S4 ran only rank 0's admissions.
 *
 * **Preconditions (CO-7, D-1).** The channel is current ([ChannelPostStep.isCurrent]: active, no removal hold, no
 * generation waiting for its switch), the committer holds no pending commit, and it holds **no valid candidate for
 * its current epoch, of any rank** — a rank-255 self-update candidate delays a pass to the settle point (at most
 * 20 minutes and one listing pass, §19.5) and never blocks it. The engine settles before the scheduled passes run
 * ([ChannelEngine.runPass]), so a pass after a settle works in e + 1 in the same actor step; a user action settles
 * first the same way ([ChannelEngine.remove]). After a rotating winner at the generation switch the pass re-checks
 * at the next step where the channel is current — the switch itself is `CH-SWITCH`'s (slice S6).
 *
 * **What a pass commits, by rank (CO-8, §19.13 item 4).** Every committer's user actions are passes at once,
 * whatever its rank; a scheduled pass (§6.8: every commit carries `force_self_update`, so any commit refreshes the
 * leaf):
 *  - **rank 0** admits the pending join requests (the policy of §6.2.4 (B) below) and refuses what it refuses; when
 *    no admissions remain it commits the **PCS** commit (empty, with a path) only if its last own commit is at least
 *    7 days old — at least 1 day in channels with timers ≤ 1 d (Q36, §19.19; [ChannelTime.pcsDays]);
 *  - **rank r ≥ 1** admits only requests it first recorded at least `r × 48 h` earlier (`ch_join_request.recorded_day`,
 *    §19.35 F-11 (a) amended by S5: a fresh request is the owner's to take first; the owner returning re-takes its
 *    work, the race is CO-10's), and otherwise commits its own PCS commit when its last commit is ≥ 7 days old
 *    (the daily cadence of short-timer channels is rank 0's alone);
 *  - **rank 255** commits nothing here but CO-9's self-update: an empty commit at the first session after its PRF
 *    slot ([ChannelSchedule]), retried at the next session after 24 h when it lost the tie-break (the settle arms
 *    the retry, [ChannelSettleStep]), skipped — the slot consumed — when CO-14 would refuse it (the pass checks its
 *    own leaf, [co14WouldRefuse], exactly the rule the native side applies to foreign rank-255 commits).
 *
 * **The admission policy (§6.2.4 (B)),** applied by the admitting committer only, to each aged request in arrival
 * order: the committer holds the `INVITE_ISSUED` (an unexpired `ch_invite_issued` row on its trusted day), the
 * invite is neither consumed nor void, its sponsor is a current member who may invite (CO-2 (A)'s own rule, checked
 * before the native call refuses it, §19.38), its `committers_digest` equals the digest of the committer's current
 * committers (`ch_channel.committers_digest`; unknown means no admission, fail closed — the digest comes from
 * `roster`, §19.37 F-S4-2 closed in S5a), the KeyPackage is canonical with `GhostKpBind.day` in `[day − 7, day + 3]`
 * (`joinVerify` checks the form, purpose, binding and both signatures natively; the window is checked here), its
 * keyed tag was never seen in the channel (`ch_kp_seen`, over `kp_ref` alone — F-S4-4), in a password channel the
 * invite's `pw_version` equals the context's, the pseudonym is not a current member, no two Adds share an invite,
 * and the member count after the commit stays within the class cap. A refused request is deleted and its KeyPackage's
 * tag recorded; a restore- or rejoin-purpose request is S7's (an invite-authorized swap) and is left pending.
 *
 * **The user-action Remove (§6.6, §19.13; SCN-CM's "committers still pass and remove the flooder").** A committer's
 * `remove` runs a pass at once with the Remove proposals; the native side enforces CO-2's rank rule (a rank removes
 * only higher ranks) and CO-1. When the removed member is a committer or a funder, the commit carries the context
 * change that drops its key from `committers`/`funders` — the same context-change machinery a password
 * set/change/remove uses (§19.29.3, Q45 (a): the rotation flag, the switch itself S6's). The removed member's
 * departure at the merge is §6.6's (slice S6 records the rest).
 *
 * **The commit** (`commit`, §10.2 fn 9) carries the valid Adds by value with their evidence in its `GhostCommitAad`
 * (§19.2), the Removes, the context change when one, the class floor, and the current generation's bootstrap
 * ((g, E_g, G_g), §5.4); the native side defers the Adds that do not fit the floor (§5.7) and refuses a KeyPackage
 * or evidence it does not accept by index, which this step refuses and retries without. The commit is sealed in
 * mode 0x11 under `K_ep(e)` into the current namespace and **enqueued**; one WELCOME blob per joiner is sealed in
 * mode 0x13 under the `JK_g` of the namespace its request came from and **kept wrapped in the committer's own
 * candidate row** (`welcome_env`, with what `CH-SETTLE` needs to enqueue it and to record the admission), never
 * enqueued here (§19.2: Welcomes only after a won commit). The losing committer's staged Welcome dies with its
 * candidate row at the settle — SCN-CD's "the loser deletes its Welcome".
 *
 * **Scheduling (CO-8, CO-9), persisted in `ch_schedule`** (S4 kept it in memory, §19.37 row 26; closed here). A
 * foreground session start schedules a due pass `U[0, 5 min]` later, at most once per 6 hours; after a scheduled
 * pass runs, its next is re-armed 6 hours out in the same column, so a restart does not re-run a pass inside its
 * window. A pass is scheduled when join work may pend, when a self-update slot is due, or when the PCS cadence may
 * be due — the cheap checks; the pass itself decides with the roster loaded. The Android JobScheduler wiring of
 * the background job (at most once per 24 h) is not this engine's; any time-triggered pass runs what is due.
 *
 * Gate G-M5 lists this file for `Outbox.enqueue`.
 */
internal class ChannelPassStep(
    private val env: ChannelEnv,
    private val sync: ChannelSyncPorts,
    private val postStep: ChannelPostStep,
) {
    private val stores = env.stores

    /** What [admit] and [remove] did. */
    enum class Result {
        /** A commit was built, its op enqueued and the own candidate recorded. */
        COMMITTED,

        /** Requests were refused and deleted; no commit (nothing valid remained). */
        REFUSED_ONLY,

        /** Nothing to do, or a precondition of CO-7 does not hold (the pass waits for the settle point). */
        NOTHING,

        /** The context or the content key is not available. */
        UNAVAILABLE,
    }

    /**
     * A relay session start (CO-8): every active channel whose work, self-update slot or PCS cadence may be due,
     * with no pass scheduled and none inside its 6-hour spacing, is scheduled `U[0, 5 min]` later. The schedule is
     * `ch_schedule` (a restart keeps it); a channel without a row — a committer added by a context change — gets one
     * seeded here, its own-commit day being today as far as the schedule knows.
     */
    fun scheduleAtSessionStart() {
        val now = env.now()
        val day = DmTime.day(now)
        val seenKey = env.keys.seenKey() ?: return
        try {
            val channels = env.database.transaction { tx -> stores.channels.channelsIn(tx.sql, ChannelState.ACTIVE) }
            for (channel in channels) {
                val key = channel.channelId.toList()
                val row = env.database.transaction { tx -> stores.channels.schedule(tx.sql, channel.channelId) }
                if (row == null) {
                    env.database.transaction { tx ->
                        stores.channels.putSchedule(
                            tx, channel.channelId,
                            ChannelSchedule.slotDay(channel.channelId, ChannelSchedule.period(day), seenKey), day, null,
                        )
                    }
                    continue
                }
                if (row.nextPassMinute != null) continue
                val workMaybe = env.database.transaction { tx ->
                    stores.joins.requests(tx.sql, channel.channelId, day).isNotEmpty() ||
                        stores.members.requests(tx.sql, channel.channelId, day).isNotEmpty()
                }
                val slotDue = day >= row.nextSelfupdateDay
                val pcsMaybe = row.lastOwnCommitDay != null &&
                    day - row.lastOwnCommitDay >= ChannelTime.pcsDays(channel.timerCode)
                if (!workMaybe && !slotDue && !pcsMaybe) continue
                val jitter = (env.random.u32() % (MAX_JITTER_MINUTES + 1)) * DmTime.MINUTE
                env.database.transaction { tx ->
                    stores.channels.putSchedule(tx, channel.channelId, row.nextSelfupdateDay, row.lastOwnCommitDay, DmTime.floorMinute(now) + jitter)
                }
            }
        } finally {
            seenKey.fill(0)
        }
    }

    /** The scheduled passes that are due, each run once ([admit]); returns how many committed. */
    fun runScheduledPasses(): Int {
        val now = env.now()
        val due = env.database.transaction { tx -> stores.channels.duePasses(tx.sql, DmTime.floorMinute(now), MAX_DUE_PASSES) }
        var committed = 0
        for (channelId in due) {
            if (admit(channelId) == Result.COMMITTED) committed++
            // The spacing, persisted: after a scheduled pass the next may run 6 hours out, and a restart
            // inside the window does not schedule again.
            env.database.transaction { tx ->
                val row = stores.channels.schedule(tx.sql, channelId)
                if (row != null) {
                    stores.channels.putSchedule(tx, channelId, row.nextSelfupdateDay, row.lastOwnCommitDay, DmTime.floorMinute(now) + PASS_SPACING_SECONDS)
                }
            }
        }
        return committed
    }

    /** The second the earliest scheduled pass is due (the actor's next wake), or null. */
    fun nextDue(): Long? = env.database.transaction { tx -> stores.channels.nextPassDue(tx.sql) }

    /** One scheduled pass over [channelId]'s work (CO-8, CO-9). */
    fun admit(channelId: ByteArray): Result = pass(channelId, null)

    /** `CH-PASS` at a user action: [member] removed, at once, whatever the committer's rank (§6.6, §19.13). */
    fun removeMember(channelId: ByteArray, member: ByteArray): Result = pass(channelId, member)

    /** §19.13 item 3: a committer of rank ≥ 1 drops its own key from `committers` and `funders` (not the last committer). */
    fun resign(channelId: ByteArray): Result = pass(channelId, null, resign = true)

    /** §19.13 item 3: rank 0 reorders `committers` so [newRank0] leads (a transfer of rank 0, then a leave). */
    fun transfer(channelId: ByteArray, newRank0: ByteArray): Result = pass(channelId, null, transferTo = newRank0)

    private class Admission(
        val request: JoinStore.RequestRow,
        val verified: ChannelCrypto.JoinVerified,
        val evidence: AdmitEvidence,
        val kpDay: Long,
        val sponsor: ByteArray,
        val tag: ByteArray,
    )

    /** A rejoin or restore the pass admits: the swap's evidence and what the settle records about it. */
    private class SwapAdmission(
        val request: JoinStore.RequestRow,
        val verified: ChannelCrypto.JoinVerified,
        val evidence: org.ghost.crypto.bridge.SwapEvidence,
        val kpDay: Long,
        /** The pseudonym whose leaf the swap replaces (a current member, §6.7). */
        val member: ByteArray,
        val tag: ByteArray,
    )

    /** A request the pass refuses: deleted, and its KeyPackage's tag kept until [untilDay] when the KeyPackage was read. */
    private class Refusal(val request: JoinStore.RequestRow, val tag: ByteArray?, val untilDay: Long) {
        override fun toString(): String = "Refusal(redacted)"
    }

    private fun pass(channelId: ByteArray, removeTarget: ByteArray?, resign: Boolean = false, transferTo: ByteArray? = null): Result {
        val now = env.now()
        val day = DmTime.day(now)
        val content = env.keys.content() ?: return Result.UNAVAILABLE
        val seenKey = env.keys.seenKey() ?: return Result.UNAVAILABLE
        try {
            return passWith(channelId, content, seenKey, now, day, removeTarget, resign, transferTo)
        } finally {
            seenKey.fill(0)
        }
    }

    private fun passWith(
        channelId: ByteArray,
        content: org.ghost.messaging.store.ContentCipher,
        seenKey: ByteArray,
        now: Long,
        day: Long,
        removeTarget: ByteArray?,
        resign: Boolean,
        transferTo: ByteArray?,
    ): Result {
        val opened = env.contexts.open(channelId) ?: return Result.UNAVAILABLE
        val p = opened.pseudonym
        val snapshot = env.database.transaction { tx ->
            val channel = stores.channels.channel(tx.sql, channelId) ?: return@transaction null
            if (!postStep.isCurrent(tx.sql, channel, now)) return@transaction null
            val epoch = stores.epochs.open(tx.sql, channelId, day) ?: return@transaction null
            if (epoch.epoch != channel.epoch) return@transaction null
            val generation = stores.generations.current(tx.sql, channelId, day) ?: return@transaction null
            val candidates = stores.candidates.candidates(tx.sql, channelId, epoch.epoch)
            Snapshot(
                channel, epoch, generation, candidates,
                stores.joins.requests(tx.sql, channelId, day),
                stores.members.requests(tx.sql, channelId, day),
                stores.channels.schedule(tx.sql, channelId),
                stores.mls.rows(tx.sql, channelId, day),
            )
        } ?: return Result.NOTHING
        // CO-7 (D-1): never pass over any valid candidate of the current epoch, whatever its rank — the pass
        // waits for the settle point (a rank-255 candidate delays, it never blocks; §19.5). The engine's pass
        // runs the settles first, so after one this pass works in e + 1 in the same actor step.
        if (snapshot.candidates.isNotEmpty()) return Result.NOTHING
        val rows = MlsRows.of(snapshot.rows)
        val roster = opened.crypto.roster(channelId, rows, day.toInt()).valueOrNull() ?: return Result.UNAVAILABLE
        // CO-1: the rank in the pre-commit context; `indexOfFirst` answers -1 for a non-committer, CO-1's 255.
        val rank = roster.context.committers.indexOfFirst { it.contentEquals(p) }.let { if (it < 0) NOT_A_COMMITTER else it }
        if (removeTarget != null && rank == NOT_A_COMMITTER) return Result.NOTHING // CO-1: only a committer Removes
        val members = roster.members.map { it.pseudonym.toList() }.toSet()
        // CO-2 (A)'s sponsor rule, applied before the native call refuses it (§19.38): a committer, or any member
        // where members may invite and the channel has no password (Q46 (b)).
        val committerSet = roster.context.committers.map { it.toList() }.toSet()
        val passwordChannel = roster.context.flags and ChannelEnv.FLAG_PASSWORD != 0
        val membersMayInvite = roster.context.flags and ChannelEnv.FLAG_MEMBERS_MAY_INVITE != 0 && !passwordChannel
        // The digest of the committer's current committers (S0-15): kept, or — forgotten by a settle that changed
        // the committers, or never learnt — taken from `roster`'s output and persisted; a password channel learns
        // it too (§19.37 F-S4-2, closed in S5a).
        val digest = snapshot.channel.committersDigest ?: ChannelDigest.learn(opened.crypto, channelId, rows, day)?.also { d ->
            env.database.transaction { tx -> stores.channels.setCommittersDigest(tx, channelId, d) }
        }

        if (rank == NOT_A_COMMITTER) {
            // CO-9: the self-update is the only commit a rank-255 member makes.
            return selfUpdate(opened, content, snapshot, rows, roster.ownRefreshEpoch(p), seenKey, now, day, roster.members.size)
        }

        // ---- the committer's pass: admissions, the user-action Remove, or the PCS commit.
        val agedRequests = if (rank == 0) {
            snapshot.requests
        } else {
            // The work-age rule (§19.13 item 4): only work first recorded at least r × 48 h earlier.
            snapshot.requests.filter { it.recordedDay + 2L * rank <= day }
        }
        val refused = ArrayList<Refusal>()
        val admissions = ArrayList<Admission>()
        val swaps = ArrayList<SwapAdmission>()
        /** One swap admission per pseudonym: a re-sent rejoin (two namespaces, a re-send) presents the
         *  newest request only — the older copies are refused like any other refused request. */
        val swapByMember = HashMap<List<Byte>, SwapAdmission>()
        val invitesUsed = HashSet<List<Byte>>()
        val cap = ChannelTime.cap(snapshot.channel.sizeClass)
        for (request in agedRequests) {
            if (admissions.size + swaps.size >= MAX_ADDS) break
            try {
                when (request.type) {
                    JoinType.JOIN -> admitJoin(
                        request, opened, content, members, committerSet, membersMayInvite, digest,
                        passwordChannel, roster, day, seenKey, refused, admissions, invitesUsed, cap,
                    )
                    JoinType.RESTORE -> admitRestore(
                        request, opened, content, members, committerSet, membersMayInvite, digest,
                        passwordChannel, roster.context.pwVersion, day, seenKey, refused, swaps, swapByMember, invitesUsed,
                    )
                    JoinType.REJOIN -> admitRejoin(
                        request, opened, content, members, snapshot.epoch.epoch, snapshot.channel.timerCode,
                        day, seenKey, refused, swaps, swapByMember,
                    )
                }
            } catch (e: CryptoUnavailable) {
                return Result.UNAVAILABLE
            }
        }

        if (removeTarget != null && removeTarget.toList() !in members) return writeRefusals(channelId, refused)        // ---- §6.6's membership work: leave requests and idle evictions (a committer's pass, any rank).
        // A leave is recorded work: the work-age rule ages it like a join request. An eviction is a scan,
        // like the PCS cadence, lower-rank-only: CO-2's rank rule and the owner — whom no rank sits below —
        // are never evicted (declared L8-C16).
        val memberRank = { who: ByteArray ->
            roster.context.committers.indexOfFirst { it.contentEquals(who) }.let { if (it < 0) NOT_A_COMMITTER else it }
        }
        val leaves = snapshot.memberRequests
            .filter { it.kind == org.ghost.messaging.channel.store.RequestKind.LEAVE }
            .filter { rank == 0 || it.recordedDay + 2L * rank <= day }
            .map { it.subject }
            .filter { it.toList() in members && !it.contentEquals(p) }
        val evictions = if (rank != NOT_A_COMMITTER) {
            // The LIMIT applies in SQL, before the roster and rank filters — a removed member's refresh
            // row survives on the committer's device until the settle that removed it deletes it (and one
            // written before this fix ships survives indefinitely), so a round of stale rows must not
            // crowd out the real idler: the candidate set is walked in rounds and the bound applies after
            // the filters (the review of S6, §19.42).
            val picked = ArrayList<ByteArray>()
            var offset = 0
            while (picked.size < MAX_EVICTIONS) {
                val round = env.database.transaction { tx ->
                    stores.members.idleBefore(tx.sql, channelId, day - roster.context.idleEvictDays, MAX_EVICTIONS, offset)
                }
                for (candidate in round) {
                    if (picked.size >= MAX_EVICTIONS) break
                    if (candidate.toList() in members && !candidate.contentEquals(p) && memberRank(candidate) > rank &&
                        picked.none { it.contentEquals(candidate) }
                    ) {
                        picked += candidate
                    }
                }
                if (round.size < MAX_EVICTIONS) break
                offset += MAX_EVICTIONS
            }
            picked
        } else {
            emptyList()
        }

        // The user-action context changes of §19.13 item 3: a resignation (rank ≥ 1, not the last
        // committer — rank 0 refuses, it transfers first, §6.6) and a transfer of rank 0.
        var context: ChannelPolicy? = null
        if (resign) {
            if (rank == NOT_A_COMMITTER || rank == 0 || roster.context.committers.size <= 1) return Result.NOTHING
            context = removeContext(roster.context, listOf(p))
        }
        if (transferTo != null) {
            if (rank != 0 || transferTo.toList() !in committerSet) return Result.NOTHING
            context = ChannelPolicy(
                channelId = roster.context.channelId,
                sizeClass = roster.context.sizeClass,
                timerCode = roster.context.timerCode,
                timerVersion = roster.context.timerVersion,
                historyPolicy = roster.context.historyPolicy,
                flags = roster.context.flags,
                idleEvictDays = roster.context.idleEvictDays,
                pwVersion = roster.context.pwVersion,
                name = roster.context.name,
                committers = listOf(transferTo) + roster.context.committers.filterNot { it.contentEquals(transferTo) },
                funders = roster.context.funders,
            )
        }

        // One commit for the pass's work, when there is work: the admissions it admitted, the members a
        // leave or an eviction removes (§6.6), and — at a user action — the Remove (an immediate pass;
        // the committers/funders update rides along when a removed member is a committer or a funder) or
        // the context change of a resignation or a transfer. With no work the pass builds nothing here;
        // the PCS commit below is a cadence decision, not a default.
        val removeWork = buildList {
            removeTarget?.let { add(it) }
            addAll(leaves)
            addAll(evictions)
        }.distinctBy { it.toList() }.filter { it.toList() in members }
        val hasWork = admissions.isNotEmpty() || swaps.isNotEmpty() || removeWork.isNotEmpty() || context != null
        val built = if (hasWork) {
            buildCommit(
                opened, snapshot, rows, admissions, swaps, refused, now, day,
                removes = removeWork,
                context = context ?: if (removeWork.isNotEmpty()) removeContext(roster.context, removeWork) else null,
            )
        } else {
            null
        }
        if (built != null) {
            return writeCommit(channelId, opened, content, snapshot, built, refused, now, day, rank, selfUpdate = false, seenKey)
        }
        if (refused.isNotEmpty()) return writeRefusals(channelId, refused)
        // No admissions, a refused Remove, or nothing: the PCS commit (§6.8), only on the cadence.
        val lastOwn = snapshot.schedule?.lastOwnCommitDay
        val pcsDue = lastOwn != null && day - lastOwn >= ChannelTime.pcsDays(snapshot.channel.timerCode)
        if (!pcsDue || removeTarget != null || resign || transferTo != null) return Result.NOTHING
        val empty = buildCommit(opened, snapshot, rows, ArrayList(), ArrayList(), ArrayList(), now, day, emptyList(), null)
            ?: return Result.NOTHING
        return writeCommit(channelId, opened, content, snapshot, empty, emptyList(), now, day, rank, selfUpdate = false, seenKey)
    }

    /** A native call found the context or the content key gone: the pass answers [Result.UNAVAILABLE]. */
    private class CryptoUnavailable : Exception()

    /** §6.2.4 (B), unchanged from S4: the join admission of one request. */
    private fun admitJoin(
        request: JoinStore.RequestRow,
        opened: ChannelContexts.Opened,
        content: org.ghost.messaging.store.ContentCipher,
        members: Set<List<Byte>>,
        committerSet: Set<List<Byte>>,
        membersMayInvite: Boolean,
        digest: ByteArray?,
        passwordChannel: Boolean,
        roster: org.ghost.crypto.bridge.ChannelCrypto.Roster,
        day: Long,
        seenKey: ByteArray,
        refused: MutableList<Refusal>,
        admissions: MutableList<Admission>,
        invitesUsed: MutableSet<List<Byte>>,
        cap: Int,
    ) {
        val channelId = request.channelId
        val inviteId = request.inviteId ?: run {
            refused += Refusal(request, null, 0)
            return
        }
        val body = content.open(request.bodyEnv, ChannelAd.joinRequest(channelId, request.hash))
        if (body == null) {
            refused += Refusal(request, null, 0)
            return
        }
        val invite = env.database.transaction { tx -> stores.invites.issued(tx.sql, channelId, inviteId, day) }
        if (invite == null || invite.consumed || invite.void) {
            refused += Refusal(request, null, 0)
            return
        }
        val verified = when (val v = opened.crypto.joinVerify(channelId, body, invite.invitePk, null, request.generation.toInt())) {
            is MlsOutcome.Ok -> v.value
            is MlsOutcome.Refused -> {
                if (v.code == MlsCode.CRYPTO_UNAVAILABLE) throw CryptoUnavailable()
                refused += Refusal(request, null, 0)
                return
            }
        }
        val tag = ChannelTags.keyPackageTag(seenKey, channelId, verified.kpRef)
        val kpDay = verified.kpBind.u32(MlsField.DAY)
        val seen = env.database.transaction { tx -> stores.joins.isKpSeen(tx.sql, channelId, tag, day) }
        val ok = !seen &&
            verified.requestType == ChannelReceiveStep.REQUEST_JOIN &&
            kpDay in (day - KP_DAYS_BEFORE)..(day + KP_DAYS_AFTER) &&
            invite.sponsor.toList() in members &&
            (invite.sponsor.toList() in committerSet || membersMayInvite) &&
            digest != null && digest.contentEquals(invite.committersDigest) &&
            (!passwordChannel || invite.pwVersion == roster.context.pwVersion) &&
            verified.pseudonym.toList() !in members &&
            invitesUsed.add(inviteId.toList()) &&
            members.size + admissions.size + 1 <= cap
        if (!ok) {
            refused += Refusal(request, tag, kpDay + KP_SEEN_DAYS)
            return
        }
        admissions += Admission(
            request = request,
            verified = verified,
            evidence = AdmitEvidence(
                kpRef = verified.kpRef,
                inviteId = inviteId,
                invitePk = invite.invitePk,
                expiryDay = invite.expiryDay,
                sponsor = invite.sponsor,
                sponsorSig = invite.sponsorSig,
                inviteSig = verified.auth.bytes(MlsField.INVITE_SIG),
            ),
            kpDay = kpDay,
            sponsor = invite.sponsor,
            tag = tag,
        )
    }

    /**
     * §6.12's restore admission: the invite-authorized swap of a current member's leaf. Like the join
     * admission (the invite is held, unexpired, unconsumed, unvoid; the sponsor may invite; the digest
     * matches; the KeyPackage is canonical and in its day window; the tag is new; the password version
     * matches) except that the pseudonym **is** a current member — a swap replaces the leaf, the member
     * count does not move, and the evidence is a restore swap. No freshness rule applies: the invite
     * authorizes the swap (§6.7).
     */
    private fun admitRestore(
        request: JoinStore.RequestRow,
        opened: ChannelContexts.Opened,
        content: org.ghost.messaging.store.ContentCipher,
        members: Set<List<Byte>>,
        committerSet: Set<List<Byte>>,
        membersMayInvite: Boolean,
        digest: ByteArray?,
        passwordChannel: Boolean,
        pwVersion: Int,
        day: Long,
        seenKey: ByteArray,
        refused: MutableList<Refusal>,
        swaps: MutableList<SwapAdmission>,
        swapByMember: MutableMap<List<Byte>, SwapAdmission>,
        invitesUsed: MutableSet<List<Byte>>,
    ) {
        val channelId = request.channelId
        val inviteId = request.inviteId ?: run {
            refused += Refusal(request, null, 0)
            return
        }
        val body = content.open(request.bodyEnv, ChannelAd.joinRequest(channelId, request.hash))
        if (body == null) {
            refused += Refusal(request, null, 0)
            return
        }
        val invite = env.database.transaction { tx -> stores.invites.issued(tx.sql, channelId, inviteId, day) }
        if (invite == null || invite.consumed || invite.void) {
            refused += Refusal(request, null, 0)
            return
        }
        val verified = when (val v = opened.crypto.joinVerify(channelId, body, invite.invitePk, null, request.generation.toInt())) {
            is MlsOutcome.Ok -> v.value
            is MlsOutcome.Refused -> {
                if (v.code == MlsCode.CRYPTO_UNAVAILABLE) throw CryptoUnavailable()
                refused += Refusal(request, null, 0)
                return
            }
        }
        val tag = ChannelTags.keyPackageTag(seenKey, channelId, verified.kpRef)
        val kpDay = verified.kpBind.u32(MlsField.DAY)
        val seen = env.database.transaction { tx -> stores.joins.isKpSeen(tx.sql, channelId, tag, day) }
        val ok = !seen &&
            verified.requestType == ChannelReceiveStep.REQUEST_RESTORE &&
            kpDay in (day - KP_DAYS_BEFORE)..(day + KP_DAYS_AFTER) &&
            invite.sponsor.toList() in members &&
            (invite.sponsor.toList() in committerSet || membersMayInvite) &&
            digest != null && digest.contentEquals(invite.committersDigest) &&
            (!passwordChannel || invite.pwVersion == pwVersion) &&
            verified.pseudonym.toList() in members &&
            invitesUsed.add(inviteId.toList())
        if (!ok) {
            refused += Refusal(request, tag, kpDay + KP_SEEN_DAYS)
            return
        }
        addSwap(
            SwapAdmission(
                request = request,
                verified = verified,
                evidence = org.ghost.crypto.bridge.SwapEvidence.Restore(
                    AdmitEvidence(
                        kpRef = verified.kpRef,
                        inviteId = inviteId,
                        invitePk = invite.invitePk,
                        expiryDay = invite.expiryDay,
                        sponsor = invite.sponsor,
                        sponsorSig = invite.sponsorSig,
                        inviteSig = verified.auth.bytes(MlsField.INVITE_SIG),
                    ),
                ),
                kpDay = kpDay,
                member = verified.pseudonym,
                tag = tag,
            ),
            swaps, swapByMember, refused, day,
        )
    }

    /**
     * §6.7's rejoin admission, the policy read from the committer's branch and clock: the pseudonym is a
     * current member; `rejoin_sig` verifies under that leaf's signature key (every leaf keeps its
     * member's key, §19.14) over (channel_id, the request's generation, the signed day, the claimed last
     * final epoch and its winner hash, the KeyPackage's hash); the day is in `[day − 7, day + 3]`; the
     * KeyPackage's tag is new and its `GhostKpBind` names this channel with purpose rejoin (the native
     * `joinVerify`); the claimed point cannot be caught up from — `last_epoch` is below the committer's
     * current epoch and either the epoch log holds a different winner for it (a fork) or its winner was
     * finalized more than one handshake TTL ago or is older than the log (D-6) —; and no authenticated
     * message from the member's current leaf opened on this branch in an epoch after `last_epoch`
     * (`ch_member_seen`: a live leaf is never replaced).
     */
    private fun admitRejoin(
        request: JoinStore.RequestRow,
        opened: ChannelContexts.Opened,
        content: org.ghost.messaging.store.ContentCipher,
        members: Set<List<Byte>>,
        currentEpoch: Long,
        timerCode: Int,
        day: Long,
        seenKey: ByteArray,
        refused: MutableList<Refusal>,
        swaps: MutableList<SwapAdmission>,
        swapByMember: MutableMap<List<Byte>, SwapAdmission>,
    ) {
        val channelId = request.channelId
        val member = request.member ?: run {
            refused += Refusal(request, null, 0)
            return
        }
        if (member.toList() !in members) {
            refused += Refusal(request, null, 0)
            return
        }
        val body = content.open(request.bodyEnv, ChannelAd.joinRequest(channelId, request.hash))
        if (body == null) {
            refused += Refusal(request, null, 0)
            return
        }
        // The signature is bound to the generation of the namespace the request was recorded from.
        val verified = when (
            val v = opened.crypto.joinVerify(channelId, body, null, member, request.generation.toInt())
        ) {
            is MlsOutcome.Ok -> v.value
            is MlsOutcome.Refused -> {
                if (v.code == MlsCode.CRYPTO_UNAVAILABLE) throw CryptoUnavailable()
                refused += Refusal(request, null, 0)
                return
            }
        }
        val tag = ChannelTags.keyPackageTag(seenKey, channelId, verified.kpRef)
        val signedDay = verified.auth.u32(MlsField.DAY).toLong()
        val lastEpoch = verified.auth.i64(MlsField.LAST_EPOCH)
        val lastHash = verified.auth.bytes(MlsField.LAST_HASH)
        val rejoinSig = verified.auth.bytes(MlsField.REJOIN_SIG)
        val kpDay = verified.kpBind.u32(MlsField.DAY)
        val seen = env.database.transaction { tx -> stores.joins.isKpSeen(tx.sql, channelId, tag, day) }
        if (seen || verified.requestType != ChannelReceiveStep.REQUEST_REJOIN ||
            signedDay !in (day - KP_DAYS_BEFORE)..(day + KP_DAYS_AFTER)
        ) {
            refused += Refusal(request, tag, kpDay + KP_SEEN_DAYS)
            return
        }
        // The freshness of the claimed point (§6.7, D-6): a fork on this branch, or a winner settled
        // beyond one handshake TTL (the requester cannot catch up in-band), or older than the log.
        val logged = env.database.transaction { tx -> stores.epochs.logged(tx.sql, channelId, lastEpoch) }
        val fork = logged != null && !logged.winnerHash.contentEquals(lastHash)
        val ttlDays = ChannelTime.handshakeTtl(timerCode).seconds / DmTime.DAY
        val beyondTtl = logged == null || day - logged.finalDay > ttlDays
        if (lastEpoch >= currentEpoch || (!fork && !beyondTtl)) {
            refused += Refusal(request, tag, kpDay + KP_SEEN_DAYS)
            return
        }
        // The live-leaf check: no authenticated message from the member's current leaf in an epoch
        // after the claimed one (§6.7; recorded by `CH-RECV`).
        val leafEpoch = env.database.transaction { tx -> stores.members.lastEpoch(tx.sql, channelId, member) }
        if (leafEpoch != null && leafEpoch > lastEpoch) {
            refused += Refusal(request, tag, kpDay + KP_SEEN_DAYS)
            return
        }
        addSwap(
            SwapAdmission(
                request = request,
                verified = verified,
                evidence = org.ghost.crypto.bridge.SwapEvidence.Rejoin(
                    kpRef = verified.kpRef,
                    generation = request.generation,
                    day = signedDay,
                    lastEpoch = lastEpoch,
                    lastHash = lastHash,
                    rejoinSig = rejoinSig,
                ),
                kpDay = kpDay,
                member = member,
                tag = tag,
            ),
            swaps, swapByMember, refused, day,
        )
    }

    /**
     * Keeps one swap admission per pseudonym (the newest request wins; the older copies are refused
     * and their tags kept, exactly the shape of any other refusal).
     */
    private fun addSwap(
        candidate: SwapAdmission,
        swaps: MutableList<SwapAdmission>,
        swapByMember: MutableMap<List<Byte>, SwapAdmission>,
        refused: MutableList<Refusal>,
        day: Long,
    ) {
        val key = candidate.member.toList()
        val held = swapByMember[key]
        if (held == null) {
            swapByMember[key] = candidate
            swaps += candidate
            return
        }
        val (keep, drop) = if (candidate.request.recordedDay >= held.request.recordedDay) {
            candidate to held
        } else {
            held to candidate
        }
        swapByMember[key] = keep
        swaps.remove(held)
        swaps += keep
        refused += Refusal(drop.request, drop.tag, drop.kpDay + KP_SEEN_DAYS)
    }

    /** CO-9: the rank-255 member's self-update at its slot — or the skip/NOTHING the rule dictates. */
    private fun selfUpdate(
        opened: ChannelContexts.Opened,
        content: org.ghost.messaging.store.ContentCipher,
        snapshot: Snapshot,
        rows: List<org.ghost.crypto.bridge.MlsRow>,
        ownRefreshEpoch: Long,
        seenKey: ByteArray,
        now: Long,
        day: Long,
        memberCount: Int,
    ): Result {
        val schedule = snapshot.schedule ?: return Result.NOTHING
        if (day < schedule.nextSelfupdateDay) return Result.NOTHING
        // CO-14 at the pass: refuse a rank-255 commit whose sender leaf has refresh_epoch > e − k — the same
        // rule the native side applies to foreign commits, checked against the member's own would-be commit.
        // A skip consumes the slot (the next period's is scheduled), it does not retry.
        if (co14WouldRefuse(ownRefreshEpoch, snapshot.epoch.epoch, memberCount)) {
            env.database.transaction { tx ->
                stores.channels.putSchedule(
                    tx, snapshot.channel.channelId,
                    ChannelSchedule.nextSlotDay(snapshot.channel.channelId, day, seenKey), schedule.lastOwnCommitDay, schedule.nextPassMinute,
                )
            }
            return Result.NOTHING
        }
        val built = buildCommit(opened, snapshot, rows, ArrayList(), ArrayList(), ArrayList(), now, day, emptyList(), null)
            ?: return Result.NOTHING
        return writeCommit(snapshot.channel.channelId, opened, content, snapshot, built, emptyList(), now, day, NOT_A_COMMITTER, selfUpdate = true, seenKey)
    }

    /** CO-14: `refresh_epoch > e − k`, `k = min(8, n)` — true when the rule would refuse the commit. */
    private fun co14WouldRefuse(refreshEpoch: Long, epoch: Long, memberCount: Int): Boolean {
        val k = minOf(CO14_K_MAX, memberCount)
        return refreshEpoch > epoch - k
    }

    /** The context change that drops [removed] from `committers` and `funders`, or null when it names neither. */
    private fun removeContext(context: ChannelPolicy, removed: List<ByteArray>): ChannelPolicy? {
        val inCommitters = context.committers.any { c -> removed.any { r -> r.contentEquals(c) } }
        val inFunders = context.funders.any { c -> removed.any { r -> r.contentEquals(c) } }
        if (!inCommitters && !inFunders) return null
        return ChannelPolicy(
            channelId = context.channelId,
            sizeClass = context.sizeClass,
            timerCode = context.timerCode,
            timerVersion = context.timerVersion,
            historyPolicy = context.historyPolicy,
            flags = context.flags,
            idleEvictDays = context.idleEvictDays,
            pwVersion = context.pwVersion,
            name = context.name,
            committers = if (inCommitters) context.committers.filterNot { c -> removed.any { r -> r.contentEquals(c) } } else context.committers,
            funders = if (inFunders) context.funders.filterNot { c -> removed.any { r -> r.contentEquals(c) } } else context.funders,
        )
    }

    /** What the pass read in its first transaction. */
    private class Snapshot(
        val channel: org.ghost.messaging.channel.store.ChannelStore.ChannelRow,
        val epoch: org.ghost.messaging.channel.store.EpochStore.EpochRow,
        val generation: org.ghost.messaging.channel.store.GenerationStore.GenerationRow,
        val candidates: List<org.ghost.messaging.channel.store.CandidateStore.CandidateRow>,
        val requests: List<JoinStore.RequestRow>,
        val memberRequests: List<org.ghost.messaging.channel.store.MemberStore.RequestRow>,
        val schedule: org.ghost.messaging.channel.store.ChannelStore.ScheduleRow?,
        val rows: List<org.ghost.messaging.channel.store.MlsKvStore.KvRow>,
    )

    /** A commit built and sealed, with its Welcomes sealed and framed. */
    private class Built(
        val committed: ChannelCrypto.Committed,
        val blob: ByteArray,
        val welcomes: List<ChannelWelcomes.Entry>,
    )

    /**
     * `commit` with the admissions, the swaps, the Removes and the context change; a KeyPackage or
     * evidence the native side refuses by index is refused here and the commit is built again without
     * it. An admission whose generation's drain has ended is refused at selection, before the native
     * call (the review of S6, §19.42). Null when a build is refused outright (a Remove the native CO-2
     * rank rule refuses, a floor that fits nothing) or no admission, swap or membership work remains.
     */
    private fun buildCommit(
        opened: ChannelContexts.Opened,
        snapshot: Snapshot,
        rows: List<org.ghost.crypto.bridge.MlsRow>,
        admissions: MutableList<Admission>,
        swaps: MutableList<SwapAdmission>,
        refused: MutableList<Refusal>,
        now: Long,
        day: Long,
        removes: List<ByteArray>,
        context: ChannelPolicy?,
    ): Built? {
        val c = snapshot.channel.channelId
        val floor = ChannelTime.floor(snapshot.channel.sizeClass)
        // The review of S6 (§19.42): a request recorded against a generation whose drain has ended —
        // the request outlived the generation it was fetched from — must not null the whole commit
        // (the evictions, the leave removals and a user Remove riding along would all be skipped, an
        // empty PCS commit could go out instead, and the request would be re-selected and re-drop the
        // pass until its expiry). The admission is refused at selection — deleted, its KeyPackage's tag
        // kept, counted, exactly the shape of a KeyPackage the native side refuses below — and the pass
        // continues with the remaining work.
        val generationRows = HashMap<Long, org.ghost.messaging.channel.store.GenerationStore.GenerationRow>()
        fun generationOf(request: JoinStore.RequestRow): org.ghost.messaging.channel.store.GenerationStore.GenerationRow? {
            return generationRows.getOrPut(request.generation) {
                env.database.transaction { tx -> stores.generations.generation(tx.sql, c, request.generation, day) }
                    ?: return null
            }
        }
        if (admissions.isNotEmpty() || swaps.isNotEmpty()) {
            val selectedAdmissions = admissions.iterator()
            while (selectedAdmissions.hasNext()) {
                val a = selectedAdmissions.next()
                if (generationOf(a.request) == null) {
                    selectedAdmissions.remove()
                    refused += Refusal(a.request, a.tag, a.kpDay + KP_SEEN_DAYS)
                }
            }
            val selectedSwaps = swaps.iterator()
            while (selectedSwaps.hasNext()) {
                val s = selectedSwaps.next()
                if (generationOf(s.request) == null) {
                    selectedSwaps.remove()
                    refused += Refusal(s.request, s.tag, s.kpDay + KP_SEEN_DAYS)
                }
            }
            // Every admission and swap refused and no membership work: nothing to build (the refusals are written).
            if (admissions.isEmpty() && swaps.isEmpty() && removes.isEmpty() && context == null) return null
        }
        while (true) {
            val request = CommitRequest(
                adds = admissions.map { it.verified.keyPackage to it.evidence },
                removes = removes,
                swaps = swaps.map { Triple(it.member, it.verified.keyPackage, it.evidence) },
                context = context,
                commitMinute = Math.floorDiv(now, DmTime.MINUTE),
                floor = floor.toLong(),
                generation = snapshot.generation.generation,
                openEpoch = snapshot.generation.openEpoch,
                gEnv = snapshot.generation.gEnv,
            )
            val committed = when (val r = opened.crypto.commit(c, rows, request, day.toInt())) {
                is MlsOutcome.Ok -> r.value
                is MlsOutcome.Refused -> {
                    val index = r.refusal.index
                    // The refusal's index names the requested work: Adds first, then the swaps (the
                    // native side's numbering), then the Removes and the context (never indexed).
                    if ((r.code == MlsCode.INVALID_KEYPACKAGE || r.code == MlsCode.INVALID_EVIDENCE) && index != null) {
                        if (index in admissions.indices) {
                            val gone = admissions.removeAt(index)
                            refused += Refusal(gone.request, gone.tag, gone.kpDay + KP_SEEN_DAYS)
                        } else if (index - admissions.size in swaps.indices) {
                            val gone = swaps.removeAt(index - admissions.size)
                            refused += Refusal(gone.request, gone.tag, gone.kpDay + KP_SEEN_DAYS)
                        } else {
                            return null
                        }
                        if (admissions.isEmpty() && swaps.isEmpty()) return null
                        continue
                    }
                    return null
                }
            }
            val sealed = opened.crypto.seal(
                c, snapshot.epoch.kEnv, ChannelCrypto.KEY_CLASS_EPOCH, snapshot.generation.namespaceId, floor,
                ChannelCrypto.MODE_EPOCH, ChannelCrypto.SealOrder(snapshot.epoch.epoch, 0, 0), committed.commit,
            ).valueOrNull() ?: return null
            // One WELCOME per joiner and per swapped member, sealed in mode 0x13 under the `JK_g` of
            // the namespace its request came from and kept wrapped in the own candidate row.
            val entries = ArrayList<ChannelWelcomes.Entry>()
            for ((i, kpRef) in committed.joiners.withIndex()) {
                val admission = admissions.firstOrNull { it.verified.kpRef.contentEquals(kpRef) }
                val swap = swaps.firstOrNull { it.verified.kpRef.contentEquals(kpRef) }
                if (admission == null && swap == null) return null
                val targetRequest = admission?.request ?: swap!!.request
                // Read at selection above (every remaining admission and swap passed it): a generation
                // row cannot vanish between the two — the pass is single-threaded and the selection ran
                // in this pass.
                val generation = generationOf(targetRequest)
                    ?: throw IllegalStateException("an admitted request's generation vanished between selection and the seal")
                val welcome = committed.welcomes[i]
                val bucket = ChannelTime.bucket(welcome.size, snapshot.channel.sizeClass) ?: return null
                val blob = opened.crypto.seal(
                    c, generation.jkEnv, ChannelCrypto.KEY_CLASS_JOIN, generation.namespaceId, bucket,
                    ChannelCrypto.MODE_WELCOME, ChannelCrypto.SealOrder.NONE, welcome,
                ).valueOrNull() ?: return null
                entries += ChannelWelcomes.Entry(
                    ns = generation.namespaceId,
                    kpRef = kpRef,
                    inviteId = admission?.request?.inviteId,
                    member = admission?.verified?.pseudonym ?: swap!!.member,
                    sponsor = admission?.sponsor,
                    requestHash = targetRequest.hash,
                    kpDay = admission?.kpDay ?: swap!!.kpDay,
                    swap = swap != null,
                    blob = blob,
                )
            }
            return Built(committed, sealed, entries)
        }
    }

    private fun writeRefusals(channelId: ByteArray, refused: List<Refusal>): Result {
        if (refused.isEmpty()) return Result.NOTHING
        env.database.transaction { tx -> refuse(tx, channelId, refused) }
        return Result.REFUSED_ONLY
    }

    private fun refuse(tx: org.ghost.sync.api.SyncTransaction, channelId: ByteArray, refused: List<Refusal>) {
        for (r in refused) {
            stores.joins.deleteRequest(tx, channelId, r.request.hash)
            // §6.2.4 (B), §19.29.1: the tag of a KeyPackage refused is kept until `GhostKpBind.day + 11`.
            if (r.tag != null) stores.joins.markKpSeen(tx, channelId, r.tag, r.untilDay)
            env.counters.count(ChannelCounters.Reason.ADMISSION_REFUSED)
        }
    }

    private fun writeCommit(
        channelId: ByteArray,
        opened: ChannelContexts.Opened,
        content: org.ghost.messaging.store.ContentCipher,
        snapshot: Snapshot,
        built: Built,
        refused: List<Refusal>,
        now: Long,
        day: Long,
        rank: Int,
        selfUpdate: Boolean,
        seenKey: ByteArray,
    ): Result {
        val committed = built.committed
        val epoch = snapshot.epoch.epoch
        val hash = committed.summary.hash
        val framed = ChannelWelcomes.encode(committed.boxPk, built.welcomes)
        return try {
            env.database.transaction { tx ->
                val fresh = stores.channels.channel(tx.sql, channelId)
                if (fresh == null || fresh.state != ChannelState.ACTIVE || fresh.epoch != epoch ||
                    stores.candidates.own(tx.sql, channelId, epoch) != null
                ) {
                    return@transaction Result.NOTHING
                }
                stores.mls.apply(tx, channelId, MlsRows.changes(committed.changes))
                val operationId = env.random.bytes(OperationId.SIZE)
                sync.outbox.enqueue(
                    tx,
                    OutboundBlob(
                        OperationId(operationId), NamespaceId(snapshot.generation.namespaceId), built.blob,
                        ChannelTime.handshakeTtl(fresh.timerCode),
                        deadlineEpochSeconds = ChannelTime.handshakeDeadline(DmTime.floorMinute(now)),
                    ),
                )
                stores.posts.insertOp(tx, operationId, channelId, OpPurpose.COMMIT, hash)
                stores.candidates.insert(
                    tx = tx,
                    channelId = channelId,
                    epoch = epoch,
                    hash = hash,
                    sender = opened.pseudonym,
                    rank = rank,
                    own = true,
                    bodyEnv = env.seal(content, ChannelAd.candidate(channelId, epoch, hash), committed.commit),
                    firstSeenMinute = DmTime.floorMinute(now),
                    welcomeEnv = if (built.welcomes.isEmpty()) null else env.seal(content, ChannelAd.welcomes(channelId, epoch, hash), framed),
                    boxEnv = committed.boxEnv,
                    removes = committed.summary.removes.isNotEmpty() || committed.summary.swaps.isNotEmpty(),
                )
                // CO-4 (D-4, S5): the creation pass is the committer's first sighting of its own
                // candidate; the anchor only moves earlier from here — when a stored copy is later
                // evidenced (the op's outcome, or a fetched copy with its store hour).
                val row = stores.epochs.epoch(tx.sql, channelId, epoch, day)
                val sighting = DmTime.floorMinute(now)
                val anchor = row?.anchorMinute?.let { minOf(it, sighting) } ?: sighting
                stores.epochs.setAnchor(tx, channelId, epoch, anchor)
                // The schedule (CO-8, CO-9): any own commit refreshes the leaf (§6.8's force_self_update),
                // so it is the PCS clock's "last commit"; a self-update that got built schedules the next
                // period's slot (a lost one is re-armed to day + 1 by the settle).
                val schedule = stores.channels.schedule(tx.sql, channelId)
                stores.channels.putSchedule(
                    tx, channelId,
                    nextSelfupdateDay = if (selfUpdate) {
                        ChannelSchedule.nextSlotDay(channelId, day, seenKey)
                    } else {
                        schedule?.nextSelfupdateDay ?: ChannelSchedule.slotDay(channelId, ChannelSchedule.period(day), seenKey)
                    },
                    lastOwnCommitDay = day,
                    nextPassMinute = schedule?.nextPassMinute,
                )
                refuse(tx, channelId, refused)
                Result.COMMITTED
            }
        } catch (e: InsufficientReplicasException) {
            // No quorum this week: no commit; the requests stay pending for the next pass.
            Result.NOTHING
        } catch (e: StorageFullException) {
            Result.NOTHING
        } finally {
            framed.fill(0)
        }
    }

    override fun toString(): String = "ChannelPassStep"

    companion object {
        /** CO-8: a scheduled pass at most once per 6 hours. */
        const val PASS_SPACING_SECONDS: Long = 6 * DmTime.HOUR

        /** CO-8: a pass `U[0, 5 min]` after the session's catch-up. */
        const val MAX_JITTER_MINUTES: Long = 5

        /** §6.2.4 (B): `GhostKpBind.day` within `[day − 7, day + 3]` of the committer's trusted day. */
        const val KP_DAYS_BEFORE: Long = 7
        const val KP_DAYS_AFTER: Long = 3

        /** §6.2.4 (B), §19.29.1: a KeyPackage tag is kept until `GhostKpBind.day + 11`. */
        const val KP_SEEN_DAYS: Long = 11

        /** §19.36 row 1: `commit` takes at most 64 Adds and swaps. */
        const val MAX_ADDS: Int = 64

        /** CO-1: the rank of a member that is no committer. */
        const val NOT_A_COMMITTER: Int = 255

        /** CO-14: k = min(8, n). */
        const val CO14_K_MAX: Int = 8

        /** One pass per scheduled channel per run of [runScheduledPasses]: the due list's bound. */
        const val MAX_DUE_PASSES: Int = 9

        /** §6.6: at most this many idle members a pass evicts (one commit carries every Remove). */
        const val MAX_EVICTIONS: Int = 8
    }
}

/** `Roster`'s own leaf `refresh_epoch` (0 when the leaf carries none — a KeyPackage leaf's value). */
private fun org.ghost.crypto.bridge.ChannelCrypto.Roster.ownRefreshEpoch(p: ByteArray): Long =
    members.firstOrNull { it.pseudonym.contentEquals(p) }?.refreshEpoch ?: 0L

/**
 * The plaintext of an own candidate's `welcome_env` (local, under the content key; never on the wire): the new leaf's box
 * public key and, per joiner or swapped member, what `CH-SETTLE` needs to enqueue the sealed WELCOME blob and to record
 * the admission — the namespace, the KeyPackage reference, the invite (null for a rejoin: its swap deletes the request by
 * hash instead of consuming an invite), the member's pseudonym, the sponsor (null for a swap), the request's blob hash,
 * the KeyPackage's day (its `ch_kp_seen` lifetime) and whether the entry is a swap (the settle restarts the member's
 * refresh and member-seen rows and keeps the sponsor record of the original admission).
 *
 * `version(1) = 1 ‖ box_pk(32) ‖ count(u16) ‖ count × (ns(32) ‖ kp_ref(32) ‖ invite_id(16, zeros when none) ‖
 * member(32) ‖ sponsor(32, zeros when none) ‖ request_hash(32) ‖ kp_day(u32) ‖ swap(u8) ‖ len(u32) ‖ blob)`.
 */
internal object ChannelWelcomes {
    class Entry(
        val ns: ByteArray,
        val kpRef: ByteArray,
        /** Null for a rejoin swap: no invite is consumed. */
        val inviteId: ByteArray?,
        val member: ByteArray,
        /** Null for a swap: the sponsor record of the original admission stays. */
        val sponsor: ByteArray?,
        val requestHash: ByteArray,
        val kpDay: Long,
        /** A swap (rejoin or restore): the settle restarts the member's local rows instead of recording a sponsor. */
        val swap: Boolean,
        val blob: ByteArray,
    ) {
        override fun toString(): String = "Welcome(redacted)"
    }

    class Framed(val boxPk: ByteArray, val entries: List<Entry>) {
        override fun toString(): String = "Welcomes(${entries.size})"
    }

    private const val VERSION: Int = 1
    private const val FIXED: Int = 32 + 32 + 16 + 32 + 32 + 32 + 4 + 1 + 4

    fun encode(boxPk: ByteArray, entries: List<Entry>): ByteArray {
        require(boxPk.size == 32 && entries.size <= 0xffff) { "bad welcome framing" }
        val size = 1 + 32 + 2 + entries.sumOf { FIXED + it.blob.size }
        val b = ByteBuffer.allocate(size)
        b.put(VERSION.toByte()).put(boxPk).putShort(entries.size.toShort())
        for (e in entries) {
            require(e.ns.size == 32 && e.kpRef.size == 32 && (e.inviteId == null || e.inviteId.size == 16) &&
                e.member.size == 32 && (e.sponsor == null || e.sponsor.size == 32) && e.requestHash.size == 32
            ) { "bad welcome entry" }
            b.put(e.ns).put(e.kpRef)
                .put(e.inviteId ?: ByteArray(16))
                .put(e.member)
                .put(e.sponsor ?: ByteArray(32))
                .put(e.requestHash)
            b.putInt(e.kpDay.toInt()).put(if (e.swap) 1 else 0).putInt(e.blob.size).put(e.blob)
        }
        return b.array()
    }

    /** The framing, or null for bytes that are not one (a defect: the envelope opened under its own row's AD). */
    fun decode(bytes: ByteArray): Framed? {
        if (bytes.size < 35 || bytes[0].toInt() != VERSION) return null
        val b = ByteBuffer.wrap(bytes)
        b.get()
        val boxPk = ByteArray(32).also { b.get(it) }
        val count = b.short.toInt() and 0xffff
        val out = ArrayList<Entry>(count)
        repeat(count) {
            if (b.remaining() < FIXED) return null
            val ns = ByteArray(32).also { b.get(it) }
            val kpRef = ByteArray(32).also { b.get(it) }
            val inviteId = ByteArray(16).also { b.get(it) }
            val member = ByteArray(32).also { b.get(it) }
            val sponsor = ByteArray(32).also { b.get(it) }
            val requestHash = ByteArray(32).also { b.get(it) }
            val kpDay = b.int.toLong() and 0xffff_ffffL
            val swap = b.get().toInt() == 1
            val len = b.int
            if (len < 0 || len > b.remaining()) return null
            val blob = ByteArray(len).also { b.get(it) }
            out += Entry(
                ns, kpRef,
                inviteId = if (inviteId.any { v -> v.toInt() != 0 }) inviteId else null,
                member,
                sponsor = if (sponsor.any { v -> v.toInt() != 0 }) sponsor else null,
                requestHash, kpDay, swap, blob,
            )
        }
        if (b.hasRemaining()) return null
        return Framed(boxPk, out)
    }
}
