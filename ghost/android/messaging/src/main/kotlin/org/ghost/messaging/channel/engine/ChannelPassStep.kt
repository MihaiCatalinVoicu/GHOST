package org.ghost.messaging.channel.engine

import org.ghost.crypto.bridge.AdmitEvidence
import org.ghost.crypto.bridge.ChannelCrypto
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
 * **`CH-PASS`** for admissions (Phase 10 design §6.2.3, §6.2.4, §6.4 CO-7 and CO-8, §10.4), **one transaction**: a
 * committer's pass over the pending join requests of its channel.
 *
 * **Preconditions (CO-7).** The channel is current ([ChannelPostStep.isCurrent]: active, no removal hold, no generation
 * waiting for its switch), the committer holds no pending commit, and no candidate of a rank at or below its own is held
 * for the current epoch.
 *
 * **The admission policy (§6.2.4 (B)),** applied by the admitting committer only, to each request in arrival order: the
 * committer holds the `INVITE_ISSUED` (an unexpired `ch_invite_issued` row on its trusted day), the invite is neither
 * consumed nor void, its sponsor is a current member who may invite (CO-2 (A)'s own rule, checked before the native call
 * refuses it, §19.38), its `committers_digest` equals the digest of the committer's
 * current committers (`ch_channel.committers_digest`; **unknown means no admission**, fail closed — finding F-S4-2 of
 * §19.37, closed in S5a: `roster` returns the digest, so the engine learns it from the roster, not a throwaway
 * `inviteBuild` its password channel could never call), the KeyPackage is canonical with `GhostKpBind.day` in `[day − 7, day + 3]` (`joinVerify` checks the form, purpose,
 * binding and both signatures natively; the window is checked here), its keyed tag was never seen in the channel
 * (`ch_kp_seen`, over `kp_ref` alone — F-S4-4: the init key is not exposed), in a password channel the invite's
 * `pw_version` equals the context's, the pseudonym is not a current member, no two Adds share an invite, and the member
 * count after the commit stays within the class cap. A refused request is deleted and its KeyPackage's tag recorded; a
 * restore-purpose request is the restore's (slice S7) and is left pending.
 *
 * **The commit** (`commit`, §10.2 fn 9) carries the valid Adds by value with their evidence in its `GhostCommitAad`
 * (§19.2), the class floor, and the current generation's bootstrap (`(g, E_g, G_g)`, §5.4); the native side defers the
 * Adds that do not fit the floor (§5.7) and refuses a KeyPackage or evidence it does not accept by index, which this step
 * refuses and retries without. The commit is sealed in mode 0x11 under `K_ep(e)` into the current namespace and
 * **enqueued**; one WELCOME blob per joiner is sealed in mode 0x13 under the `JK_g` of the namespace its request came
 * from and **kept wrapped in the committer's own candidate row** (`welcome_env`, with what `CH-SETTLE` needs to enqueue
 * it and to record the admission), never enqueued here (§19.2: Welcomes only after a won commit).
 *
 * **Scheduling (CO-8, the part this slice serves).** Rank 0 runs a pass when join work is pending, at the first
 * time-triggered pass at least `U[0, 5 min]` after a relay session start, at most once per 6 hours ([scheduleAtSessionStart], [runScheduledPasses]);
 * the schedule is in memory (a restart schedules again at the next session start), so `ch_schedule` stays CO-9's (S5).
 * A committer of rank ≥ 1 does not admit in this slice: CO-8's work-age rule needs the day a request was first recorded,
 * which §9 has no column for (§19.35 F-11 (a), S5's).
 *
 * Gate G-M5 lists this file for `Outbox.enqueue`.
 */
internal class ChannelPassStep(
    private val env: ChannelEnv,
    private val sync: ChannelSyncPorts,
    private val postStep: ChannelPostStep,
) {
    private val stores = env.stores

    /** Channel → the second its next scheduled pass is due (CO-8; in memory, T33). */
    private val nextPass = HashMap<List<Byte>, Long>()

    /** Channel → the second its last pass ran (the 6-hour spacing of CO-8). */
    private val lastPass = HashMap<List<Byte>, Long>()

    /** What [admit] did. */
    enum class Result {
        /** A commit was built, its op enqueued and the own candidate recorded. */
        COMMITTED,

        /** Requests were refused and deleted; no commit (nothing valid remained). */
        REFUSED_ONLY,

        /** Nothing to do, or a precondition of CO-7 does not hold. */
        NOTHING,

        /** The context or the content key is not available. */
        UNAVAILABLE,
    }

    /**
     * A relay session start (CO-8): every channel this client commits for at rank 0, with join work pending and no pass
     * in the last 6 hours, is scheduled `U[0, 5 min]` later.
     */
    fun scheduleAtSessionStart() {
        val now = env.now()
        val day = DmTime.day(now)
        val channels = env.database.transaction { tx -> stores.channels.channelsIn(tx.sql, ChannelState.ACTIVE) }
        for (channel in channels) {
            val key = channel.channelId.toList()
            if (nextPass.containsKey(key)) continue
            val last = lastPass[key]
            if (last != null && now - last < PASS_SPACING_SECONDS) continue
            val pending = env.database.transaction { tx -> stores.joins.requests(tx.sql, channel.channelId, day) }
            if (pending.isEmpty()) continue
            val jitter = (env.random.u32() % (MAX_JITTER_MINUTES + 1)) * DmTime.MINUTE
            nextPass[key] = now + jitter
        }
    }

    /** The scheduled passes that are due, each run once ([admit]); returns how many committed. */
    fun runScheduledPasses(): Int {
        val now = env.now()
        var committed = 0
        for ((key, at) in nextPass.entries.sortedBy { it.value }.toList()) {
            if (at > now) continue
            nextPass.remove(key)
            lastPass[key] = now
            if (admit(key.toByteArray()) == Result.COMMITTED) committed++
        }
        return committed
    }

    /** The second the earliest scheduled pass is due (the actor's next wake), or null. */
    fun nextDue(): Long? = nextPass.values.minOrNull()

    /** Forgets the schedule (lock, wipe). */
    fun clear() {
        nextPass.clear()
        lastPass.clear()
    }

    /** One pass over [channelId]'s pending join requests. */
    fun admit(channelId: ByteArray): Result {
        val now = env.now()
        val day = DmTime.day(now)
        val content = env.keys.content() ?: return Result.UNAVAILABLE
        val seenKey = env.keys.seenKey() ?: return Result.UNAVAILABLE
        try {
            return passWith(channelId, content, seenKey, now, day)
        } finally {
            seenKey.fill(0)
        }
    }

    private class Admission(
        val request: JoinStore.RequestRow,
        val verified: ChannelCrypto.JoinVerified,
        val evidence: AdmitEvidence,
        val kpDay: Long,
        val sponsor: ByteArray,
        val tag: ByteArray,
    )

    /** A request the pass refuses: deleted, and its KeyPackage's tag kept until [untilDay] when the KeyPackage was read. */
    private class Refusal(val request: JoinStore.RequestRow, val tag: ByteArray?, val untilDay: Long) {
        override fun toString(): String = "Refusal(redacted)"
    }

    private fun passWith(
        channelId: ByteArray,
        content: org.ghost.messaging.store.ContentCipher,
        seenKey: ByteArray,
        now: Long,
        day: Long,
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
            Snapshot(channel, epoch, generation, candidates, stores.joins.requests(tx.sql, channelId, day), stores.mls.rows(tx.sql, channelId, day))
        } ?: return Result.NOTHING
        if (snapshot.requests.isEmpty()) return Result.NOTHING
        val rows = MlsRows.of(snapshot.rows)
        val roster = opened.crypto.roster(channelId, rows, day.toInt()).valueOrNull() ?: return Result.UNAVAILABLE
        val rank = roster.context.committers.indexOfFirst { it.contentEquals(p) }
        // CO-1: only a committer admits; CO-7: no own pending commit, no candidate of a rank at or below this one.
        if (rank != 0) return Result.NOTHING
        if (snapshot.candidates.any { it.own || it.rank <= rank }) return Result.NOTHING
        val members = roster.members.map { it.pseudonym.toList() }.toSet()
        val passwordChannel = roster.context.flags and ChannelEnv.FLAG_PASSWORD != 0
        // CO-2 (A)'s sponsor rule, applied before the native call refuses it (§19.38): a committer, or any member where
        // members may invite and the channel has no password (Q46 (b)).
        val committerSet = roster.context.committers.map { it.toList() }.toSet()
        val membersMayInvite = roster.context.flags and ChannelEnv.FLAG_MEMBERS_MAY_INVITE != 0 && !passwordChannel
        // The digest of the committer's current committers (S0-15): kept, or — forgotten by a settle that changed the
        // committers, or never learnt — taken from `roster`'s output and persisted; a password channel learns it too
        // (§19.37 F-S4-2, closed in S5a: the throwaway `inviteBuild` it needed the password for is gone).
        val digest = snapshot.channel.committersDigest ?: ChannelDigest.learn(opened.crypto, channelId, rows, day)?.also { d ->
            env.database.transaction { tx -> stores.channels.setCommittersDigest(tx, channelId, d) }
        }
        val refused = ArrayList<Refusal>()
        val admissions = ArrayList<Admission>()
        val invitesUsed = HashSet<List<Byte>>()
        val cap = ChannelTime.cap(snapshot.channel.sizeClass)
        for (request in snapshot.requests) {
            if (admissions.size >= MAX_ADDS) break
            if (request.type != JoinType.JOIN) continue // a restore is S7's (an invite-authorized swap, §6.12)
            val inviteId = request.inviteId ?: continue
            val body = content.open(request.bodyEnv, ChannelAd.joinRequest(channelId, request.hash))
            if (body == null) {
                refused += Refusal(request, null, 0)
                continue
            }
            val invite = env.database.transaction { tx -> stores.invites.issued(tx.sql, channelId, inviteId, day) }
            if (invite == null || invite.consumed || invite.void) {
                refused += Refusal(request, null, 0)
                continue
            }
            val verified = when (val v = opened.crypto.joinVerify(channelId, body, invite.invitePk, null, request.generation.toInt())) {
                is MlsOutcome.Ok -> v.value
                is MlsOutcome.Refused -> {
                    if (v.code == MlsCode.CRYPTO_UNAVAILABLE) return Result.UNAVAILABLE
                    refused += Refusal(request, null, 0)
                    continue
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
                continue
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
        val built = buildCommit(opened, snapshot, rows, admissions, refused, now, day) ?: return writeRefusals(channelId, refused)
        return writeCommit(channelId, opened, content, snapshot, built, refused, now, day)
    }

    /** What the pass read in its first transaction. */
    private class Snapshot(
        val channel: org.ghost.messaging.channel.store.ChannelStore.ChannelRow,
        val epoch: org.ghost.messaging.channel.store.EpochStore.EpochRow,
        val generation: org.ghost.messaging.channel.store.GenerationStore.GenerationRow,
        val candidates: List<org.ghost.messaging.channel.store.CandidateStore.CandidateRow>,
        val requests: List<JoinStore.RequestRow>,
        val rows: List<org.ghost.messaging.channel.store.MlsKvStore.KvRow>,
    )

    /** A commit built and sealed, with its Welcomes sealed and framed. */
    private class Built(
        val committed: ChannelCrypto.Committed,
        val blob: ByteArray,
        val welcomes: List<ChannelWelcomes.Entry>,
    )

    /**
     * `commit` with the admissions; a KeyPackage or evidence the native side refuses by index is refused here and the
     * commit is built again without it. Null when no admission remains.
     */
    private fun buildCommit(
        opened: ChannelContexts.Opened,
        snapshot: Snapshot,
        rows: List<org.ghost.crypto.bridge.MlsRow>,
        admissions: MutableList<Admission>,
        refused: MutableList<Refusal>,
        now: Long,
        day: Long,
    ): Built? {
        val c = snapshot.channel.channelId
        val floor = ChannelTime.floor(snapshot.channel.sizeClass)
        while (admissions.isNotEmpty()) {
            val request = CommitRequest(
                adds = admissions.map { it.verified.keyPackage to it.evidence },
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
                    if ((r.code == MlsCode.INVALID_KEYPACKAGE || r.code == MlsCode.INVALID_EVIDENCE) && index != null &&
                        index in admissions.indices
                    ) {
                        val gone = admissions.removeAt(index)
                        refused += Refusal(gone.request, gone.tag, gone.kpDay + KP_SEEN_DAYS)
                        continue
                    }
                    return null
                }
            }
            val sealed = opened.crypto.seal(
                c, snapshot.epoch.kEnv, ChannelCrypto.KEY_CLASS_EPOCH, snapshot.generation.namespaceId, floor,
                ChannelCrypto.MODE_EPOCH, ChannelCrypto.SealOrder(snapshot.epoch.epoch, 0, 0), committed.commit,
            ).valueOrNull() ?: return null
            val entries = ArrayList<ChannelWelcomes.Entry>()
            for ((i, kpRef) in committed.joiners.withIndex()) {
                val admission = admissions.firstOrNull { it.verified.kpRef.contentEquals(kpRef) } ?: return null
                val generation = env.database.transaction { tx ->
                    stores.generations.generation(tx.sql, c, admission.request.generation, day)
                } ?: return null
                val welcome = committed.welcomes[i]
                val bucket = ChannelTime.bucket(welcome.size, snapshot.channel.sizeClass) ?: return null
                val blob = opened.crypto.seal(
                    c, generation.jkEnv, ChannelCrypto.KEY_CLASS_JOIN, generation.namespaceId, bucket,
                    ChannelCrypto.MODE_WELCOME, ChannelCrypto.SealOrder.NONE, welcome,
                ).valueOrNull() ?: return null
                entries += ChannelWelcomes.Entry(
                    ns = generation.namespaceId,
                    kpRef = kpRef,
                    inviteId = admission.evidence.inviteId,
                    member = admission.verified.pseudonym,
                    sponsor = admission.sponsor,
                    requestHash = admission.request.hash,
                    kpDay = admission.kpDay,
                    blob = blob,
                )
            }
            return Built(committed, sealed, entries)
        }
        return null
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
                    rank = 0,
                    own = true,
                    bodyEnv = env.seal(content, ChannelAd.candidate(channelId, epoch, hash), committed.commit),
                    firstSeenMinute = DmTime.floorMinute(now),
                    welcomeEnv = env.seal(content, ChannelAd.welcomes(channelId, epoch, hash), framed),
                    boxEnv = committed.boxEnv,
                    removes = committed.summary.removes.isNotEmpty() || committed.summary.swaps.isNotEmpty(),
                )
                // CO-4: the own commit's first sighting is its pass.
                val row = stores.epochs.epoch(tx.sql, channelId, epoch, day)
                val sighting = DmTime.floorMinute(now)
                val anchor = row?.anchorMinute?.let { minOf(it, sighting) } ?: sighting
                stores.epochs.setAnchor(tx, channelId, epoch, anchor)
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
    }
}

/**
 * The plaintext of an own candidate's `welcome_env` (local, under the content key; never on the wire): the new leaf's box
 * public key and, per joiner, what `CH-SETTLE` needs to enqueue the sealed WELCOME blob and to record the admission —
 * the namespace, the KeyPackage reference, the invite, the member's pseudonym, the sponsor, the request's blob hash and
 * the KeyPackage's day (its `ch_kp_seen` lifetime).
 *
 * `version(1) = 1 ‖ box_pk(32) ‖ count(u16) ‖ count × (ns(32) ‖ kp_ref(32) ‖ invite_id(16) ‖ member(32) ‖ sponsor(32) ‖
 * request_hash(32) ‖ kp_day(u32) ‖ len(u32) ‖ blob)`.
 */
internal object ChannelWelcomes {
    class Entry(
        val ns: ByteArray,
        val kpRef: ByteArray,
        val inviteId: ByteArray,
        val member: ByteArray,
        val sponsor: ByteArray,
        val requestHash: ByteArray,
        val kpDay: Long,
        val blob: ByteArray,
    ) {
        override fun toString(): String = "Welcome(redacted)"
    }

    class Framed(val boxPk: ByteArray, val entries: List<Entry>) {
        override fun toString(): String = "Welcomes(${entries.size})"
    }

    private const val VERSION: Int = 1
    private const val FIXED: Int = 32 + 32 + 16 + 32 + 32 + 32 + 4 + 4

    fun encode(boxPk: ByteArray, entries: List<Entry>): ByteArray {
        require(boxPk.size == 32 && entries.size <= 0xffff) { "bad welcome framing" }
        val size = 1 + 32 + 2 + entries.sumOf { FIXED + it.blob.size }
        val b = ByteBuffer.allocate(size)
        b.put(VERSION.toByte()).put(boxPk).putShort(entries.size.toShort())
        for (e in entries) {
            require(e.ns.size == 32 && e.kpRef.size == 32 && e.inviteId.size == 16 && e.member.size == 32 &&
                e.sponsor.size == 32 && e.requestHash.size == 32) { "bad welcome entry" }
            b.put(e.ns).put(e.kpRef).put(e.inviteId).put(e.member).put(e.sponsor).put(e.requestHash)
            b.putInt(e.kpDay.toInt()).putInt(e.blob.size).put(e.blob)
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
            val len = b.int
            if (len < 0 || len > b.remaining()) return null
            val blob = ByteArray(len).also { b.get(it) }
            out += Entry(ns, kpRef, inviteId, member, sponsor, requestHash, kpDay, blob)
        }
        if (b.hasRemaining()) return null
        return Framed(boxPk, out)
    }
}
