package org.ghost.messaging.channel.engine

import org.ghost.crypto.bridge.ChannelCrypto
import org.ghost.crypto.bridge.ChannelRecognition
import org.ghost.crypto.bridge.CommitSummary
import org.ghost.crypto.bridge.MlsCode
import org.ghost.crypto.bridge.MlsCommitReason
import org.ghost.crypto.bridge.MlsField
import org.ghost.crypto.bridge.MlsOutcome
import org.ghost.messaging.channel.store.CandidateStore
import org.ghost.messaging.channel.store.ChannelState
import org.ghost.messaging.channel.store.ChannelStore
import org.ghost.messaging.channel.store.GenerationStore
import org.ghost.messaging.channel.store.InviteStore
import org.ghost.messaging.channel.store.JoinStore
import org.ghost.messaging.channel.store.JoinType
import org.ghost.messaging.engine.DmTime
import org.ghost.messaging.engine.DmTimers
import org.ghost.messaging.store.ContentCipher
import org.ghost.sync.api.BlobHash
import org.ghost.sync.api.Consumer
import org.ghost.sync.api.InboundBlob
import org.ghost.sync.api.NamespaceId
import org.ghost.sync.api.PeekedBlob
import org.ghost.sync.api.SyncTransaction
import org.ghost.sync.store.StoreLimits
import java.security.MessageDigest

/**
 * **`CH-RECV`** (Phase 10 design §6.3.2 … §6.3.4, §10.4): the messaging actor drains `Consumer.CHANNEL` as it drains
 * `Consumer.DM` (D16). Each round `peek`s up to [peekLimit] fetched rows (512, §19.38: §6.3.5's 128 is below Phase 7's
 * `FETCHED_CAP` of one namespace), routes each by its namespace — a listened generation (`ch_generation`) or a pending
 * join (`ch_join`, §19.35 F-8) — and classifies it by the one hint that matches (CS-S5: `R_ep(e)` with mode 0x11 for the
 * current and every retained epoch, `R_join(g)` with 0x12 and 0x13 for the namespace's generation). Then, in this order,
 * each in its own transaction after `Inbox.claimOne` (whose offer counter commits first, the F9 §7.8 poison guard: a blob
 * offered for the fourth time is consumed unprocessed and counted):
 *
 *  1. **Application messages** of each epoch, in peek order ([ChannelPeekOrder]) and **in batches of up to 32**, one
 *     `receive` call and one transaction per batch (S0-17); a message that fails rolls back alone inside the batch (§3.4
 *     point 9) and is consumed and counted; posts are applied before reactions (§19.35 F-4), and a reaction whose post is
 *     not on the device yet is **held in memory** until the post lands (§19.38: bounded, lost at a restart, and dropped
 *     and counted when evicted); a batch whose `receive` throws (`INTERNAL`) is retried blob by blob, and a blob that
 *     throws alone is left to the poison guard. A namespace **under pressure** — a full window, or as many due rows as
 *     `FETCHED_CAP` — defers the entries a gap holds instead of holding them in place (§19.38, [ChannelPeekOrder]), and a
 *     batch that decrypts the `seq` they wait for re-offers them; the round is then repeated (≤ [RECEIVE_ROUNDS]).
 *  2. **Commits**, alone: for the current epoch a validation run (CO-2, native), recorded as a candidate with its sighting
 *     and its relay store hour, its removal-hold mark (§19.35 F-1) and the CO-4 anchor of the epoch, within the bounds of
 *     §6.3.5 (one per sender, the lowest hash; the best 8 by `(rank, hash)`); for a retained past epoch a **late
 *     candidate** — a fork signal, or nothing when it is the winner resurrected (CO-6) — never processed.
 *  3. **Join requests** (mode 0x12): a committer records a pending request (§6.2.3), others consume and ignore it.
 *  4. **Welcomes** (mode 0x13): a pending join's are `CH-JOIN`'s; a member consumes and ignores one.
 *  5. **No match**: deferred with a backoff (60 s doubling to 6 h; `Inbox.defer`) while a key could still appear — a
 *     future epoch, a pending join's Welcome, an `INVITE_ISSUED` a request names — and consumed at its relay expiry.
 *
 * **Dropped before `process_message`** (§6.3.2, §19.16): an MLS **proposal** (its header content type, which `open`
 * reads), counted — GHOST never stores one, or every later post of the member would be refused. **A result OpenMLS
 * reports as the member's own** (`OwnPrivateMessage`, `OwnPendingCommit`) is evidence of nothing (§19.13): Phase 7 never
 * fetches an own blob back — the enqueue writes the own `done` row of `(namespace, hash)` — so any such blob is a copy
 * someone else re-sealed, dropped and counted.
 *
 * **Dedup** (§6.3.4): layer 1 is Phase 7's `(namespace, hash)` tombstone (a copy never reaches this step); layer 2 is
 * MLS (a replayed message fails to decrypt, a resurrected commit of a settled epoch has the winner's hash); layer 3 is
 * the seal (a copy into another namespace does not open, CS-S3); layer 4 is `ch_seen`, the keyed tag of the author and
 * the op id (§19.38), kept as `dm_seen` with the post's bucket: an op id an author already used is dropped even after
 * its post was swept, and another author's reuse of it is counted as the clash it is.
 *
 * **Remote data cannot fail a batch.** Every value a member chose is checked before it reaches a store (a store refuses a
 * bad value with an exception, which would roll the whole batch back and, at the fourth offer, poison every post in it).
 *
 * **No relay-visible call** (T40, gate G-M5): this file calls no `Namespaces`, `Outbox`, `Registrations`, `Funding` or
 * `Capabilities` method. `defer`, `markConsumed` and `reofferDeferred` write local rows.
 */
internal class ChannelReceiveStep(
    private val env: ChannelEnv,
    private val sync: ChannelSyncPorts,
    private val joinStep: ChannelJoinStep,
    private val peekOrder: ChannelPeekOrder,
    /** The rows one round peeks (§19.38); a world passes a smaller one to put a pass under pressure. */
    private val peekLimit: Int = PEEK_LIMIT,
    /** Phase 7's fetched cap of a namespace, whose reach puts the namespace under pressure (§19.38). */
    private val fetchedCap: Int = StoreLimits.FETCHED_CAP,
) {
    private val stores = env.stores

    /**
     * `(namespace ‖ hash)` → the next deferral in seconds of a blob no key opens yet (in memory: a restart starts the
     * backoff over, T33). Kept across passes while the blob waits — a deferred blob is not in the next peek — and bounded
     * by eviction of the least recently used entry (§19.38: pruning it to each peek reset every backoff to 60 s).
     */
    private val backoff = object : LinkedHashMap<List<Byte>, Int>(64, 0.75f, true) {
        override fun removeEldestEntry(eldest: MutableMap.MutableEntry<List<Byte>, Int>?): Boolean = size > MAX_BACKOFF_ENTRIES
    }

    /**
     * Reactions whose post is not on the device yet, `(channel ‖ target ‖ author)` → the reaction (§19.38): a reaction can
     * arrive in an earlier batch than its post, or while its post is held behind a gap. Bounded (the eldest is dropped
     * and counted as an orphan); in memory, so a restart loses what it held (declared, §19.38).
     */
    private val heldReactions = object : LinkedHashMap<List<Byte>, HeldReaction>(16, 0.75f, false) {
        override fun removeEldestEntry(eldest: MutableMap.MutableEntry<List<Byte>, HeldReaction>?): Boolean {
            val drop = size > MAX_HELD_REACTIONS
            if (drop) env.counters.count(ChannelCounters.Reason.REACTION_ORPHAN)
            return drop
        }
    }

    /** A held reaction: its grapheme already sealed for the row it will be written to. */
    private class HeldReaction(val channelId: ByteArray, val target: ByteArray, val author: ByteArray, val graphemeEnv: ByteArray) {
        override fun toString(): String = "HeldReaction(redacted)"
    }

    /** Whether a batch of the current round re-offered rows a gap had deferred (the round is then repeated). */
    private var reoffered = false

    /** What the hint said a blob is. */
    private sealed class Kind {
        class Epoch(val epoch: Long) : Kind()
        object Join : Kind()
        object Welcome : Kind()
        object Unknown : Kind()
    }

    /** A peeked blob and what routing and recognition made of it. */
    private class Classified(
        val blob: PeekedBlob,
        val channel: ChannelStore.ChannelRow?,
        val generation: GenerationStore.GenerationRow?,
        val join: JoinStore.JoinRow?,
        val kind: Kind,
    ) {
        val namespace: List<Byte> = blob.namespace.toByteArray().toList()
        val key: List<Byte> = namespace + blob.hash.toByteArray().toList()
    }

    /** A mode-0x11 blob opened in memory. */
    private class Opened(val c: Classified, val epoch: Long, val contentType: Int, val leaf: Long, val seq: Long, val body: ByteArray)

    /** What opening a mode-0x11 blob did: opened, consumed (a forgery, counted), or left for a later pass. */
    private sealed class OpenResult {
        class Ok(val opened: Opened) : OpenResult()
        object Consumed : OpenResult()
        object Left : OpenResult()
    }

    /** What [claim] did: the blob, nothing (gone or not due), or a fourth offer consumed unprocessed (the poison guard). */
    private sealed class Claim {
        class Held(val blob: InboundBlob) : Claim()
        object Gone : Claim()
        object Poisoned : Claim()
    }

    /**
     * One pass over the fetched channel blobs; returns how many were consumed, so the engine can repeat it after a settle
     * re-offered deferred blobs (CO-4's catch-up). A round that re-offered rows a gap had deferred is followed by another
     * at once, up to [RECEIVE_ROUNDS]. Stops at [deadlineMonotonicMillis] (the consumer tail's, Phase 9 §21.12 point 1: a
     * claimed blob is never abandoned half-applied).
     */
    fun consume(deadlineMonotonicMillis: Long?): Int {
        var consumed = 0
        repeat(RECEIVE_ROUNDS) {
            reoffered = false
            consumed += consumeRound(deadlineMonotonicMillis)
            if (!reoffered || outOfTime(deadlineMonotonicMillis)) return consumed
        }
        return consumed
    }

    private fun consumeRound(deadlineMonotonicMillis: Long?): Int {
        val peeked = sync.inbox.peek(Consumer.CHANNEL, peekLimit)
        if (peeked.isEmpty()) {
            peekOrder.idle(env.now())
            return 0
        }
        val now = env.now()
        val day = DmTime.day(now)
        val present = peeked.map { it.namespace.toByteArray().toList() + it.hash.toByteArray().toList() }.toSet()
        // §19.38: a full window may hide the next blob of a sender, and a namespace at Phase 7's fetched cap fetches no
        // further blob until rows are consumed — under either, a gap is deferred, not held in place.
        val windowFull = peeked.size >= peekLimit
        val dueByNamespace = peeked.groupingBy { it.namespace.toByteArray().toList() }.eachCount()
        val classified = env.database.transaction { tx -> peeked.map { classify(tx, it, day) } }
        var consumed = 0
        val apps = ArrayList<ChannelPeekOrder.Entry<Opened>>()
        val commits = ArrayList<Opened>()
        val joins = ArrayList<Classified>()
        val welcomes = ArrayList<Classified>()
        val unknown = ArrayList<Classified>()
        for (c in classified) {
            when (val k = c.kind) {
                is Kind.Epoch -> when (val r = openEpoch(c, k.epoch, day)) {
                    OpenResult.Consumed -> consumed++
                    OpenResult.Left -> Unit
                    is OpenResult.Ok -> {
                        val o = r.opened
                        when (o.contentType) {
                            CONTENT_APPLICATION -> {
                                val pressure = windowFull || (dueByNamespace[c.namespace] ?: 0) >= fetchedCap
                                apps += ChannelPeekOrder.Entry(c.channel!!.channelId, o.epoch, o.leaf, o.seq, c.key, c.namespace, o, pressure)
                            }
                            CONTENT_COMMIT -> commits += o
                            // §6.3.2, §19.16: a proposal is dropped before `process_message`, never stored.
                            else -> if (drop(c, ChannelCounters.Reason.PROPOSAL)) consumed++
                        }
                    }
                }
                Kind.Join -> joins += c
                Kind.Welcome -> welcomes += c
                Kind.Unknown -> unknown += c
            }
        }
        val plan = peekOrder.plan(apps, present, now)
        for ((entry, waitingFor) in plan.deferrals) {
            if (outOfTime(deadlineMonotonicMillis)) return consumed
            val opened = entry.value
            val deferred = if (opened != null) {
                deferClaimed(opened.c, ChannelPeekOrder.GAP_DEFER_SECONDS)
            } else {
                deferKey(entry.key, ChannelPeekOrder.GAP_DEFER_SECONDS)
            }
            if (deferred) {
                peekOrder.deferred(entry, waitingFor, now + ChannelPeekOrder.GAP_DEFER_SECONDS)
                env.counters.count(ChannelCounters.Reason.GAP_DEFERRED)
            }
        }
        for (batch in plan.batches) {
            if (outOfTime(deadlineMonotonicMillis)) return consumed
            consumed += applicationBatch(batch, now, day)
        }
        for (o in commits) {
            if (outOfTime(deadlineMonotonicMillis)) return consumed
            consumed += commit(o, now, day)
        }
        val committers = HashMap<List<Byte>, Boolean>()
        for (c in joins) {
            if (outOfTime(deadlineMonotonicMillis)) return consumed
            consumed += joinRequest(c, committers, now, day)
        }
        for (c in welcomes) {
            if (outOfTime(deadlineMonotonicMillis)) return consumed
            consumed += welcome(c)
        }
        for (c in unknown) {
            if (outOfTime(deadlineMonotonicMillis)) return consumed
            consumed += unmatched(c, now)
        }
        return consumed
    }

    /** Forgets what the passes kept in memory (the backoffs, the held reactions): the context closed. */
    fun clear() {
        backoff.clear()
        heldReactions.clear()
    }

    // ------------------------------------------------------------------------------------ classification

    private fun classify(tx: SyncTransaction, blob: PeekedBlob, day: Long): Classified {
        val ns = blob.namespace.toByteArray()
        val bytes = blob.ciphertext
        val route = stores.generations.route(tx.sql, ns, day)
        if (route != null) {
            val channel = stores.channels.channel(tx.sql, route.channelId)
            val generation = stores.generations.generation(tx.sql, route.channelId, route.generation, day)
            if (channel == null || generation == null) return Classified(blob, null, null, null, Kind.Unknown)
            // The likely keys first (CS-S5): the current epoch, then the retained ones newest first, then the join modes.
            val candidates = sequence {
                for (e in stores.epochs.retained(tx.sql, channel.channelId, day)) {
                    yield(ChannelRecognition.Candidate(e.rEp, ChannelCrypto.MODE_EPOCH, e.epoch))
                }
                yield(ChannelRecognition.Candidate(generation.rJoin, ChannelCrypto.MODE_JOIN, JOIN_MARK))
                yield(ChannelRecognition.Candidate(generation.rJoin, ChannelCrypto.MODE_WELCOME, WELCOME_MARK))
            }
            val kind = when (val m = ChannelRecognition.matchFirst(bytes, candidates)?.value) {
                null -> Kind.Unknown
                JOIN_MARK -> Kind.Join
                WELCOME_MARK -> Kind.Welcome
                else -> Kind.Epoch(m)
            }
            return Classified(blob, channel, generation, null, kind)
        }
        val join = stores.joins.joinByNamespace(tx.sql, ns, day)
        if (join != null) {
            val channel = stores.channels.channel(tx.sql, join.channelId)
            val rJoin = join.rJoin ?: return Classified(blob, channel, null, join, Kind.Unknown)
            val kind = when {
                ChannelRecognition.matches(bytes, rJoin, ChannelCrypto.MODE_WELCOME) -> Kind.Welcome
                ChannelRecognition.matches(bytes, rJoin, ChannelCrypto.MODE_JOIN) -> Kind.Join
                else -> Kind.Unknown
            }
            return Classified(blob, channel, null, join, kind)
        }
        return Classified(blob, null, null, null, Kind.Unknown)
    }

    /** Opens a mode-0x11 blob in memory (no write); a forged or non-canonical seal is consumed and counted. */
    private fun openEpoch(c: Classified, epoch: Long, day: Long): OpenResult {
        val channel = c.channel ?: return OpenResult.Left
        val generation = c.generation ?: return OpenResult.Left
        val epochRow = env.database.transaction { tx -> stores.epochs.epoch(tx.sql, channel.channelId, epoch, day) }
            ?: return if (drop(c, ChannelCounters.Reason.UNOPENABLE)) OpenResult.Consumed else OpenResult.Left
        val opened = env.contexts.open(channel.channelId) ?: return OpenResult.Left
        return when (
            val o = opened.crypto.open(
                channel.channelId, epochRow.kEnv, ChannelCrypto.KEY_CLASS_EPOCH, generation.namespaceId,
                ChannelCrypto.MODE_EPOCH, c.blob.ciphertext,
            )
        ) {
            is MlsOutcome.Ok -> {
                val v = o.value
                // The key is the epoch's; a header that names another epoch is not this epoch's message (CS-S7).
                if (v.headerEpoch != epoch) {
                    if (drop(c, ChannelCounters.Reason.NON_CANONICAL)) OpenResult.Consumed else OpenResult.Left
                } else {
                    OpenResult.Ok(Opened(c, epoch, v.contentType ?: 0, v.aadLeaf ?: 0, v.aadSeq ?: 0, v.body))
                }
            }
            is MlsOutcome.Refused -> when (o.code) {
                MlsCode.CRYPTO_UNAVAILABLE -> OpenResult.Left
                MlsCode.STATE_CORRUPT -> {
                    deferClaimed(c, STATE_CORRUPT_DEFER_SECONDS)
                    env.counters.count(ChannelCounters.Reason.STATE_CORRUPT)
                    OpenResult.Left
                }
                MlsCode.NOT_OPEN -> if (drop(c, ChannelCounters.Reason.FORGED_SEAL)) OpenResult.Consumed else OpenResult.Left
                else -> if (drop(c, ChannelCounters.Reason.NON_CANONICAL)) OpenResult.Consumed else OpenResult.Left
            }
        }
    }

    // ------------------------------------------------------------------------------- application messages

    /** A claimed application message of a batch: its MLS body and its inbox row. */
    private class Ready(val key: List<Byte>, val body: ByteArray, val blob: InboundBlob)

    private fun applicationBatch(batch: List<ChannelPeekOrder.Entry<Opened>>, now: Long, day: Long): Int {
        if (batch.isEmpty()) return 0
        val channelId = batch.first().channelId
        val epoch = batch.first().epoch
        val content = env.keys.content() ?: return 0
        val seenKey = env.keys.seenKey() ?: return 0
        try {
            var consumed = 0
            val claimed = ArrayList<Ready>()
            for (e in batch) {
                val o = e.value
                // A row the window showed is claimed as peeked; a deferred one offered back by its key, by its key (§19.38).
                when (val r = if (o != null) claim(o.c) else claimKey(e.key)) {
                    Claim.Poisoned -> {
                        consumed++
                        peekOrder.forget(e.key)
                    }
                    Claim.Gone -> peekOrder.forget(e.key)
                    is Claim.Held -> {
                        if (o != null) {
                            claimed += Ready(e.key, o.body, r.blob)
                        } else {
                            when (val b = openClaimed(channelId, e, r.blob, day)) {
                                is Reopened.Body -> claimed += Ready(e.key, b.body, r.blob)
                                Reopened.Unavailable -> Unit
                                Reopened.Bad -> {
                                    env.database.transaction { tx -> consume(tx, r.blob, ChannelCounters.Reason.NON_CANONICAL) }
                                    peekOrder.forget(e.key)
                                    consumed++
                                }
                            }
                        }
                    }
                }
            }
            if (claimed.isEmpty()) return consumed
            val done = applyBatch(channelId, epoch, claimed, content, seenKey, now, day)
            if (done != null) return consumed + done
            // S0-17: a batch that fails with INTERNAL is retried blob by blob, each in its own transaction; a blob that
            // fails alone stays claimed, and the poison guard consumes it at its fourth offer.
            for (one in claimed) {
                consumed += applyBatch(channelId, epoch, listOf(one), content, seenKey, now, day) ?: 0
            }
            return consumed
        } finally {
            seenKey.fill(0)
        }
    }

    /** What re-opening a row claimed by its key gave. */
    private sealed class Reopened {
        class Body(val body: ByteArray) : Reopened()
        object Unavailable : Reopened()
        object Bad : Reopened()
    }

    /**
     * Opens a row deferred behind a gap and claimed by its key (§19.38): the seal again, under the epoch's key — the row
     * was opened as this message before it was deferred, so anything else is a store that changed under it.
     */
    private fun openClaimed(channelId: ByteArray, e: ChannelPeekOrder.Entry<Opened>, blob: InboundBlob, day: Long): Reopened {
        val epochRow = env.database.transaction { tx -> stores.epochs.epoch(tx.sql, channelId, e.epoch, day) } ?: return Reopened.Bad
        val opened = env.contexts.open(channelId) ?: return Reopened.Unavailable
        return when (
            val o = opened.crypto.open(
                channelId, epochRow.kEnv, ChannelCrypto.KEY_CLASS_EPOCH, blob.namespace.toByteArray(), ChannelCrypto.MODE_EPOCH,
                blob.ciphertext,
            )
        ) {
            is MlsOutcome.Ok -> {
                val v = o.value
                if (v.headerEpoch == e.epoch && v.contentType == CONTENT_APPLICATION && v.aadLeaf == e.leaf && v.aadSeq == e.seq) {
                    Reopened.Body(v.body)
                } else {
                    Reopened.Bad
                }
            }
            is MlsOutcome.Refused -> if (o.code == MlsCode.CRYPTO_UNAVAILABLE) Reopened.Unavailable else Reopened.Bad
        }
    }

    /** One transaction for one batch; null when the native call threw (`INTERNAL`), with nothing written. */
    private fun applyBatch(
        channelId: ByteArray,
        epoch: Long,
        claimed: List<Ready>,
        content: ContentCipher,
        seenKey: ByteArray,
        now: Long,
        day: Long,
    ): Int? {
        val opened = env.contexts.open(channelId) ?: return 0
        val done = env.database.transaction { tx ->
            val channel = stores.channels.channel(tx.sql, channelId)
            if (channel == null || (channel.state != ChannelState.ACTIVE && channel.state != ChannelState.LEAVING)) {
                for (r in claimed) consume(tx, r.blob, ChannelCounters.Reason.UNROUTED)
                return@transaction claimed.size
            }
            val stored = MlsRows.of(stores.mls.rows(tx.sql, channelId, day))
            val received = try {
                opened.crypto.receive(channelId, stored, epoch, claimed.map { it.body }, day.toInt())
            } catch (e: IllegalStateException) {
                // `INTERNAL` (a caught Rust panic) or a reply the facade could not decode: retried blob by blob.
                return@transaction null
            }
            val items = when (received) {
                is MlsOutcome.Ok -> received.value
                is MlsOutcome.Refused -> when (received.code) {
                    MlsCode.CRYPTO_UNAVAILABLE -> return@transaction 0
                    MlsCode.STATE_CORRUPT -> {
                        for (r in claimed) sync.inbox.defer(tx, r.blob.namespace, r.blob.hash, STATE_CORRUPT_DEFER_SECONDS)
                        env.counters.count(ChannelCounters.Reason.STATE_CORRUPT)
                        return@transaction 0
                    }
                    else -> {
                        for (r in claimed) consume(tx, r.blob, ChannelCounters.Reason.NON_CANONICAL)
                        return@transaction claimed.size
                    }
                }
            }
            // One item per message, in order (§10.2 fn 6): another count is the facade's contract broken, INTERNAL.
            if (items.items.size != claimed.size) return@transaction null
            stores.mls.apply(tx, channelId, MlsRows.changes(items.changes))
            // The context an INVITE_ISSUED is judged against, read once and only when the batch holds one (§19.38).
            var inviters: Inviters? = null
            val judge = { inviters ?: readInviters(opened, channelId, stored, day).also { inviters = it } }
            // Posts and records first, reactions second (§19.35 F-4): a reaction of a lower leaf to a post of a higher one
            // sits before its target in the peek order.
            val reactions = ArrayList<ChannelCrypto.Item.App>()
            for ((index, item) in items.items.withIndex()) {
                when (item) {
                    is ChannelCrypto.Item.App -> {
                        peekOrder.decrypted(channelId, epoch, item.senderLeaf, item.seq)
                        when (item.content.kind) {
                            ChannelPostStep.KIND_REACTION -> reactions += item
                            ChannelPostStep.KIND_POST ->
                                applyPost(tx, channel, epoch, item, claimed[index].blob, content, seenKey, now, day)
                            ChannelPostStep.KIND_INVITE_ISSUED -> applyInviteIssued(tx, channel, item, judge(), day)
                            // LEAVE is slice S6's (a committer's pending work), REVEAL slice S9's (the box keys).
                            ChannelPostStep.KIND_LEAVE, ChannelPostStep.KIND_REVEAL ->
                                env.counters.count(ChannelCounters.Reason.DEFERRED_KIND)
                            else -> env.counters.count(ChannelCounters.Reason.NON_CANONICAL)
                        }
                    }
                    is ChannelCrypto.Item.Own -> env.counters.count(ChannelCounters.Reason.FORGED_OWN)
                    is ChannelCrypto.Item.Proposal -> env.counters.count(ChannelCounters.Reason.PROPOSAL)
                    is ChannelCrypto.Item.Commit -> env.counters.count(ChannelCounters.Reason.NON_CANONICAL)
                    is ChannelCrypto.Item.Failed -> env.counters.count(ChannelCounters.Reason.UNDECRYPTABLE)
                }
            }
            for (item in reactions) applyReaction(tx, channel, item, content)
            for (r in claimed) sync.inbox.markConsumed(tx, r.blob.namespace, r.blob.hash)
            // §19.38: the rows a gap had deferred under pressure come back once the `seq` they waited for decrypted.
            for (ns in peekOrder.reofferDue(channelId)) {
                if (sync.inbox.reofferDeferred(tx, NamespaceId(ns.toByteArray())) > 0) reoffered = true
            }
            claimed.size
        }
        if (done == claimed.size) for (r in claimed) peekOrder.forget(r.key)
        return done
    }

    private fun applyPost(
        tx: SyncTransaction,
        channel: ChannelStore.ChannelRow,
        epoch: Long,
        item: ChannelCrypto.Item.App,
        blob: InboundBlob,
        content: ContentCipher,
        seenKey: ByteArray,
        now: Long,
        day: Long,
    ) {
        val fields = item.content
        val text = fields.text
        val replyTo = fields.replyTo
        if (text == null || text.isEmpty() || text.size > ChannelPostStep.MAX_TEXT || fields.timerCode !in 0..DmTimers.TIMER_MAX ||
            fields.opId.size != ChannelPostStep.OP_ID_BYTES || (replyTo != null && replyTo.size != ChannelPostStep.OP_ID_BYTES)
        ) {
            return env.counters.count(ChannelCounters.Reason.NON_CANONICAL)
        }
        val c = channel.channelId
        val tag = ChannelTags.opTag(seenKey, c, item.sender, fields.opId)
        // Layer 4 (§6.3.4): an op id its author already used — a re-encryption after FAILED keeps its op id — is dropped,
        // even once its post was swept.
        if (stores.posts.isSeen(tx.sql, c, tag, day)) {
            env.counters.count(ChannelCounters.Reason.DUPLICATE)
            return
        }
        // §5.5: a receiver deletes a post after the shorter of its own timer and the channel's.
        val timer = ChannelTime.shorterTimer(fields.timerCode, channel.timerCode)
        val authorSeconds = fields.authorMinute * DmTime.MINUTE
        // §8.2: an unread post dies at min(E, consume + bucket + 1 h); E is its blob's relay expiry.
        val deleteAt = DmTimers.unreadDeadlineMinute(now, blob.relayExpiryHour, timer)
        // §19.38 (the DM's EXPIRED_WHILE_HELD, F9 §21.10 point 5): a post whose relay copy expired while it waited here —
        // behind a gap, a deferral, a closed process — is past both its lives and is not inserted, only counted.
        if (blob.relayExpiryHour <= now || (deleteAt != null && deleteAt <= now)) {
            env.counters.count(ChannelCounters.Reason.EXPIRED_WHILE_HELD)
            return
        }
        val inserted = stores.posts.insertIncomingIfAbsent(
            tx = tx,
            opId = fields.opId,
            channelId = c,
            author = item.sender,
            kind = ChannelPostStep.KIND_POST,
            replyTo = replyTo,
            timerCode = timer,
            epoch = epoch,
            bodyEnv = env.seal(content, ChannelAd.postBody(fields.opId), text),
            authorMinute = authorSeconds,
            deleteAtMinute = deleteAt,
            relayExpiryHour = blob.relayExpiryHour,
        )
        if (!inserted) {
            // §19.35 F-10: the first holder of an op id keeps it; another author reusing it is counted, not shown (and
            // can suppress the later holder's post: recorded in §19.38, F-S4-15).
            val existing = stores.posts.post(tx.sql, fields.opId, now)
            val sameAuthor = existing == null || existing.author.contentEquals(item.sender)
            env.counters.count(if (sameAuthor) ChannelCounters.Reason.DUPLICATE else ChannelCounters.Reason.OP_ID_CLASH)
            return
        }
        stores.posts.markSeen(tx, c, tag, DmTimers.seenUntilDay(authorSeconds, ChannelTime.postTtl(timer)))
        // The reactions that reached the device before this post (§19.38) land with it.
        val prefix = c.toList() + fields.opId.toList()
        val waiting = heldReactions.entries.filter { it.key.size > prefix.size && it.key.subList(0, prefix.size) == prefix }
        for (held in waiting) {
            val r = held.value
            stores.posts.putReaction(tx, r.target, r.author, r.channelId, r.graphemeEnv)
            heldReactions.remove(held.key)
        }
    }

    private fun applyReaction(tx: SyncTransaction, channel: ChannelStore.ChannelRow, item: ChannelCrypto.Item.App, content: ContentCipher) {
        val fields = item.content
        val target = fields.target
        val grapheme = fields.grapheme ?: ByteArray(0)
        if (target == null || target.size != ChannelPostStep.OP_ID_BYTES || grapheme.size > MAX_GRAPHEME) {
            return env.counters.count(ChannelCounters.Reason.NON_CANONICAL)
        }
        val heldKey = channel.channelId.toList() + target.toList() + item.sender.toList()
        if (grapheme.isEmpty()) {
            // A withdrawal: of the stored reaction, or of one still waiting for its post.
            heldReactions.remove(heldKey)
            stores.posts.deleteReaction(tx, target, item.sender)
            return
        }
        val graphemeEnv = env.seal(content, ChannelAd.grapheme(target, item.sender), grapheme)
        if (!stores.posts.putReaction(tx, target, item.sender, channel.channelId, graphemeEnv)) {
            // The post is not on the device yet: held until it lands (a later reaction of the same author replaces it).
            heldReactions.remove(heldKey)
            heldReactions[heldKey] = HeldReaction(channel.channelId, target, item.sender, graphemeEnv)
            env.counters.count(ChannelCounters.Reason.REACTION_HELD)
        }
    }

    /** Who may sponsor an invite in the current context (§6.2.1, Q46 (b)): its members and whether each may invite. */
    private class Inviters(val members: Set<List<Byte>>, val committers: Set<List<Byte>>, val membersMayInvite: Boolean) {
        fun mayInvite(sponsor: ByteArray): Boolean {
            val p = sponsor.toList()
            return p in members && (p in committers || membersMayInvite)
        }

        override fun toString(): String = "Inviters(redacted)"
    }

    private fun readInviters(opened: ChannelContexts.Opened, channelId: ByteArray, rows: List<org.ghost.crypto.bridge.MlsRow>, day: Long): Inviters? {
        val roster = opened.crypto.roster(channelId, rows, day.toInt()).valueOrNull() ?: return null
        val flags = roster.context.flags
        return Inviters(
            members = roster.members.mapTo(HashSet()) { it.pseudonym.toList() },
            committers = roster.context.committers.mapTo(HashSet()) { it.toList() },
            membersMayInvite = flags and ChannelEnv.FLAG_MEMBERS_MAY_INVITE != 0 && flags and ChannelEnv.FLAG_PASSWORD == 0,
        )
    }

    /**
     * §6.2.1: every member records an `INVITE_ISSUED` (`ch_invite_issued`); the sponsor is the post's MLS sender, whose
     * `sponsor_sig` CO-2 (A) verifies at admission. The namespace's deferred blobs are re-offered: a join request that
     * arrived before the invite it names was deferred for want of it ([joinRequest]).
     *
     * **What is recorded** (§19.38): only a record that could admit anyone — its sponsor a current member who may invite
     * (a committer, or any member where members may and the channel has no password: CO-2 (A)'s own rule, which would
     * refuse the admission later) and its `expiry_day` no later than §5.9's `issue day + 7` allows, with a day of clock
     * skew. Without these a member could plant records no invite stands behind, without end. `sponsor_sig` itself is
     * verified only at admission: no native function verifies it alone (recorded, §19.38).
     */
    private fun applyInviteIssued(tx: SyncTransaction, channel: ChannelStore.ChannelRow, item: ChannelCrypto.Item.App, inviters: Inviters?, day: Long) {
        val f = item.content
        val inviteId = f.inviteId
        val invitePk = f.invitePk
        val sponsorSig = f.sponsorSig
        val digest = f.committersDigest
        val expiryDay = f.expiryDay
        val pwVersion = f.pwVersion
        if (inviteId == null || inviteId.size != INVITE_ID_BYTES || invitePk == null || invitePk.size != KEY_BYTES ||
            sponsorSig == null || sponsorSig.size != SIGNATURE_BYTES || digest == null || digest.size != KEY_BYTES ||
            expiryDay == null || expiryDay < 0 || (pwVersion != null && pwVersion !in 1..MAX_PW_VERSION)
        ) {
            return env.counters.count(ChannelCounters.Reason.NON_CANONICAL)
        }
        if (expiryDay > day + ChannelInviteStep.MAX_EXPIRY_DAYS + EXPIRY_SKEW_DAYS || inviters == null || !inviters.mayInvite(item.sender)) {
            return env.counters.count(ChannelCounters.Reason.INVITE_REFUSED)
        }
        val recorded = stores.invites.recordIssued(
            tx = tx,
            channelId = channel.channelId,
            inviteId = inviteId,
            invitePk = invitePk,
            sponsor = item.sender,
            sponsorSig = sponsorSig,
            committersDigest = digest,
            pwVersion = pwVersion,
            expiryDay = expiryDay,
        )
        if (recorded) {
            for (g in stores.generations.live(tx.sql, channel.channelId, day)) {
                sync.inbox.reofferDeferred(tx, NamespaceId(g.namespaceId))
            }
        }
    }

    // ------------------------------------------------------------------------------------------- commits

    private fun commit(o: Opened, now: Long, day: Long): Int {
        val channel = o.c.channel ?: return 0
        val c = channel.channelId
        val blob = when (val r = claim(o.c)) {
            Claim.Poisoned -> return 1
            Claim.Gone -> return 0
            is Claim.Held -> r.blob
        }
        if (o.epoch < channel.epoch) {
            // CO-6: a commit of a settled epoch is never processed (OpenMLS refuses a non-current handshake before
            // decrypting it, valn1307): the winner resurrected is ignored, another hash is a fork signal (diagnostics).
            env.database.transaction { tx ->
                val hash = sha256(o.body)
                val settled = stores.epochs.epoch(tx.sql, c, o.epoch, day)
                if (settled?.winnerHash != null && settled.winnerHash.contentEquals(hash)) {
                    env.counters.count(ChannelCounters.Reason.RESURRECTED_COMMIT)
                } else {
                    stores.epochs.addForkSignal(tx, c, o.epoch, hash, day)
                    env.counters.count(ChannelCounters.Reason.LATE_CANDIDATE)
                }
                sync.inbox.markConsumed(tx, blob.namespace, blob.hash)
            }
            return 1
        }
        val content = env.keys.content() ?: return 0
        val opened = env.contexts.open(c) ?: return 0
        return env.database.transaction { tx ->
            val fresh = stores.channels.channel(tx.sql, c)
            if (fresh == null || (fresh.state != ChannelState.ACTIVE && fresh.state != ChannelState.LEAVING) || o.epoch != fresh.epoch) {
                // Settled meanwhile (the next copy is a late candidate), or not a member any more.
                consume(tx, blob, ChannelCounters.Reason.LATE_CANDIDATE)
                return@transaction 1
            }
            val rows = MlsRows.of(stores.mls.rows(tx.sql, c, day))
            val received = try {
                opened.crypto.receive(c, rows, o.epoch, listOf(o.body), day.toInt())
            } catch (e: IllegalStateException) {
                // `INTERNAL`: nothing written; the blob stays claimed and the poison guard consumes it at its fourth offer.
                return@transaction 0
            }
            val item = when (received) {
                is MlsOutcome.Ok -> received.value.items.singleOrNull()
                is MlsOutcome.Refused -> {
                    if (received.code == MlsCode.CRYPTO_UNAVAILABLE) return@transaction 0
                    if (received.code == MlsCode.STATE_CORRUPT) {
                        sync.inbox.defer(tx, blob.namespace, blob.hash, STATE_CORRUPT_DEFER_SECONDS)
                        env.counters.count(ChannelCounters.Reason.STATE_CORRUPT)
                        return@transaction 0
                    }
                    consume(tx, blob, ChannelCounters.Reason.NON_CANONICAL)
                    return@transaction 1
                }
            }
            // The validation run's change-set is discarded (CO-2: "checked on a validation run whose change-set is
            // discarded"); the winner is processed again, with persistence, at the settle.
            when (item) {
                is ChannelCrypto.Item.Commit -> {
                    if (item.summary.isValid && item.summary.epoch == o.epoch) {
                        recordCandidate(tx, fresh, o.epoch, item.summary, o.body, blob, content, now)
                    } else if (item.summary.invalidReason == MlsCommitReason.LIFETIME) {
                        // §19.29.1: a `LifetimeError` refusal is a non-canonical KeyPackage — the commit
                        // is invalid for every member on both of OpenMLS's branches: dropped and counted,
                        // never a candidate, never blocking.
                        env.counters.count(ChannelCounters.Reason.INVALID_LIFETIME)
                    } else {
                        env.counters.count(ChannelCounters.Reason.INVALID_COMMIT)
                    }
                }
                // The member's own message: a copy of the member's own commit that a listing pass
                // fetched (D-5, owner 2026-10-05) verifies the pending commit, recognised by its hash,
                // and ends the INDETERMINATE wait; any other "own" blob is a forgery (§19.13).
                is ChannelCrypto.Item.Own -> {
                    val hash = sha256(o.body)
                    val ownCandidate = stores.candidates.own(tx.sql, c, o.epoch)
                    if (ownCandidate != null && ownCandidate.hash.contentEquals(hash)) {
                        val storeHour = (blob.relayExpiryHour - ChannelTime.handshakeTtl(fresh.timerCode).seconds).takeIf { it >= 0 }
                        val seen = DmTime.floorMinute(now)
                        stores.candidates.markVerified(tx, c, o.epoch, hash, seen, storeHour)
                        lowerAnchor(tx, c, o.epoch, seen, storeHour)
                    } else {
                        env.counters.count(ChannelCounters.Reason.FORGED_OWN)
                    }
                }
                is ChannelCrypto.Item.Proposal -> env.counters.count(ChannelCounters.Reason.PROPOSAL)
                is ChannelCrypto.Item.Failed ->
                    if (item.refusal.reason == MlsCommitReason.LIFETIME) {
                        env.counters.count(ChannelCounters.Reason.INVALID_LIFETIME)
                    } else {
                        env.counters.count(ChannelCounters.Reason.INVALID_COMMIT)
                    }
                is ChannelCrypto.Item.App, null -> env.counters.count(ChannelCounters.Reason.NON_CANONICAL)
            }
            sync.inbox.markConsumed(tx, blob.namespace, blob.hash)
            1
        }
    }

    /**
     * Records a valid candidate within §6.3.5's bounds (CO-3's keeping rule; the arbitration among them is `CH-SETTLE`'s):
     * another copy of a held candidate only lowers its store hour; one candidate per sender, the lowest hash; at most 8
     * foreign ones, the best by `(rank, hash)`. The CO-4 anchor of the epoch is the earliest, over the held candidates, of
     * the first sighting and the relay store hour + 60 min.
     */
    private fun recordCandidate(
        tx: SyncTransaction,
        channel: ChannelStore.ChannelRow,
        epoch: Long,
        summary: CommitSummary,
        body: ByteArray,
        blob: InboundBlob,
        content: ContentCipher,
        now: Long,
    ) {
        val c = channel.channelId
        val hash = summary.hash
        // CO-4: the store hour is `relayExpiryHour − handshake TTL` of the copy fetched (the relay rounds the expiry up).
        val storeHour = (blob.relayExpiryHour - ChannelTime.handshakeTtl(channel.timerCode).seconds).takeIf { it >= 0 }
        val firstSeen = DmTime.floorMinute(now)
        if (stores.candidates.candidate(tx.sql, c, epoch, hash) != null) {
            if (storeHour != null) stores.candidates.lowerStoreHour(tx, c, epoch, hash, storeHour)
            lowerAnchor(tx, c, epoch, firstSeen, storeHour)
            return
        }
        val ofSender = stores.candidates.candidateOf(tx.sql, c, epoch, summary.sender)
        if (ofSender != null) {
            if (ofSender.own || compareUnsigned(hash, ofSender.hash) >= 0) return
            stores.candidates.delete(tx, c, epoch, ofSender.hash)
        }
        val foreign = stores.candidates.candidates(tx.sql, c, epoch).filter { !it.own }
        if (foreign.size >= MAX_FOREIGN_CANDIDATES) {
            val worst = foreign.maxWithOrNull(CANDIDATE_ORDER) ?: return
            val better = summary.rank < worst.rank || (summary.rank == worst.rank && compareUnsigned(hash, worst.hash) < 0)
            if (!better) return
            stores.candidates.delete(tx, c, epoch, worst.hash)
        }
        stores.candidates.insert(
            tx = tx,
            channelId = c,
            epoch = epoch,
            hash = hash,
            sender = summary.sender,
            rank = summary.rank,
            own = false,
            bodyEnv = env.seal(content, ChannelAd.candidate(c, epoch, hash), body),
            firstSeenMinute = firstSeen,
            storeHour = storeHour,
            // CO-13: a Remove, a leave, an eviction or a swap removes a leaf whose holder could read the epoch's posts.
            removes = summary.removes.isNotEmpty() || summary.swaps.isNotEmpty(),
        )
        lowerAnchor(tx, c, epoch, firstSeen, storeHour)
    }

    private fun lowerAnchor(tx: SyncTransaction, channelId: ByteArray, epoch: Long, firstSeen: Long, storeHour: Long?) {
        val row = stores.epochs.epoch(tx.sql, channelId, epoch, DmTime.day(env.now())) ?: return
        val sighting = minOf(firstSeen, storeHour?.let { it + DmTime.HOUR } ?: Long.MAX_VALUE)
        val anchor = DmTime.floorMinute(row.anchorMinute?.let { minOf(it, sighting) } ?: sighting)
        if (anchor != row.anchorMinute) stores.epochs.setAnchor(tx, channelId, epoch, anchor)
    }

    // -------------------------------------------------------------------------------------- join requests

    /**
     * §6.3.2's 0x12 row. A committer opens the request with `JK_g` and finds the invite it names: `joinVerify` (§10.2
     * fn 15) needs the invite's public key before it says which invite the request names (finding F-S4-3 of §19.37), so
     * the request is verified under each distinct `invite_pk` of the live invites the member holds, and then bound to the
     * record whose `invite_id` is **the one the invitee signed** (`auth.INVITE_ID`; §19.38: binding it to the first record
     * that merely shares the key let any member plant a record under a lower id and capture the request). A request
     * refused for its KeyPackage, purpose or binding is consumed and counted; one no held invite signs is **deferred** —
     * the `INVITE_ISSUED` may arrive later — until its relay expiry. A request for a spent or void invite, a second request
     * for one invite and a 65th request are ignored (§6.2.4, §6.3.5). The policy of §6.2.4 (B) is the pass's (`CH-PASS`),
     * on the stored request.
     */
    private fun joinRequest(c: Classified, committers: MutableMap<List<Byte>, Boolean>, now: Long, day: Long): Int {
        val channel = c.channel
        val generation = c.generation
        if (channel == null || generation == null || channel.state != ChannelState.ACTIVE) {
            // An invitee's own namespace carries other joiners' requests, which it cannot open (its key is an invite's).
            return if (drop(c, null)) 1 else 0
        }
        val opened = env.contexts.open(channel.channelId) ?: return 0
        val committer = committers.getOrPut(channel.channelId.toList()) { isCommitter(channel, opened, day) }
        if (!committer) return if (drop(c, null)) 1 else 0
        val content = env.keys.content() ?: return 0
        val body = when (
            val o = opened.crypto.open(
                channel.channelId, generation.jkEnv, ChannelCrypto.KEY_CLASS_JOIN, generation.namespaceId,
                ChannelCrypto.MODE_JOIN, c.blob.ciphertext,
            )
        ) {
            is MlsOutcome.Ok -> o.value.body
            is MlsOutcome.Refused -> return when (o.code) {
                MlsCode.CRYPTO_UNAVAILABLE -> 0
                MlsCode.NOT_OPEN -> if (drop(c, ChannelCounters.Reason.FORGED_SEAL)) 1 else 0
                else -> if (drop(c, ChannelCounters.Reason.NON_CANONICAL)) 1 else 0
            }
        }
        val invites = env.database.transaction { tx -> stores.invites.issuedOf(tx.sql, channel.channelId, day) }
        var found: Pair<InviteStore.IssuedRow, ChannelCrypto.JoinVerified>? = null
        // One verification per key: records that share an `invite_pk` cost one `joinVerify` together.
        for (sharing in invites.groupBy { it.invitePk.toList() }.values) {
            when (val v = opened.crypto.joinVerify(channel.channelId, body, sharing.first().invitePk, null, generation.generation.toInt())) {
                is MlsOutcome.Ok -> {
                    val signed = v.value.auth.bytesOrNull(MlsField.INVITE_ID) ?: continue
                    val invite = sharing.firstOrNull { it.inviteId.contentEquals(signed) } ?: continue
                    found = invite to v.value
                    break
                }
                is MlsOutcome.Refused -> when (v.code) {
                    MlsCode.BAD_SIGNATURE -> continue
                    MlsCode.CRYPTO_UNAVAILABLE -> return 0
                    // The KeyPackage, its purpose or its form is refused whatever the invite (decoded before the signature).
                    else -> return if (drop(c, ChannelCounters.Reason.JOIN_REFUSED)) 1 else 0
                }
            }
        }
        val match = found
        if (match == null) {
            env.counters.count(ChannelCounters.Reason.JOIN_UNKNOWN_INVITE)
            return deferUnknown(c, now)
        }
        val (invite, verified) = match
        val type = when (verified.requestType) {
            REQUEST_JOIN -> JoinType.JOIN
            REQUEST_RESTORE -> JoinType.RESTORE
            else -> return if (drop(c, ChannelCounters.Reason.JOIN_REFUSED)) 1 else 0
        }
        val blob = when (val r = claim(c)) {
            Claim.Poisoned -> return 1
            Claim.Gone -> return 0
            is Claim.Held -> r.blob
        }
        return env.database.transaction { tx ->
            when {
                invite.consumed || invite.void -> consume(tx, blob, ChannelCounters.Reason.JOIN_REFUSED)
                // A second request for one invite is ignored (§6.2.4); so is a request past the 64 of §6.3.5.
                stores.joins.requestOfInvite(tx.sql, channel.channelId, invite.inviteId, day) != null ->
                    consume(tx, blob, ChannelCounters.Reason.DUPLICATE)
                stores.joins.requests(tx.sql, channel.channelId, day).size >= MAX_JOIN_REQUESTS ->
                    consume(tx, blob, ChannelCounters.Reason.JOIN_REFUSED)
                else -> {
                    val hash = blob.hash.toByteArray()
                    stores.joins.insertRequest(
                        tx, channel.channelId, hash, generation.generation, type, invite.inviteId,
                        env.seal(content, ChannelAd.joinRequest(channel.channelId, hash), body), invite.expiryDay,
                    )
                    sync.inbox.markConsumed(tx, blob.namespace, blob.hash)
                }
            }
            1
        }
    }

    /** Whether the member is a committer of the channel's current context (CO-1: rank < 255). */
    private fun isCommitter(channel: ChannelStore.ChannelRow, opened: ChannelContexts.Opened, day: Long): Boolean {
        val rows = MlsRows.of(env.database.transaction { tx -> stores.mls.rows(tx.sql, channel.channelId, day) })
        val roster = opened.crypto.roster(channel.channelId, rows, day.toInt()).valueOrNull() ?: return false
        val p = opened.pseudonym
        return roster.context.committers.any { it.contentEquals(p) }
    }

    // ------------------------------------------------------------------------------------------- welcomes

    private fun welcome(c: Classified): Int {
        val join = c.join
        if (join == null || c.channel?.state != ChannelState.JOINING) {
            // §6.3.2's 0x13 row: a member needs nothing from a Welcome.
            return if (drop(c, null)) 1 else 0
        }
        val blob = when (val r = claim(c)) {
            Claim.Poisoned -> return 1
            Claim.Gone -> return 0
            is Claim.Held -> r.blob
        }
        return when (joinStep.join(blob, join)) {
            ChannelJoinStep.Outcome.JOINED, ChannelJoinStep.Outcome.CONSUMED -> 1
            ChannelJoinStep.Outcome.LEFT -> 0
        }
    }

    // -------------------------------------------------------------------------------------------- no match

    private fun unmatched(c: Classified, now: Long): Int {
        if (c.channel == null && c.join == null) return if (drop(c, ChannelCounters.Reason.UNROUTED)) 1 else 0
        return deferUnknown(c, now)
    }

    /** §6.3.2 "no match": deferred with a backoff while a key could still appear, consumed at its relay expiry. */
    private fun deferUnknown(c: Classified, now: Long): Int {
        if (c.blob.relayExpiryHour <= now) return if (drop(c, ChannelCounters.Reason.UNOPENABLE)) 1 else 0
        val delay = backoff[c.key] ?: FIRST_DEFER_SECONDS
        if (deferClaimed(c, delay)) backoff[c.key] = minOf(delay * 2, MAX_DEFER_SECONDS)
        return 0
    }

    // ---------------------------------------------------------------------------------------------- helpers

    /**
     * `Inbox.claimOne` (its offer counter commits before the hand-off, F9 §7.8), then the poison guard: a blob offered for
     * the fourth time died unconsumed three times — a native crash, a full disk, a defect — and is consumed unprocessed
     * and counted, so no crash loop can hold the channel (R2's rule for DMs, with the same constant).
     */
    private fun claim(c: Classified): Claim = claim(c.blob.namespace, c.blob.hash)

    /** [claim] of a row known by its `(namespace ‖ hash)` key alone: a deferred row offered back by the plan (§19.38). */
    private fun claimKey(key: List<Byte>): Claim =
        claim(NamespaceId(key.subList(0, NamespaceId.SIZE).toByteArray()), BlobHash(key.subList(NamespaceId.SIZE, key.size).toByteArray()))

    private fun claim(namespace: NamespaceId, hash: BlobHash): Claim {
        val blob = sync.inbox.claimOne(Consumer.CHANNEL, namespace, hash) ?: return Claim.Gone
        if (blob.offers >= POISON_OFFERS) {
            env.database.transaction { tx -> sync.inbox.markConsumed(tx, blob.namespace, blob.hash) }
            env.counters.count(ChannelCounters.Reason.POISONED)
            return Claim.Poisoned
        }
        return Claim.Held(blob)
    }

    /** Claims and defers the row [key] by [seconds]; true when deferred (a row gone is forgotten). */
    private fun deferKey(key: List<Byte>, seconds: Int): Boolean = when (val r = claimKey(key)) {
        Claim.Poisoned, Claim.Gone -> {
            peekOrder.forget(key)
            false
        }
        is Claim.Held -> {
            env.database.transaction { tx -> sync.inbox.defer(tx, r.blob.namespace, r.blob.hash, seconds) }
            true
        }
    }

    /** Claims and consumes a blob; [reason] null consumes without counting (traffic the member ignores). True when consumed. */
    private fun drop(c: Classified, reason: ChannelCounters.Reason?): Boolean = when (val r = claim(c)) {
        Claim.Poisoned -> true
        Claim.Gone -> false
        is Claim.Held -> {
            env.database.transaction { tx -> sync.inbox.markConsumed(tx, r.blob.namespace, r.blob.hash) }
            backoff.remove(c.key)
            reason?.let { env.counters.count(it) }
            true
        }
    }

    /** Claims and defers a blob by [seconds]; true when deferred. */
    private fun deferClaimed(c: Classified, seconds: Int): Boolean = when (val r = claim(c)) {
        Claim.Poisoned, Claim.Gone -> false
        is Claim.Held -> {
            env.database.transaction { tx -> sync.inbox.defer(tx, r.blob.namespace, r.blob.hash, seconds) }
            true
        }
    }

    private fun consume(tx: SyncTransaction, blob: InboundBlob, reason: ChannelCounters.Reason) {
        sync.inbox.markConsumed(tx, blob.namespace, blob.hash)
        env.counters.count(reason)
    }

    private fun outOfTime(deadlineMonotonicMillis: Long?): Boolean {
        val deadline = deadlineMonotonicMillis ?: return false
        return env.clock.monotonicMillis() + TAIL_RESERVE_MILLIS >= deadline
    }

    override fun toString(): String = "ChannelReceiveStep"

    companion object {
        /**
         * The rows one round peeks: §6.3.5's 128 raised to twice Phase 7's `FETCHED_CAP` of a namespace (§19.38), so one
         * namespace's whole due set fits; beyond it a pass is under pressure ([ChannelPeekOrder]).
         */
        const val PEEK_LIMIT: Int = 512

        /** At most this many rounds a pass, each after one that re-offered rows a gap had deferred (§19.38). */
        const val RECEIVE_ROUNDS: Int = 16

        /** §6.3.5: at most 64 pending join requests per channel. */
        const val MAX_JOIN_REQUESTS: Int = 64

        /** §6.3.5: at most 8 foreign candidates per epoch. */
        const val MAX_FOREIGN_CANDIDATES: Int = 8

        /** §6.3.2: the first deferral, doubled to [MAX_DEFER_SECONDS]. */
        const val FIRST_DEFER_SECONDS: Int = 60
        const val MAX_DEFER_SECONDS: Int = 6 * 3_600

        /** The blobs whose deferral backoff is remembered (the least recently used one is forgotten first). */
        const val MAX_BACKOFF_ENTRIES: Int = 4_096

        /** The reactions held for a post that has not arrived (§19.38). */
        const val MAX_HELD_REACTIONS: Int = 256

        /** A blob whose stored state did not load waits an hour, never consumed (it is not the blob's fault). */
        const val STATE_CORRUPT_DEFER_SECONDS: Int = 3_600

        /** R2 of Phase 9 (`ReceiveStep.POISON_OFFERS`): the fourth offer of a blob that died three times is consumed. */
        const val POISON_OFFERS: Int = 4

        /** §5.5: a reaction's grapheme is at most 32 bytes (`ch_reaction.grapheme_env` is 29 … 60). */
        const val MAX_GRAPHEME: Int = 32

        /** The consumer tail stops claiming with fewer than two seconds left (Phase 9 §21.12 point 1). */
        const val TAIL_RESERVE_MILLIS: Long = 2_000

        /** `open`'s content type of a mode-0x11 PrivateMessage: 1 application, 2 commit, 3 proposal. */
        const val CONTENT_APPLICATION: Int = 1
        const val CONTENT_COMMIT: Int = 2

        /** `joinVerify`'s request types: 1 join, 2 rejoin, 3 restore. */
        const val REQUEST_JOIN: Int = 1
        const val REQUEST_RESTORE: Int = 3

        /** The clock skew an `INVITE_ISSUED`'s expiry may carry beyond §5.9's `issue day + 7` (§19.38). */
        const val EXPIRY_SKEW_DAYS: Long = 1

        private const val INVITE_ID_BYTES: Int = 16
        private const val KEY_BYTES: Int = 32
        private const val SIGNATURE_BYTES: Int = 64
        private const val MAX_PW_VERSION: Int = 65_535

        private const val JOIN_MARK: Long = -1
        private const val WELCOME_MARK: Long = -2

        /** CO-3's order of candidates: `(rank, hash)`, the hash compared as unsigned bytes. */
        val CANDIDATE_ORDER: Comparator<CandidateStore.CandidateRow> =
            compareBy<CandidateStore.CandidateRow> { it.rank }.thenComparator { a, b -> compareUnsigned(a.hash, b.hash) }

        fun sha256(bytes: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(bytes)

        /** Unsigned lexicographic order of two hashes (CO-3's tie-break). */
        fun compareUnsigned(a: ByteArray, b: ByteArray): Int {
            for (i in 0 until minOf(a.size, b.size)) {
                val d = (a[i].toInt() and 0xff) - (b[i].toInt() and 0xff)
                if (d != 0) return d
            }
            return a.size - b.size
        }
    }
}
