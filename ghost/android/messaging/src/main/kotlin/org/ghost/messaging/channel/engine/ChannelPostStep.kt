package org.ghost.messaging.channel.engine

import org.ghost.crypto.bridge.ChannelContentFields
import org.ghost.crypto.bridge.ChannelCrypto
import org.ghost.crypto.bridge.MlsOutcome
import org.ghost.messaging.api.PostResult
import org.ghost.messaging.channel.store.ChannelState
import org.ghost.messaging.channel.store.ChannelStore
import org.ghost.messaging.channel.store.ChannelStoreError
import org.ghost.messaging.channel.store.ChannelStoreException
import org.ghost.messaging.channel.store.Direction
import org.ghost.messaging.channel.store.GenerationState
import org.ghost.messaging.channel.store.OpPurpose
import org.ghost.messaging.channel.store.PostState
import org.ghost.messaging.engine.DmTime
import org.ghost.messaging.engine.DmTimers
import org.ghost.messaging.store.ContentCipher
import org.ghost.storage.SqlExecutor
import org.ghost.storage.StorageFullException
import org.ghost.sync.api.InsufficientReplicasException
import org.ghost.sync.api.NamespaceId
import org.ghost.sync.api.OperationId
import org.ghost.sync.api.OutboundBlob
import org.ghost.sync.api.SyncTransaction

/**
 * **`CH-POST`** (Phase 10 design §6.3.1, §10.4): a post, a reaction or an administrative post (`INVITE_ISSUED`, §6.2.1)
 * is encrypted **only when the channel is current**, in one transaction with its op; otherwise it waits as plaintext
 * under the content key in `ch_pending_post` and is encrypted in the first transaction where the channel is current
 * ([encryptPending], run at every actor pass after the receive step).
 *
 * **What "current" is here** ([isCurrent]): the channel is `active`; it holds no valid candidate for its current epoch
 * that removes a pseudonym — the removal hold of CO-13 (§19.6), read from `ch_candidate.removes` (§19.35 F-1, amended
 * into migration 7 by this slice); and no generation is waiting for its switch (§19.8: posts composed between a settle and
 * the switch wait). **Condition (a) of §6.3.1 is not implemented** — "the client has, in the present session, completed
 * one listing pass over every relay of the current generation's set": `:sync` exposes no listing-pass signal to its
 * consumer (finding F-S4-1 of §19.37, which CO-4 (ii) of S5 shares). In a pass the receive step runs before
 * [encryptPending], so a pending post is encrypted after the blobs the pass fetched were processed.
 *
 * **One op per post** (§6.3.1's last paragraph): the current generation's namespace, the bucket of §5.7, the post TTL of
 * §5.8 (the handshake TTL for an administrative post, §19.21), the deadline `author + min(bucket, 7 d)` (`author + 7 d`
 * for an administrative post), the relays of `set(ns_g, week(now))` (registered with the namespace) and Phase 7's send
 * delay (`SendDelay.OFF` is refused for `Consumer.CHANNEL`, S1a). `seq` is `ch_epoch.own_seq`, incremented in the same
 * transaction, and becomes the `ChannelOrder` of the MLS AAD natively (§5.5, §19.18).
 *
 * Gate G-M5 lists this file for `Outbox.enqueue` (`CH-POST`, and `CH-INVITE`'s `INVITE_ISSUED` through [compose]).
 */
internal class ChannelPostStep(
    private val env: ChannelEnv,
    private val sync: ChannelSyncPorts,
) {
    private val stores = env.stores

    /** What [compose] did with a post. */
    enum class Composed { ENCRYPTED, PENDING }

    /**
     * The facade's `post` and `react` (§10.3): [fields] is the content (kind 1 or 2) with a fresh op id; the author minute
     * and the timer are this step's. Encrypted at once when the channel is current, else pending.
     */
    fun post(channelId: ByteArray, kind: Int, text: ByteArray?, replyTo: ByteArray?, target: ByteArray?, grapheme: ByteArray?): PostResult {
        val now = env.now()
        val content = env.keys.content() ?: return PostResult.CRYPTO_UNAVAILABLE
        val row = env.database.transaction { tx -> stores.channels.channel(tx.sql, channelId) }
        if (row == null || row.state != ChannelState.ACTIVE) return PostResult.NOT_MEMBER
        val opened = env.contexts.open(channelId) ?: return PostResult.CRYPTO_UNAVAILABLE
        if (!opened.pseudonym.contentEquals(row.myPseudonym)) return PostResult.CRYPTO_UNAVAILABLE
        val fields = ChannelContentFields(
            kind = kind,
            opId = env.random.bytes(OP_ID_BYTES),
            authorMinute = Math.floorDiv(now, DmTime.MINUTE),
            timerCode = row.timerCode,
            text = text,
            replyTo = replyTo,
            target = target,
            grapheme = grapheme,
        )
        val encoded = when (val e = ChannelCrypto.contentEncode(fields)) {
            is MlsOutcome.Ok -> e.value
            is MlsOutcome.Refused -> return if (e.code == org.ghost.crypto.bridge.MlsCode.CRYPTO_UNAVAILABLE) {
                PostResult.CRYPTO_UNAVAILABLE
            } else {
                PostResult.TOO_LARGE
            }
        }
        return try {
            env.database.transaction { tx ->
                val fresh = stores.channels.channel(tx.sql, channelId)
                if (fresh == null || fresh.state != ChannelState.ACTIVE) return@transaction PostResult.NOT_MEMBER
                compose(tx, fresh, opened, content, fields, encoded, handshake = false, now = now)
                PostResult.QUEUED
            }
        } catch (e: InsufficientReplicasException) {
            PostResult.NO_REPLICAS
        } catch (e: StorageFullException) {
            PostResult.STORAGE_FULL
        } catch (e: ChannelStoreException) {
            limitOrThrow(e)
        } finally {
            encoded.fill(0)
        }
    }

    /**
     * The user's **retry** of a failed post (§6.11's `failed → queued`, a `CH-POST`): the post keeps its op id — §6.3.4 layer
     * 4 is what drops the second copy at a member the first one reached (an op that ended FAILED may still have been stored
     * by a relay) — and is re-encrypted under the epoch, the timer and the minute of now ([PostStore.retry], S3's contract).
     * A channel that is not current keeps it pending like any post, and the row stays `failed` until it is encrypted; a
     * second retry while it waits changes nothing.
     */
    fun retryPost(channelId: ByteArray, opId: ByteArray): PostResult {
        val now = env.now()
        val content = env.keys.content() ?: return PostResult.CRYPTO_UNAVAILABLE
        val row = env.database.transaction { tx -> stores.channels.channel(tx.sql, channelId) }
        if (row == null || row.state != ChannelState.ACTIVE) return PostResult.NOT_MEMBER
        val post = env.database.transaction { tx -> stores.posts.post(tx.sql, opId, now) }
        if (post == null || !post.channelId.contentEquals(channelId) || post.direction != Direction.OUT ||
            post.state != PostState.FAILED || post.kind != KIND_POST
        ) {
            return PostResult.NOT_FAILED
        }
        val opened = env.contexts.open(channelId) ?: return PostResult.CRYPTO_UNAVAILABLE
        if (!opened.pseudonym.contentEquals(row.myPseudonym)) return PostResult.CRYPTO_UNAVAILABLE
        val text = content.open(post.bodyEnv, ChannelAd.postBody(opId)) ?: return PostResult.CRYPTO_UNAVAILABLE
        val fields = ChannelContentFields(
            kind = KIND_POST,
            opId = opId,
            authorMinute = Math.floorDiv(now, DmTime.MINUTE),
            timerCode = row.timerCode,
            text = text,
            replyTo = post.replyTo,
            target = null,
            grapheme = null,
        )
        val encoded = when (val e = ChannelCrypto.contentEncode(fields)) {
            is MlsOutcome.Ok -> e.value
            is MlsOutcome.Refused -> {
                text.fill(0)
                return PostResult.CRYPTO_UNAVAILABLE
            }
        }
        return try {
            env.database.transaction { tx ->
                val fresh = stores.channels.channel(tx.sql, channelId)
                if (fresh == null || fresh.state != ChannelState.ACTIVE) return@transaction PostResult.NOT_MEMBER
                val waiting = stores.posts.pending(tx.sql, channelId, DmTime.floorHour(now)).any { it.opId.contentEquals(opId) }
                if (!waiting) compose(tx, fresh, opened, content, fields, encoded, handshake = false, now = now)
                PostResult.QUEUED
            }
        } catch (e: InsufficientReplicasException) {
            PostResult.NO_REPLICAS
        } catch (e: StorageFullException) {
            PostResult.STORAGE_FULL
        } catch (e: ChannelStoreException) {
            limitOrThrow(e)
        } finally {
            encoded.fill(0)
            text.fill(0)
        }
    }

    /** §6.3.5's 256 pending posts of a channel, reached: a result; any other store refusal is a defect, rethrown. */
    private fun limitOrThrow(e: ChannelStoreException): PostResult =
        if (e.error == ChannelStoreError.LIMIT) PostResult.LIMIT_REACHED else throw e

    /**
     * Encrypts [encoded] and enqueues it in [tx] when the channel is current, else keeps it pending. Throws what
     * `Outbox.enqueue` throws ([InsufficientReplicasException]: fewer than two operators this week), which rolls the
     * caller's transaction back. A native refusal of `encrypt` other than `PENDING_COMMIT` throws too: the channel's
     * stored state does not load, and nothing of the post may be written.
     */
    fun compose(
        tx: SyncTransaction,
        channel: ChannelStore.ChannelRow,
        opened: ChannelContexts.Opened,
        content: ContentCipher,
        fields: ChannelContentFields,
        encoded: ByteArray,
        handshake: Boolean,
        now: Long,
    ): Composed {
        val day = DmTime.day(now)
        if (!isCurrent(tx.sql, channel, now) || !encryptNow(tx, channel, opened, content, fields, encoded, handshake, now, day)) {
            keepPending(tx, channel.channelId, fields, content, encoded, handshake, now)
            return Composed.PENDING
        }
        return Composed.ENCRYPTED
    }

    /**
     * §6.3.1's "current" as far as `:sync` lets the consumer know it (see the class note): active, no removal hold on the
     * current epoch, no generation waiting for its switch.
     */
    fun isCurrent(sql: SqlExecutor, channel: ChannelStore.ChannelRow, now: Long): Boolean {
        if (channel.state != ChannelState.ACTIVE) return false
        if (stores.candidates.holdsRemoval(sql, channel.channelId, channel.epoch)) return false
        val day = DmTime.day(now)
        return stores.generations.live(sql, channel.channelId, day).none { it.state == GenerationState.PENDING_SWITCH }
    }

    private fun encryptNow(
        tx: SyncTransaction,
        channel: ChannelStore.ChannelRow,
        opened: ChannelContexts.Opened,
        content: ContentCipher,
        fields: ChannelContentFields,
        encoded: ByteArray,
        handshake: Boolean,
        now: Long,
        day: Long,
    ): Boolean {
        val c = channel.channelId
        val epoch = stores.epochs.open(tx.sql, c, day) ?: return false
        val generation = stores.generations.current(tx.sql, c, day) ?: return false
        val rows = MlsRows.of(stores.mls.rows(tx.sql, c, day))
        val encrypted = when (val e = opened.crypto.encrypt(c, rows, encoded, epoch.ownSeq.toInt(), day.toInt())) {
            is MlsOutcome.Ok -> e.value
            is MlsOutcome.Refused -> {
                // The native backstop of CO-13 (§6.3.1, §19.13): an own pending commit that removes a pseudonym. The
                // removal hold above holds the post first; the backstop is reached only when the own commit is the hold.
                // A library gone meanwhile keeps the post pending too; any other refusal is a state that does not load.
                if (e.code == org.ghost.crypto.bridge.MlsCode.PENDING_COMMIT || e.code == org.ghost.crypto.bridge.MlsCode.CRYPTO_UNAVAILABLE) {
                    return false
                }
                throw IllegalStateException("channel encrypt refused: ${e.code}")
            }
        }
        check(encrypted.epoch == epoch.epoch) { "the post was encrypted in another epoch than the open one" }
        val seq = stores.epochs.nextOwnSeq(tx, c, epoch.epoch, day)
        check(seq == epoch.ownSeq) { "the own sequence moved under the encryption" }
        stores.mls.apply(tx, c, MlsRows.changes(encrypted.changes))
        val bucket = ChannelTime.bucket(encrypted.mls.size, channel.sizeClass)
            ?: throw IllegalStateException("a post longer than any bucket passed the content codec")
        val blob = when (
            val s = opened.crypto.seal(
                c, epoch.kEnv, ChannelCrypto.KEY_CLASS_EPOCH, generation.namespaceId, bucket, ChannelCrypto.MODE_EPOCH,
                ChannelCrypto.SealOrder(epoch.epoch, encrypted.senderLeaf.toInt(), seq.toInt()), encrypted.mls,
            )
        ) {
            is MlsOutcome.Ok -> s.value
            is MlsOutcome.Refused -> throw IllegalStateException("channel seal refused: ${s.code}")
        }
        val authorSeconds = fields.authorMinute * DmTime.MINUTE
        val ttl = if (handshake) ChannelTime.handshakeTtl(channel.timerCode) else ChannelTime.postTtl(channel.timerCode)
        val deadline = if (handshake) ChannelTime.handshakeDeadline(authorSeconds) else ChannelTime.postDeadline(authorSeconds, channel.timerCode)
        val operationId = env.random.bytes(OperationId.SIZE)
        sync.outbox.enqueue(
            tx,
            OutboundBlob(OperationId(operationId), NamespaceId(generation.namespaceId), blob, ttl, deadlineEpochSeconds = deadline),
        )
        val purpose = if (fields.kind == KIND_POST || fields.kind == KIND_REACTION) OpPurpose.POST else OpPurpose.REQUEST
        stores.posts.insertOp(tx, operationId, c, purpose, fields.opId)
        when (fields.kind) {
            KIND_POST -> {
                val deleteAt = DmTimers.senderExpireMinute(now, fields.timerCode)
                // A retry (§6.11's failed → queued) re-encrypts a row that exists; a new post inserts its row.
                if (!stores.posts.retry(tx, fields.opId, epoch.epoch, fields.timerCode, authorSeconds, deleteAt)) {
                    stores.posts.insertOutgoing(
                        tx = tx,
                        opId = fields.opId,
                        channelId = c,
                        author = opened.pseudonym,
                        kind = KIND_POST,
                        replyTo = fields.replyTo,
                        timerCode = fields.timerCode,
                        epoch = epoch.epoch,
                        bodyEnv = env.seal(content, ChannelAd.postBody(fields.opId), fields.text ?: ByteArray(0)),
                        authorMinute = authorSeconds,
                        deleteAtMinute = deleteAt,
                    )
                }
            }
            KIND_REACTION -> {
                val target = fields.target ?: throw IllegalStateException("a reaction without a target")
                val grapheme = fields.grapheme ?: ByteArray(0)
                if (grapheme.isEmpty()) {
                    stores.posts.deleteReaction(tx, target, opened.pseudonym)
                } else {
                    stores.posts.putReaction(tx, target, opened.pseudonym, c, env.seal(content, ChannelAd.grapheme(target, opened.pseudonym), grapheme))
                }
            }
            else -> Unit
        }
        return true
    }

    private fun keepPending(
        tx: SyncTransaction,
        channelId: ByteArray,
        fields: ChannelContentFields,
        content: ContentCipher,
        encoded: ByteArray,
        handshake: Boolean,
        now: Long,
    ) {
        val authorSeconds = fields.authorMinute * DmTime.MINUTE
        val deadline = if (handshake) ChannelTime.handshakeDeadline(authorSeconds) else ChannelTime.postDeadline(authorSeconds, fields.timerCode)
        stores.posts.insertPending(
            tx, fields.opId, channelId, fields.kind, env.seal(content, ChannelAd.pending(fields.opId), encoded),
            DmTime.ceilHour(maxOf(deadline, now + DmTime.MINUTE)),
        )
    }

    /**
     * The pending posts of every active channel that is current now (§6.3.1: "encrypted and enqueued in the first
     * transaction where the channel is current"), each in a transaction of its own, oldest deadline first. The content
     * is re-encoded with the channel's timer of the moment — encrypt-at-session (§5.5: "the author encrypts with the
     * current policy timer") — and keeps its op id and author minute.
     */
    fun encryptPending() {
        val now = env.now()
        val content = env.keys.content() ?: return
        val channels = env.database.transaction { tx -> stores.channels.channelsIn(tx.sql, ChannelState.ACTIVE) }
        for (channel in channels) {
            val pending = env.database.transaction { tx -> stores.posts.pending(tx.sql, channel.channelId, DmTime.floorHour(now)) }
            if (pending.isEmpty()) continue
            val opened = env.contexts.open(channel.channelId) ?: continue
            for (row in pending) {
                val plain = content.open(row.contentEnv, ChannelAd.pending(row.opId)) ?: continue
                val stored = ChannelCrypto.contentDecode(plain).valueOrNull()
                plain.fill(0)
                stored ?: continue
                val handshake = stored.kind != KIND_POST && stored.kind != KIND_REACTION
                try {
                    env.database.transaction { tx ->
                        val fresh = stores.channels.channel(tx.sql, channel.channelId) ?: return@transaction
                        if (!isCurrent(tx.sql, fresh, now)) return@transaction
                        val fields = stored.withTimer(if (handshake) stored.timerCode else fresh.timerCode)
                        val encoded = ChannelCrypto.contentEncode(fields).valueOrNull() ?: return@transaction
                        try {
                            if (encryptNow(tx, fresh, opened, content, fields, encoded, handshake, now, DmTime.day(now))) {
                                stores.posts.deletePending(tx, row.opId)
                            }
                        } finally {
                            encoded.fill(0)
                        }
                    }
                } catch (e: InsufficientReplicasException) {
                    // No quorum this week: the post stays pending until its deadline, as a DM send does.
                    Unit
                }
            }
        }
    }

    private fun ChannelContentFields.withTimer(timer: Int): ChannelContentFields = ChannelContentFields(
        kind = kind, opId = opId, authorMinute = authorMinute, timerCode = timer, text = text, replyTo = replyTo,
        target = target, grapheme = grapheme, inviteId = inviteId, invitePk = invitePk, expiryDay = expiryDay,
        sponsorSig = sponsorSig, committersDigest = committersDigest, pwVersion = pwVersion, hpkeEnc = hpkeEnc,
        ciphertext = ciphertext,
    )

    override fun toString(): String = "ChannelPostStep"

    companion object {
        const val OP_ID_BYTES: Int = 16

        /** `ChannelContent.kind` (§5.5). */
        const val KIND_POST: Int = 1
        const val KIND_REACTION: Int = 2
        const val KIND_INVITE_ISSUED: Int = 3
        const val KIND_LEAVE: Int = 4
        const val KIND_REVEAL: Int = 5

        /** The longest text of a post (§5.5, NFR-14). */
        const val MAX_TEXT: Int = 16_000
    }
}
