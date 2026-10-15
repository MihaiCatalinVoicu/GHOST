package org.ghost.messaging.engine

import org.ghost.crypto.bridge.CredentialV3
import org.ghost.crypto.bridge.DmCards
import org.ghost.crypto.bridge.DmContent
import org.ghost.media.send.MediaFeeder
import org.ghost.media.send.MediaOpId
import org.ghost.media.store.MediaBlob
import org.ghost.media.store.MediaDescriptor
import org.ghost.media.store.MediaKind
import org.ghost.media.store.MediaLimits
import org.ghost.media.store.MediaObjects
import org.ghost.media.store.MediaRole
import org.ghost.media.store.NewOutgoing
import org.ghost.media.store.ObjectState
import org.ghost.media.store.RetryResult
import org.ghost.media.store.UploadState
import org.ghost.messaging.port.DmClock
import org.ghost.messaging.port.DmCrypto
import org.ghost.messaging.port.DmEnvelopes
import org.ghost.messaging.port.DmRandom
import org.ghost.messaging.store.ContactStore
import org.ghost.messaging.store.ContentCipher
import org.ghost.messaging.store.MessageStore
import org.ghost.storage.StorageFullException
import org.ghost.sync.api.CapabilityKind
import org.ghost.sync.api.CapabilitySource
import org.ghost.sync.api.Consumer
import org.ghost.sync.api.InsufficientReplicasException
import org.ghost.sync.api.NamespaceId
import org.ghost.sync.api.Outcome
import org.ghost.sync.api.SyncDatabase

/**
 * The sender half of the media state machines (Phase 11 design §13.5): **MEDIA-COMMIT**,
 * **MEDIA-FEED**, **MEDIA-OUTCOME**, **MEDIA-READY** and **MEDIA-DEADLINE**, each one transaction
 * on the DM actor, exactly as F9's steps are. State lives in the stores of `:media` (S3); this
 * class owns the transitions' order and the DM rows around them:
 *
 *  - `MEDIA-COMMIT` (§6.3): registers `M_c` LOCAL with the deposit credentials and deletes a
 *    pending `dm_orphan_namespace(M_c)` row (the S4-owner producers' counterpart, §22.7 row 3),
 *    inserts the kind-5 `dm_message` (caption, countdown **not** started — the upper bound
 *    `ceil_minute(deadline_hour + timer)`, D26) and the kind-5 `dm_outbound_item` (L0 with a zero
 *    key slot, the object's TTL bucket in `ttl_seconds`), then the object, its blobs and its
 *    fragments. No ratchet step, no descriptor enqueue: the item waits for `MEDIA-READY`, and if
 *    no usable session exists then, it waits in `dm_pending_send` like a text (§6.3's last
 *    paragraph).
 *  - `MEDIA-FEED` (§6.4): the [MediaFeeder] fills the outbox from the files, per ordinal, within
 *    the 32/64 windows.
 *  - `MEDIA-OUTCOME` (§6.4): releases Phase 7 outcomes for `Consumer.MEDIA`; SENT/DEGRADED/final
 *    INDETERMINATE settle the ordinal; an INDETERMINATE with budget left is the identical-bytes
 *    resend as a new op (≤ 2 per ordinal and generation, before `resendNotAfter` and the
 *    deadline); FAILED settles the ordinal, fails the object and the message, and stops the
 *    feeder for it.
 *  - `MEDIA-READY` (§6.4): every ordinal final, none failed — the object is `uploaded`, the
 *    sender's countdown starts (`expire_at_minute` lowered, the only-earlier rule), the descriptor
 *    item is sent by F9's SEND **with the object's TTL and deadline from `media_upload`**
 *    (R-MT4 — never `ttlFor` of the conversation's current timer), and the `M_c` orphan rule is
 *    offered its producer.
 *  - `MEDIA-DEADLINE` (§6.4): an object still `uploading` at `deadline_hour` fails, the countdown
 *    starts, the orphan rule is offered; a retry after it answers `DEADLINE_PASSED`.
 *
 * A file whose hash does not match its row fails the object with **no** failed ordinal — the
 * ciphertext is gone — and `retryMedia` answers `NOT_RETRYABLE` for it (§6.4; the store's
 * [RetryResult] extension, F-S5-7 in §22.8).
 *
 * All calls run on the DM actor (§13.7); nothing here logs or touches the network beyond the
 * outbox the feeder enqueues (G-DM2's allowlist names `MediaFeeder`; the steps here only read
 * and write rows).
 */
internal class MediaSteps(
    private val database: SyncDatabase,
    private val sync: DmSyncPorts,
    private val crypto: DmCrypto,
    private val envelopes: DmEnvelopes,
    private val material: ContactMaterial,
    private val relays: RelaySetResolver,
    private val sendStep: SendStep,
    private val feeder: MediaFeeder,
    private val opIds: MediaOpId,
    private val clock: DmClock,
    private val random: DmRandom,
    private val contexts: SelfContexts,
    private val mediaOrphans: MediaOrphanSteps,
) {
    private val contacts = ContactStore()
    private val messages = MessageStore()
    private val objects = MediaObjects(org.ghost.media.store.MediaFragments())
    private val mediaFragments = org.ghost.media.store.MediaFragments()
    private val expiry = ExpiryClock(database, clock)

    /** What the preparation (media worker) hands `MEDIA-COMMIT`; nothing here is key material. */
    class CommitRequest(
        val contactId: ByteArray,
        val kind: MediaKind,
        val viewOnce: Boolean,
        val classCode: Int,
        val objectId: ByteArray,
        val manifestHash: ByteArray,
        val caption: ByteArray,
        /** `key_env` (60 bytes) bound to `(out, contactId, objectId, manifestHash)`. */
        val keyEnv: ByteArray,
        val manifestBlob: ByteArray,
        val manifestFile: ByteArray,
        val fragmentHashes: List<ByteArray>,
        val fragmentFiles: List<ByteArray>,
    )

    /** The expiry clock the media stores read under, for callers outside a pass (R-T7). */
    fun nowE(): Long = expiry.nowSeconds()

    /** `MEDIA-COMMIT`'s refusal answers, beside [SendStep.Outcome] (UNKNOWN_CONTACT, BLOCKED…). */
    enum class CommitOutcome {
        /** The week whose slot table cannot span two operators (ADR-11). */
        NO_REPLICAS,

        /** The DM context is closed or the native library is missing. */
        CRYPTO_UNAVAILABLE,
    }

    sealed interface CommitResult {
        class Committed(val messageId: ByteArray) : CommitResult
        class Refused(val outcome: SendStep.Outcome) : CommitResult
        data object NoReplicas : CommitResult
        data object Unavailable : CommitResult
    }

    /**
     * §6.3's transaction. [self] is the caller's resolved context (before the transaction, per
     * the S8 rule). On [CommitResult.Committed] the caller posts `MEDIA-FEED`; the sealed bytes
     * are already durable files, and the prepared names stay reserved until this returns.
     */
    @Suppress("LongMethod", "ReturnCount")
    fun commit(self: SelfContext, req: CommitRequest): CommitResult {
        val now = clock.nowEpochSeconds()
        val authorMinute = DmTime.floorMinute(now)
        return try {
            database.transaction { tx ->
                val contact = contacts.contact(tx.sql, req.contactId)
                    ?: return@transaction CommitResult.Refused(SendStep.Outcome.UNKNOWN_CONTACT)
                refusalFor(contact.trust)?.let { return@transaction CommitResult.Refused(it) }
                val conversation = contacts.conversation(tx.sql, req.contactId)
                    ?: return@transaction CommitResult.Refused(SendStep.Outcome.UNKNOWN_CONTACT)
                val card = self.content.open(contact.cardEnv ?: return@transaction CommitResult.Refused(
                    SendStep.Outcome.REVOKED,
                ), req.contactId) ?: return@transaction CommitResult.Refused(SendStep.Outcome.CRYPTO_UNAVAILABLE)

                // §6.3 point 1: M_c registered LOCAL with the deposit credentials, and a pending
                // orphan row for M_c goes in the same transaction (§22.7 row 3).
                val derived = crypto.deriveCard(card, ORPHAN_SLOT)
                if (derived !is DmCards.DeriveResult.Ok) {
                    return@transaction CommitResult.Unavailable
                }
                val mediaNs = derived.values.mediaNamespace
                val set = relays.forNamespace(mediaNs, DmTime.week(now))
                    ?: return@transaction CommitResult.NoReplicas
                try {
                    sync.namespaces.register(
                        tx = tx,
                        namespace = NamespaceId(mediaNs),
                        consumer = Consumer.MEDIA,
                        relays = set.map { it.relay }.toSet(),
                        listen = false,
                        capabilitySource = CapabilitySource.LOCAL,
                    )
                    for (slot in set) {
                        val fromCard = material.fromCard(card, slot.slot) ?: continue
                        try {
                            sync.capabilities.put(
                                tx,
                                slot.relay,
                                NamespaceId(mediaNs),
                                CapabilityKind.WRITE,
                                CredentialV3.credential(
                                    CredentialV3.Kind.DEPOSIT,
                                    slot.slot,
                                    mediaNs,
                                    fromCard.deposit,
                                ),
                                DmTime.ceilHour(now) + CREDENTIAL_LIFETIME_SECONDS,
                            )
                        } finally {
                            fromCard.clearSecrets()
                        }
                    }
                } finally {
                    derived.values.clearSecrets()
                }
                contacts.deleteOrphan(tx, mediaNs)

                // §6.3 point 2: the message (countdown not started — D26's upper bound) and the
                // item (the object's bucket rides the item for the pending path, Q27/S3b).
                val ttl = DmTimers.bucketOf(conversation.timerCode)
                val deadlineHour = DmTime.ceilHour(DmTimers.deadlineSeconds(authorMinute, ttl))
                val timerSeconds = DmTimers.timerSeconds(conversation.timerCode)
                val messageId = random.bytes(MESSAGE_ID_BYTES)
                val minuteIndex = messages.nextMinuteIndex(
                    tx.sql, conversation.conversationId, authorMinute, expiry.nowMinute(tx.sql),
                )
                messages.insertMessage(
                    tx = tx,
                    messageId = messageId,
                    conversationId = conversation.conversationId,
                    outgoing = true,
                    kind = DmContent.Kind.MEDIA.wire,
                    authorMinute = authorMinute,
                    sortMinute = authorMinute,
                    minuteIndex = minuteIndex,
                    timerCode = conversation.timerCode,
                    bodyEnv = self.content.seal(
                        random.bytes(ContentCipher.NONCE_BYTES),
                        messageId,
                        bodyPlain(null, req.caption),
                    ),
                    state = MessageStore.STATE_QUEUED,
                    expireAtMinute = ceilMinute(deadlineHour + timerSeconds),
                    unreadDeadlineMinute = null,
                )
                val descriptorBody = descriptorBody(req)
                val l0 = envelopes.encodeContent(
                    kind = DmContent.Kind.MEDIA,
                    messageId = messageId,
                    authorMinute = authorMinute / DmTime.MINUTE,
                    minuteIndex = minuteIndex,
                    timerCode = conversation.timerCode,
                    timerVersion = conversation.timerVersion,
                    quoteRef = null,
                    body = descriptorBody,
                    contactId = req.contactId,
                    offerRootGen = 0,
                    offerEnv = EMPTY,
                    revocation = EMPTY,
                    sessionReset = false,
                    pqKey = null,
                    pqKeyFirst = false,
                )
                val encoded = when (l0) {
                    is DmContent.Encoded.Ok -> l0
                    DmContent.Encoded.Oversize ->
                        throw IllegalStateException("a media descriptor L0 does not fit its bucket")
                    DmContent.Encoded.NonCanonical,
                    DmContent.Encoded.StateCorrupt,
                    DmContent.Encoded.Unavailable,
                    -> return@transaction CommitResult.Unavailable
                }
                messages.insertItem(
                    tx = tx,
                    itemId = messageId,
                    contactId = req.contactId,
                    messageRef = messageId,
                    kind = DmContent.Kind.MEDIA.wire,
                    control = null,
                    l0Env = self.content.seal(random.bytes(ContentCipher.NONCE_BYTES), messageId, encoded.l0),
                    deadlineHour = deadlineHour,
                    state = MessageStore.ITEM_PENDING,
                    ttlSeconds = ttl.seconds.toLong(),
                )

                // §6.3 points 3 and 4: the object, one blob row per file, the fragments.
                objects.insertOutgoing(
                    tx,
                    NewOutgoing(
                        descriptor = MediaDescriptor(
                            req.objectId, req.kind, req.viewOnce, req.classCode, req.manifestHash,
                        ),
                        destId = req.contactId,
                        keyEnv = req.keyEnv,
                        messageId = messageId,
                        namespaceId = mediaNs,
                        ttlSeconds = ttl.seconds.toLong(),
                        deadlineHour = deadlineHour,
                    ),
                )
                org.ghost.media.store.MediaBlobs(mediaFragments).insert(
                    tx,
                    MediaBlob(req.manifestHash, req.manifestFile, org.ghost.media.store.BlobOrigin.SEALED, null),
                )
                for (i in req.fragmentHashes.indices) {
                    org.ghost.media.store.MediaBlobs(mediaFragments).insert(
                        tx,
                        MediaBlob(
                            req.fragmentHashes[i], req.fragmentFiles[i],
                            org.ghost.media.store.BlobOrigin.SEALED, null,
                        ),
                    )
                }
                mediaFragments.insertSealed(
                    tx, req.objectId, req.classCode, req.manifestHash, req.fragmentHashes,
                )
                CommitResult.Committed(messageId)
            }
        } catch (e: InsufficientReplicasException) {
            CommitResult.NoReplicas
        } catch (e: StorageFullException) {
            CommitResult.Refused(SendStep.Outcome.STORAGE_FULL)
        }
    }

    /** §6.3 point 5 / §13.5 `MEDIA-FEED`'s body: feed every active upload, one transaction. */
    fun feed() {
        val nowE = expiry.nowSeconds()
        database.transaction { tx ->
            val active = objects.activeUploads(tx.sql, nowE, limit = FEED_BATCH)
            for (objectId in active) {
                when (val fed = feeder.feed(tx, objectId, nowE)) {
                    is MediaFeeder.Fed.Ok -> Unit
                    MediaFeeder.Fed.HashMismatch -> failObject(tx, objectId, nowE)
                }
            }
        }
    }

    /** `MEDIA-OUTCOME` (§6.4): drain the media outcomes, then the READY checks they may complete. */
    fun outcomes(): Int {
        val self = contexts.get()
        var released = 0
        // The READY flushes run AFTER the outcome transactions: the descriptor SEND opens
        // transactions of its own (plan, seal-and-enqueue), and SyncDatabase is not reentrant.
        val ready = ArrayList<List<Any>>()
        for (outcome in sync.outbox.outcomes(Consumer.MEDIA, OUTCOME_BATCH)) {
            if (applyOne(outcome, self, ready)) released += 1
        }
        for (item in ready) {
            sendStep.flushMediaDescriptor(
                self = self,
                contactId = item[0] as ByteArray,
                itemId = item[1] as ByteArray,
                ttlSeconds = item[2] as Long,
                deadlineHour = item[3] as Long,
                mediaKeyEnv = item[4] as ByteArray,
            )
        }
        return released
    }

    /** `MEDIA-DEADLINE` (§6.4): time-triggered; a process that was not running applies it at start. */
    fun deadline() {
        // SelfContexts opens its own transaction when cold: resolved before ours (the S8 rule).
        val self = contexts.get()
        val now = clock.nowEpochSeconds()
        val nowE = expiry.nowSeconds()
        database.transaction { tx ->
            for (objectId in objects.pastDeadline(tx.sql, nowE, DEADLINE_BATCH)) {
                objects.markFailed(tx, objectId)
                failObject(tx, objectId, nowE)
                val obj = objects.byId(tx.sql, objectId, nowE)
                val messageId = obj?.messageId
                val upload = objects.upload(tx.sql, objectId, nowE)
                if (messageId != null && upload != null) {
                    val message = messages.message(tx.sql, messageId, expiry.nowMinute(tx.sql)) ?: continue
                    // The countdown anchors at the upload's end — the deadline hour (D26): a pass
                    // that runs late lowers to the same value the upper bound already carried.
                    messages.lowerExpireAt(tx, messageId, countdownMinute(upload.deadlineHour, message.timerCode))
                }
                val contact = obj?.destId ?: continue
                mediaOrphans.recordIfOrphaned(tx, self, contact, now)
            }
        }
    }

    // ---------------------------------------------------------------- internals

    private fun applyOne(
        outcome: org.ghost.sync.api.OutboundOutcome,
        self: SelfContext?,
        ready: MutableList<List<Any>>,
    ): Boolean {
        val now = clock.nowEpochSeconds()
        val nowE = expiry.nowSeconds()
        return database.transaction { tx ->
            if (!sync.outbox.release(tx, outcome.operationId)) return@transaction false
            val op = mediaFragments.op(tx.sql, outcome.operationId.toByteArray(), nowE)
                ?: return@transaction true // the message was deleted: the release stands, counted.
            val upload = objects.upload(tx.sql, op.objectId, nowE) ?: return@transaction true
            val contactId = objects.byId(tx.sql, op.objectId, nowE)?.destId ?: return@transaction true
            when (outcome.outcome) {
                Outcome.SENT -> settle(tx, op, UploadState.SENT, self, contactId, ready, nowE)
                Outcome.DEGRADED -> settle(tx, op, UploadState.DEGRADED, self, contactId, ready, nowE)
                Outcome.INDETERMINATE -> {
                    val resendNotAfter = outcome.resendNotAfterEpochSeconds
                    val mayResend = op.resendCount < MediaLimits.MAX_RESENDS &&
                        resendNotAfter != null &&
                        now < resendNotAfter &&
                        now < upload.deadlineHour
                    if (mayResend && feeder.resend(tx, op.objectId, op.ordinal, op.retryGen, op.resendCount + 1, nowE)) {
                        // The ordinal stays open; the new op is the identical bytes.
                    } else {
                        settle(tx, op, UploadState.INDETERMINATE, self, contactId, ready, nowE)
                    }
                }
                Outcome.FAILED -> {
                    mediaFragments.settle(tx, op.objectId, op.ordinal, UploadState.FAILED)
                    objects.markFailed(tx, op.objectId)
                    failObject(tx, op.objectId, nowE)
                    mediaOrphans.recordIfOrphaned(tx, self, contactId, now)
                }
            }
            true
        }
    }

    /**
     * Settle an ordinal final; when the object turns READY, queue the descriptor's data for the
     * flush that [outcomes] runs after its transactions (§13.5's "in the same pass", not the same
     * transaction — the SEND's own transactions must not nest).
     */
    private fun settle(
        tx: org.ghost.sync.api.SyncTransaction,
        op: org.ghost.media.store.MediaOp,
        to: UploadState,
        self: SelfContext?,
        contactId: ByteArray,
        ready: MutableList<List<Any>>,
        nowE: Long,
    ) {
        mediaFragments.settle(tx, op.objectId, op.ordinal, to)
        val now = clock.nowEpochSeconds()
        if (!mediaFragments.allAcknowledged(tx.sql, op.objectId)) return
        val obj = objects.byId(tx.sql, op.objectId, nowE) ?: return
        if (obj.role != MediaRole.OUT || obj.state != ObjectState.UPLOADING) return
        objects.markUploaded(tx, op.objectId)
        val messageId = obj.messageId ?: return
        val message = messages.message(tx.sql, messageId, expiry.nowMinute(tx.sql)) ?: return
        messages.lowerExpireAt(tx, messageId, countdownMinute(now, message.timerCode))
        // The descriptor SEND in the same pass, with the object's TTL and deadline (R-MT4): queued
        // for after this transaction (the SEND runs transactions of its own).
        val upload = objects.upload(tx.sql, op.objectId, nowE) ?: return
        ready += listOf(contactId, messageId, upload.ttlSeconds, upload.deadlineHour, obj.keyEnv ?: return)
        mediaOrphans.recordIfOrphaned(tx, self, contactId, now)
    }

    /** An object ends `failed` and its message with it; the countdown still waits for READY/deadline. */
    private fun failObject(tx: org.ghost.sync.api.SyncTransaction, objectId: ByteArray, nowE: Long) {
        val messageId = objects.byId(tx.sql, objectId, nowE)?.messageId ?: return
        messages.setItemState(tx, messageId, MessageStore.ITEM_PENDING, STATE_FAILED)
        messages.setMessageState(tx, messageId, MessageStore.STATE_QUEUED, STATE_FAILED)
    }

    private fun countdownMinute(now: Long, timerCode: Int): Long =
        ceilMinute(now + DmTimers.timerSeconds(timerCode))

    /**
     * The next multiple of 60 seconds: the `*_minute` columns are second-aligned timestamps on a
     * minute grid (`CHECK (expire_at_minute % 60 = 0)`), not minute indices — the media tables'
     * hour deadlines compare against the same seconds scale.
     */
    private fun ceilMinute(seconds: Long): Long = -Math.floorDiv(-seconds, DmTime.MINUTE) * DmTime.MINUTE

    private fun refusalFor(trust: ContactStore.Trust): SendStep.Outcome? = when (trust) {
        ContactStore.Trust.BLOCKED -> SendStep.Outcome.BLOCKED
        ContactStore.Trust.REVOKED -> SendStep.Outcome.REVOKED
        ContactStore.Trust.REQUEST -> SendStep.Outcome.REQUEST_NOT_ACCEPTED
        else -> null
    }

    /** §4.1's MEDIA body: d_version, kind, flags, class, object_id, the zero key slot, manifest_hash, caption. */
    private fun descriptorBody(req: CommitRequest): ByteArray {
        val caption = req.caption
        if (caption.size > CAPTION_MAX_BYTES) throw IllegalArgumentException("caption")
        val out = ByteArray(4 + 16 + 32 + 32 + 2 + caption.size)
        out[0] = 1
        out[1] = req.kind.code.toByte()
        out[2] = (if (req.viewOnce) 1 else 0).toByte()
        out[3] = req.classCode.toByte()
        req.objectId.copyInto(out, 4)
        // bytes 20..51: the key slot stays zero (§4.1).
        req.manifestHash.copyInto(out, 52)
        out[84] = (caption.size ushr 8).toByte()
        out[85] = caption.size.toByte()
        caption.copyInto(out, 86)
        return out
    }

    private fun bodyPlain(quoteRef: ByteArray?, body: ByteArray): ByteArray {
        val out = ByteArray(1 + (quoteRef?.size ?: 0) + body.size)
        out[0] = (if (quoteRef != null) FLAG_HAS_QUOTE else 0).toByte()
        var at = 1
        quoteRef?.let { it.copyInto(out, at); at += it.size }
        body.copyInto(out, at)
        return out
    }

    companion object {
        private const val ORPHAN_SLOT: Int = 0
        private const val MESSAGE_ID_BYTES: Int = 16
        private const val CREDENTIAL_LIFETIME_SECONDS: Long = 7L * 86_400L
        private const val FLAG_HAS_QUOTE: Int = 1
        private const val CAPTION_MAX_BYTES: Int = 1_024
        private val EMPTY: ByteArray = ByteArray(0)
        private const val FEED_BATCH: Int = 64
        private const val OUTCOME_BATCH: Int = 64
        private const val DEADLINE_BATCH: Int = 64
        const val STATE_FAILED: String = "failed"
    }
}
