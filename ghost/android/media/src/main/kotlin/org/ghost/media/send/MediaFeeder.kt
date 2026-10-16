package org.ghost.media.send

import org.ghost.media.store.CiphertextFiles
import org.ghost.media.store.MediaBlobs
import org.ghost.media.store.MediaFragments
import org.ghost.media.store.MediaLimits
import org.ghost.media.store.MediaObjects
import org.ghost.media.store.MediaOp
import org.ghost.media.store.MediaStoreException
import org.ghost.sync.api.NamespaceId
import org.ghost.sync.api.Outbox
import org.ghost.sync.api.OutboundBlob
import org.ghost.sync.api.SyncTransaction
import org.ghost.sync.api.TtlBucket
import java.security.MessageDigest

/**
 * The deterministic media operation id of §6.4:
 * `SHA-256("ghost/v1/media/op" || object_id(16) || i16_be(ordinal) || u8(retry_gen) || u8(resend_count))[0..16]`.
 * A port because the label is a derivation label and G-DM3 keeps `ghost/v<n>/` labels out of
 * `:media`: the production implementation lives in `:messaging` (allowlisted), the worlds re-derive
 * through the host build's `testSealBeginWithKey` (§15.6).
 */
fun interface MediaOpId {
    fun of(objectId: ByteArray, ordinal: Int, retryGen: Int, resendCount: Int): ByteArray
}

/**
 * `MediaFeeder` of Phase 11 design §6.4 (`MEDIA-FEED`): fills the Phase 7 outbox from the
 * ciphertext files, per ordinal, lowest first with the manifest (ordinal −1) first, at most
 * [MediaLimits.OPEN_PER_OBJECT] open ordinals of the object and [MediaLimits.OPEN_PER_DEVICE] of
 * the device, each blob hash-verified against its row **before** the operation is enqueued.
 *
 * Deterministic op ids make a repeated feed idempotent at the store ([MediaFragments.enqueue]
 * refuses an ordinal that is not `unsent`, and `Outbox.enqueue` answers `AlreadyEnqueued`), so a
 * crash after the enqueue transaction never double-feeds. A file whose bytes do not match its
 * row's hash is local corruption: the object is `failed` with no ordinal ever fed, which is how
 * `retryMedia` tells it from a FAILED-outcome object (§6.4, F-S5-7 in §22.8).
 *
 * The one relay-visible call is `Outbox.enqueue` — this file is on G-DM2's allowlist by name
 * (§22.5 row 15), like `SendStep`: the feed is caused by the user's own send, never by an
 * arrival (T28). No logging, no clock (§13.1).
 */
class MediaFeeder(
    private val files: CiphertextFiles,
    private val objects: MediaObjects,
    private val fragments: MediaFragments,
    private val blobs: MediaBlobs,
    private val outbox: Outbox,
    private val opIds: MediaOpId,
) {

    /** What one [feed] call decided. */
    sealed interface Fed {
        /** [count] ordinals were enqueued (possibly zero: the windows were full or nothing was unsent). */
        data class Ok(val count: Int) : Fed

        /**
         * A file's bytes did not match its row's hash: the object is `failed` (in this transaction,
         * by the caller's message-failing effect), the feeder fed nothing more.
         */
        data object HashMismatch : Fed
    }

    /**
     * Feeds up to the window bounds. [nowE] is the expiry clock the stores read under (the
     * caller's, R-T7). Returns what was fed; every effect is in [tx].
     */
    fun feed(tx: SyncTransaction, objectId: ByteArray, nowE: Long): Fed {
        val upload = objects.upload(tx.sql, objectId, nowE) ?: return Fed.Ok(0)
        val namespace = NamespaceId(upload.namespaceId)
        val bucket = bucketOf(upload.ttlSeconds)
        var fed = 0
        while (fragments.openCount(tx.sql, objectId) < MediaLimits.OPEN_PER_OBJECT &&
            fragments.openCountOfDevice(tx.sql) < MediaLimits.OPEN_PER_DEVICE
        ) {
            val next = fragments.unsent(tx.sql, objectId, nowE, limit = 1).firstOrNull() ?: break
            val blob = blobs.byHash(tx.sql, next.blobHash)
                ?: throw MediaStoreException(
                    org.ghost.media.store.MediaStoreError.MISSING_ROW,
                    "media_blob",
                )
            val bytes = files.read(blob.fileName)
            if (!MessageDigest.isEqual(digest(bytes), next.blobHash)) {
                objects.markFailed(tx, objectId)
                return Fed.HashMismatch
            }
            val opId = opIds.of(objectId, next.ordinal, upload.retryGen, 0)
            // Phase 7 refuses identical bytes in one namespace (UNIQUE (namespace_id, blob_hash)):
            // a retried ordinal's re-feed collides with its generation-0 op (F-S5-19). The
            // store's answer stands; the op row is written only on the store's acceptance, so a
            // refusal leaves the ordinal unsent for the next pass.
            if (outbox.enqueue(
                    tx,
                    OutboundBlob(
                        org.ghost.sync.api.OperationId(opId),
                        namespace,
                        bytes,
                        bucket,
                        deadlineEpochSeconds = upload.deadlineHour,
                    ),
                ) == org.ghost.sync.api.EnqueueResult.AlreadyEnqueued
            ) {
                // The store owns these bytes already (F-S5-19): this pass is done — breaking, not
                // continuing, or the still-unsent ordinal would spin the loop for ever.
                break
            }
            fragments.enqueue(tx, MediaOp(opId, objectId, next.ordinal, upload.retryGen, 0))
            fed++
        }
        return Fed.Ok(fed)
    }

    /**
     * `MEDIA-OUTCOME`'s identical-bytes resend (§6.4): the same file's bytes under a new op id
     * (`resend_count + 1`, the same ordinal and retry generation), enqueued with the operation in
     * one transaction. False when the bytes no longer match the row (the object is failed first,
     * exactly like [feed]'s hash rule).
     */
    fun resend(
        tx: SyncTransaction,
        objectId: ByteArray,
        ordinal: Int,
        retryGen: Int,
        resendCount: Int,
        nowE: Long,
    ): Boolean {
        val upload = objects.upload(tx.sql, objectId, nowE) ?: return false
        val fragment = fragments.fragment(tx.sql, objectId, ordinal, nowE)
            ?: throw MediaStoreException(org.ghost.media.store.MediaStoreError.MISSING_ROW, "media_fragment")
        val blob = blobs.byHash(tx.sql, fragment.blobHash)
            ?: throw MediaStoreException(org.ghost.media.store.MediaStoreError.MISSING_ROW, "media_blob")
        val bytes = files.read(blob.fileName)
        if (!MessageDigest.isEqual(digest(bytes), fragment.blobHash)) {
            objects.markFailed(tx, objectId)
            return false
        }
        val opId = opIds.of(objectId, ordinal, retryGen, resendCount)
        outbox.enqueue(
            tx,
            OutboundBlob(
                org.ghost.sync.api.OperationId(opId),
                NamespaceId(upload.namespaceId),
                bytes,
                bucketOf(upload.ttlSeconds),
                deadlineEpochSeconds = upload.deadlineHour,
            ),
        )
        fragments.insertResend(tx, MediaOp(opId, objectId, ordinal, retryGen, resendCount))
        return true
    }

    private fun digest(bytes: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(bytes)

    private fun bucketOf(seconds: Long): TtlBucket =
        TtlBucket.entries.firstOrNull { it.seconds.toLong() == seconds }
            ?: throw IllegalStateException("unknown ttl bucket")
}
