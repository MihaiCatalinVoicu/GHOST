package org.ghost.media.store

/**
 * The rows of the media tables, as the stores return them. **No `toString` shows a byte** (T3): an object id, a hash, a
 * file name and a wrapped key are secrets or identifiers a crash report must not carry, so each row prints its state and
 * kind and nothing else. The tests apply `assertRedacted` to every row type (no decimal list, hex or Base64 of a field,
 * and no `[B@`).
 */

/** A `media_object` row, as the expiry-filtered reads return it: [state] and [keyEnv] are the **effective** ones (see [MediaObjects]). */
class MediaObject(
    val objectId: ByteArray,
    val role: MediaRole,
    val destId: ByteArray,
    val kind: MediaKind,
    val viewOnce: Boolean,
    val classCode: Int,
    val manifestHash: ByteArray,
    /** The wrapped file key (`key_env`, 60 bytes), or null once it was erased (T45). Never printed. */
    val keyEnv: ByteArray?,
    val state: ObjectState,
    val messageId: ByteArray?,
    val decodeFailures: Int,
    /** The descriptor blob's relay expiry, as an hour (Unix seconds); null for an outgoing object. */
    val incompleteAfterHour: Long?,
) {
    override fun toString(): String = "MediaObject(role=$role, kind=$kind, class=$classCode, state=$state)"
}

/** A `media_upload` row: the bucket, deadline and retry generation fixed at `MEDIA-COMMIT` (R-MT4). */
class MediaUpload(
    val objectId: ByteArray,
    val namespaceId: ByteArray,
    val ttlSeconds: Long,
    val deadlineHour: Long,
    val retryGen: Int,
) {
    override fun toString(): String = "MediaUpload(ttl=$ttlSeconds, retryGen=$retryGen)"
}

/** A `media_fragment` row: [ordinal] -1 is the manifest; [uploadState] is null for a fragment of an incoming object. */
class MediaFragment(
    val objectId: ByteArray,
    val ordinal: Int,
    val blobHash: ByteArray,
    val state: FragmentState,
    val uploadState: UploadState?,
) {
    override fun toString(): String = "MediaFragment(ordinal=$ordinal, state=$state, upload=$uploadState)"
}

/** A `media_blob` row: [fileName] is the 16 random bytes whose hex is the name of the file in the store. */
class MediaBlob(
    val blobHash: ByteArray,
    val fileName: ByteArray,
    val origin: BlobOrigin,
    /** The last day a pooled blob is kept (an ingested one); null for a sealed one. */
    val retainUntilDay: Long?,
) {
    override fun toString(): String = "MediaBlob(origin=$origin)"
}

/** A `media_outbound_op` row: the Phase 7 operation that carried (object, ordinal) in a retry generation and resend. */
class MediaOp(
    val operationId: ByteArray,
    val objectId: ByteArray,
    val ordinal: Int,
    val retryGen: Int,
    val resendCount: Int,
) {
    override fun toString(): String = "MediaOp(ordinal=$ordinal, retryGen=$retryGen, resend=$resendCount)"
}

/**
 * What a descriptor says about its object (the part of the kind-5 L0 the store keeps, §4.1 and §7.2): the codec that parses
 * the L0 is Rust's (slice S1, S2), so the store takes the parsed fields.
 */
class MediaDescriptor(
    val objectId: ByteArray,
    val kind: MediaKind,
    val viewOnce: Boolean,
    val classCode: Int,
    val manifestHash: ByteArray,
) {
    init {
        Fields.objectId(objectId)
        Fields.range("media_object.class_code", classCode.toLong(), 0, MediaLimits.CLASSES.size - 1L)
        Fields.hash("media_object.manifest_hash", manifestHash)
        if (kind == MediaKind.IMAGE && classCode != 0) throw MediaStoreException(MediaStoreError.BAD_VALUE, "media_object.class_code")
    }

    override fun toString(): String = "MediaDescriptor(kind=$kind, class=$classCode)"
}

/** What `MEDIA-COMMIT` inserts for an outgoing object (§6.3 point 3 and 4): the object and its upload. */
class NewOutgoing(
    val descriptor: MediaDescriptor,
    val destId: ByteArray,
    /** `key_env` bound to (out, destination, object, manifest), 60 bytes. */
    val keyEnv: ByteArray,
    val messageId: ByteArray,
    val namespaceId: ByteArray,
    val ttlSeconds: Long,
    val deadlineHour: Long,
) {
    init {
        Fields.bytes("media_object.dest_id", destId, 16)
        Fields.bytes("media_object.key_env", keyEnv, 60)
        Fields.bytes("media_object.message_id", messageId, 16)
        Fields.bytes("media_upload.namespace_id", namespaceId, 32)
        if (ttlSeconds !in MediaLimits.TTL_BUCKETS) throw MediaStoreException(MediaStoreError.BAD_VALUE, "media_upload.ttl_seconds")
        Fields.hour("media_upload.deadline_hour", deadlineHour)
    }

    override fun toString(): String = "NewOutgoing(kind=${descriptor.kind}, class=${descriptor.classCode}, ttl=$ttlSeconds)"
}
