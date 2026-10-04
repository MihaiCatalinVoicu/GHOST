package org.ghost.media.store

import org.ghost.storage.SqlExecutor
import org.ghost.sync.api.SyncTransaction

/**
 * The object-side rows of the media schema (Phase 11 design §6.3, §7.2, §7.6, §11, §13.6): `media_object` (one row per
 * media object, ours or theirs) and `media_upload` (the bucket, deadline and retry generation of an outgoing one), and the
 * transitions of §7.6, each of which the schema checks again with a trigger.
 *
 * **Every read of an object carries the expiry filter** (§10.7 point 4, as the media tables have it). A media row has no
 * deadline column of its own for its life: it dies with its message, so a read joins `dm_message` and hides the object when
 * `delete_at_minute <= :now_e`, before the sweep that deletes it (physical deletion lags: a frozen process, a deferred
 * alarm). Two deadlines are the object's own, and a read **applies them as the maintenance that has not run yet would**:
 * an incoming object still `awaiting` or `fetching` past its `incomplete_after_hour` is declared loss (§7.5), so it reads as
 * `incomplete`, with no key and no fragments, and an outgoing object still `uploading` past its `deadline_hour` reads as
 * `failed` (§6.4). The lint of mutant ME-16 (`MediaDaoQueries` in `:storage`) runs every read against a world that still
 * holds the expired rows and one that does not and requires the two to be indistinguishable.
 *
 * **Every write goes through the caller's [SyncTransaction]** and there is no `REPLACE` and no upsert (gate G-DM4).
 * Transitions are guarded `UPDATE`s whose changed-row count decides: a row that is not in a state the machine moves from is
 * [MediaStoreError.ILLEGAL_TRANSITION], a row that is not there [MediaStoreError.MISSING_ROW]. Whoever moves an object to a
 * state that holds no key ([ObjectState.keyless]) erases its `key_env` in the same statement (the CHECK of §13.6 requires
 * it), and the caller follows every erasure with F9 §10.7's checkpoint (§11.1): this class writes rows and runs none.
 */
class MediaObjects(private val fragments: MediaFragments) {

    // ---------------------------------------------------------------- reads (expiry-filtered)

    /** One object, if it is there and its message has not expired. [MediaObject.state] and [MediaObject.keyEnv] are the effective ones. */
    fun byId(sql: SqlExecutor, objectId: ByteArray, nowE: Long): MediaObject? {
        var out: MediaObject? = null
        sql.query(BY_ID, listOf(nowE, nowE, nowE, Fields.objectId(objectId), nowE)) { out = readObject(it) }
        return out
    }

    /** The object of a message, if the message has not expired (the display path: a message row names its media). */
    fun byMessage(sql: SqlExecutor, messageId: ByteArray, nowE: Long): MediaObject? {
        var out: MediaObject? = null
        sql.query(BY_MESSAGE, listOf(nowE, nowE, nowE, Fields.bytes("media_object.message_id", messageId, 16), nowE)) { out = readObject(it) }
        return out
    }

    /** The upload row of a live object: its bucket and deadline, from which the descriptor takes its TTL (R-MT4). */
    fun upload(sql: SqlExecutor, objectId: ByteArray, nowE: Long): MediaUpload? {
        var out: MediaUpload? = null
        sql.query(UPLOAD_OF, listOf(Fields.objectId(objectId), nowE)) {
            out = MediaUpload(it.blob(0), it.blob(1), it.long(2), it.long(3), it.long(4).toInt())
        }
        return out
    }

    /** Outgoing objects the feeder works on: `uploading` and not past their deadline, the earliest deadline first. */
    fun activeUploads(sql: SqlExecutor, nowE: Long, limit: Int): List<ByteArray> =
        ids(sql, ACTIVE_UPLOADS, listOf(nowE, nowE, limit.toLong()))

    /** Incoming objects the media actor works on: `awaiting` or `fetching` and not past `incomplete_after_hour`. */
    fun pendingDownloads(sql: SqlExecutor, nowE: Long, limit: Int): List<ByteArray> =
        ids(sql, PENDING_DOWNLOADS, listOf(nowE, nowE, limit.toLong()))

    /** Incoming objects whose every blob is here and whose full validation pass is due (`complete`, §7.3). */
    fun toVerify(sql: SqlExecutor, nowE: Long, limit: Int): List<ByteArray> = ids(sql, TO_VERIFY, listOf(nowE, limit.toLong()))

    /** View-once objects left in `viewing` (a crash or a lock after the key was erased): `VIEW-ONCE-CLOSE` runs for them at start (§11.2). */
    fun viewing(sql: SqlExecutor, nowE: Long, limit: Int): List<ByteArray> = ids(sql, VIEWING, listOf(nowE, limit.toLong()))

    // ---------------------------------------------------------------- reads (bounds)

    /** Whether an object with this id exists, expired or not: a second descriptor for it is `drop(duplicate_object)` (§7.2). */
    fun exists(sql: SqlExecutor, objectId: ByteArray): Boolean = sql.queryCount(EXISTS, listOf(Fields.objectId(objectId))) > 0

    /** Whether an object is already attached to this message (one object per message, the unique index of §13.6). */
    fun existsForMessage(sql: SqlExecutor, messageId: ByteArray): Boolean =
        sql.queryCount(EXISTS_FOR_MESSAGE, listOf(Fields.bytes("media_object.message_id", messageId, 16))) > 0

    /** The objects of the given messages (live or not): the ones `MediaPort.onMessagesDeleted` deletes. */
    fun objectsOfMessage(sql: SqlExecutor, messageId: ByteArray): List<ByteArray> =
        ids(sql, OBJECTS_OF_MESSAGE, listOf(Fields.bytes("media_object.message_id", messageId, 16)))

    // ---------------------------------------------------------------- reads (sweeps: they name exactly the expired rows)

    /** Incoming objects past `incomplete_after_hour` that `MEDIA-GC` declares `incomplete` (§7.5). */
    fun incompleteDue(sql: SqlExecutor, nowE: Long, limit: Int): List<ByteArray> = ids(sql, INCOMPLETE_DUE, listOf(nowE, nowE, limit.toLong()))

    /** Outgoing objects still `uploading` past `deadline_hour` that `MEDIA-DEADLINE` fails (§6.4). */
    fun pastDeadline(sql: SqlExecutor, nowE: Long, limit: Int): List<ByteArray> = ids(sql, PAST_DEADLINE, listOf(nowE, nowE, limit.toLong()))

    // ---------------------------------------------------------------- writes: creation

    /**
     * `MEDIA-COMMIT` (§6.3 points 3 and 4): the outgoing object (`uploading`, with its key) and its upload row. The message
     * row exists already (the foreign key), and the blob and fragment rows follow ([MediaBlobs.insert],
     * [MediaFragments.insertSealed]).
     */
    fun insertOutgoing(tx: SyncTransaction, outgoing: NewOutgoing) {
        val d = outgoing.descriptor
        if (exists(tx.sql, d.objectId) || existsForMessage(tx.sql, outgoing.messageId)) throw MediaStoreException(MediaStoreError.ROW_EXISTS, "media_object")
        tx.sql.exec(
            "INSERT INTO media_object(object_id, role, dest_id, kind, view_once, class_code, manifest_hash, key_env, state, message_id, " +
                "decode_failures, incomplete_after_hour) VALUES (?, 'out', ?, ?, ?, ?, ?, ?, 'uploading', ?, 0, NULL)",
            listOf(
                d.objectId, outgoing.destId, d.kind.code.toLong(), Fields.flag(d.viewOnce), d.classCode.toLong(), d.manifestHash,
                outgoing.keyEnv, outgoing.messageId,
            ),
        )
        tx.sql.exec(
            "INSERT INTO media_upload(object_id, namespace_id, ttl_seconds, deadline_hour, retry_gen) VALUES (?, ?, ?, ?, 0)",
            listOf(d.objectId, outgoing.namespaceId, outgoing.ttlSeconds, outgoing.deadlineHour),
        )
    }

    /**
     * Inside F9 `RECV` or the held replay (§7.2): a kind-5 L0 from a contact creates the message row as F9 does and,
     * through this, an incoming object `awaiting` with the `key_env` that `decrypt` or `sessionInbound` returned. A second
     * descriptor naming an existing `object_id` is `drop(duplicate_object)` for the object ([DescriptorResult.DUPLICATE_OBJECT],
     * nothing written; the message follows F9's dedup). **Never called for a descriptor in a request** (D28): the `key_env` is
     * dropped unstored and no object exists, which is the caller's rule and is tested at the `:messaging` boundary.
     * [incompleteAfterHour] is the relay expiry of the descriptor blob.
     */
    fun onDescriptor(
        tx: SyncTransaction,
        messageId: ByteArray,
        contactId: ByteArray,
        descriptor: MediaDescriptor,
        keyEnv: ByteArray,
        incompleteAfterHour: Long,
    ): DescriptorResult {
        Fields.bytes("media_object.message_id", messageId, 16)
        Fields.bytes("media_object.dest_id", contactId, 16)
        Fields.bytes("media_object.key_env", keyEnv, 60)
        Fields.hour("media_object.incomplete_after_hour", incompleteAfterHour)
        if (exists(tx.sql, descriptor.objectId)) return DescriptorResult.DUPLICATE_OBJECT
        if (existsForMessage(tx.sql, messageId)) throw MediaStoreException(MediaStoreError.ROW_EXISTS, "media_object.message_id")
        tx.sql.exec(
            "INSERT INTO media_object(object_id, role, dest_id, kind, view_once, class_code, manifest_hash, key_env, state, message_id, " +
                "decode_failures, incomplete_after_hour) VALUES (?, 'in', ?, ?, ?, ?, ?, ?, 'awaiting', ?, 0, ?)",
            listOf(
                descriptor.objectId, contactId, descriptor.kind.code.toLong(), Fields.flag(descriptor.viewOnce),
                descriptor.classCode.toLong(), descriptor.manifestHash, keyEnv, messageId, incompleteAfterHour,
            ),
        )
        return DescriptorResult.CREATED
    }

    // ---------------------------------------------------------------- writes: the outgoing machine

    /** `MEDIA-READY` (§6.4): every ordinal is final and none failed. */
    fun markUploaded(tx: SyncTransaction, objectId: ByteArray) = move(tx, objectId, listOf(ObjectState.UPLOADING), ObjectState.UPLOADED)

    /** `MEDIA-OUTCOME` on a FAILED ordinal, and `MEDIA-DEADLINE` for an object still `uploading` at its deadline. */
    fun markFailed(tx: SyncTransaction, objectId: ByteArray) = move(tx, objectId, listOf(ObjectState.UPLOADING), ObjectState.FAILED)

    /**
     * The user's retry of a failed object (§6.4): the retry generation goes up by one (at most [MediaLimits.MAX_RETRIES]),
     * the object returns to `uploading` and its `failed` ordinals to `unsent`; `sent`, `degraded` and `indeterminate`
     * ordinals are **not** stored again. The generation is written first: the schema lets a fragment leave `failed` only
     * once the object's generation has moved past the one of its last operation.
     */
    fun retryUpload(tx: SyncTransaction, objectId: ByteArray, nowE: Long): RetryResult {
        val object_ = byId(tx.sql, objectId, nowE) ?: return RetryResult.NO_SUCH_OBJECT
        val upload = upload(tx.sql, objectId, nowE) ?: return RetryResult.NOT_FAILED
        if (object_.state != ObjectState.FAILED) return RetryResult.NOT_FAILED
        if (upload.deadlineHour <= nowE) return RetryResult.DEADLINE_PASSED
        if (upload.retryGen >= MediaLimits.MAX_RETRIES) return RetryResult.RETRIES_EXHAUSTED
        tx.sql.exec("UPDATE media_upload SET retry_gen = retry_gen + 1 WHERE object_id = ?", listOf(objectId))
        move(tx, objectId, listOf(ObjectState.FAILED), ObjectState.UPLOADING)
        tx.sql.exec("UPDATE media_fragment SET upload_state = 'unsent' WHERE object_id = ? AND upload_state = 'failed'", listOf(objectId))
        return RetryResult.RETRIED
    }

    /** The sender's uploads of the object are over: its upload row goes (§5.1: when all of a contact's uploads are over, its `media_upload` rows are deleted and the `M_c` orphan rule applies). */
    fun deleteUpload(tx: SyncTransaction, objectId: ByteArray): Boolean =
        tx.sql.execUpdate("DELETE FROM media_upload WHERE object_id = ?", listOf(Fields.objectId(objectId))) == 1

    // ---------------------------------------------------------------- writes: the incoming machine

    /** `MEDIA-BIND` (§7.2): the fragment rows are in, the object is `fetching`. */
    fun markFetching(tx: SyncTransaction, objectId: ByteArray) = move(tx, objectId, listOf(ObjectState.AWAITING), ObjectState.FETCHING)

    /** The last `expected` fragment row was bound: the object is `complete` and `MEDIA-VERIFY` is due (§7.2). */
    fun markComplete(tx: SyncTransaction, objectId: ByteArray) = move(tx, objectId, listOf(ObjectState.FETCHING), ObjectState.COMPLETE)

    /** `MEDIA-VERIFY` passed (§7.3): the object may be shown. */
    fun markVerified(tx: SyncTransaction, objectId: ByteArray) = move(tx, objectId, listOf(ObjectState.COMPLETE), ObjectState.VERIFIED)

    /**
     * A manifest that does not open, a validation that fails, a file found corrupted after `verified` (§7.2, §7.3): the
     * object is `corrupt`, its key is erased and its references released in the same transaction (an ingested blob that no
     * row names returns to the pool with its original retention, a sealed one is deleted). Returns the blob rows deleted;
     * the files go with the reconcile after the commit, and the caller checkpoints (§11.1).
     */
    fun markCorrupt(tx: SyncTransaction, objectId: ByteArray): Int {
        move(tx, objectId, listOf(ObjectState.AWAITING, ObjectState.COMPLETE, ObjectState.VERIFIED), ObjectState.CORRUPT)
        return fragments.release(tx, listOf(objectId), ReleasePolicy.RELEASE)
    }

    /** An object not `complete` by its `incomplete_after_hour` is declared loss (§7.5): the same release as [markCorrupt]. */
    fun markIncomplete(tx: SyncTransaction, objectId: ByteArray): Int {
        move(tx, objectId, listOf(ObjectState.AWAITING, ObjectState.FETCHING), ObjectState.INCOMPLETE)
        return fragments.release(tx, listOf(objectId), ReleasePolicy.RELEASE)
    }

    /** Two sandbox failures on one object (CS-M8, §9.2): it is never offered to the sandbox again. */
    fun markUndecodable(tx: SyncTransaction, objectId: ByteArray) = move(tx, objectId, listOf(ObjectState.VERIFIED), ObjectState.UNDECODABLE)

    /**
     * One sandbox failure on a verified object (a timeout, a dead instance, an out-of-range answer): the count goes up and
     * the new value is returned. At [MediaLimits.MAX_DECODE_FAILURES] the object is undecodable, which the caller records
     * with [markUndecodable]; a third failure is [MediaStoreError.LIMIT].
     */
    fun recordDecodeFailure(tx: SyncTransaction, objectId: ByteArray): Int {
        val changed = tx.sql.execUpdate(
            "UPDATE media_object SET decode_failures = decode_failures + 1 WHERE object_id = ? AND state = 'verified' AND decode_failures < ?",
            listOf(Fields.objectId(objectId), MediaLimits.MAX_DECODE_FAILURES.toLong()),
        )
        if (changed != 1) {
            throw MediaStoreException(
                if (rawState(tx.sql, objectId) == ObjectState.VERIFIED) MediaStoreError.LIMIT else MediaStoreError.ILLEGAL_TRANSITION,
                "media_object.decode_failures",
            )
        }
        return tx.sql.queryCount(DECODE_FAILURES_OF, listOf(objectId))
    }

    // ---------------------------------------------------------------- writes: view-once and erasure

    /**
     * `VIEW-ONCE-OPEN` (§11.2), the row half: a `verified` view-once object with a key becomes `viewing` and its key is
     * erased, in this statement. The caller read the key with [byId] and moved it into a native reader **before** (the key
     * leaves the database only after the reader holds it), commits, checkpoints, and only then returns the handle to the UI.
     */
    fun openViewOnce(tx: SyncTransaction, objectId: ByteArray) {
        val changed = tx.sql.execUpdate(
            "UPDATE media_object SET state = 'viewing', key_env = NULL WHERE object_id = ? AND state = 'verified' AND view_once = 1 AND key_env IS NOT NULL",
            listOf(Fields.objectId(objectId)),
        )
        if (changed != 1) throw missing(tx.sql, objectId)
    }

    /**
     * `VIEW-ONCE-CLOSE` (§11.2): `viewing` → `viewed`, and the object's fragment rows and every blob no row names any more
     * are erased, whatever their origin (the file goes with the reconcile). Returns the blob rows deleted.
     */
    fun closeViewOnce(tx: SyncTransaction, objectId: ByteArray): Int {
        move(tx, objectId, listOf(ObjectState.VIEWING), ObjectState.VIEWED)
        return fragments.release(tx, listOf(objectId), ReleasePolicy.ERASE)
    }

    /**
     * The sender's view-once cleanup (§6.4, §11.2): once the descriptor has a final outcome other than FAILED (or the
     * deadline passed after a FAILED one) the sender erases its copy — the key now, the fragment rows and the blobs no row
     * names any more with them. The object row stays with its state (`uploaded` or `failed`) and no key. Returns the blob
     * rows deleted.
     */
    fun eraseSenderCopy(tx: SyncTransaction, objectId: ByteArray): Int {
        val changed = tx.sql.execUpdate(
            "UPDATE media_object SET key_env = NULL WHERE object_id = ? AND role = 'out' AND view_once = 1",
            listOf(Fields.objectId(objectId)),
        )
        if (changed != 1) throw missing(tx.sql, objectId)
        return fragments.release(tx, listOf(objectId), ReleasePolicy.ERASE)
    }

    /**
     * `SWEEP` and the contact deletion (§11.1, `MediaPort.onMessagesDeleted`): every object of [messageIds] is deleted with
     * its upload, fragment and operation rows (the foreign keys cascade) and then every blob no row names any more,
     * whatever its origin — a blob another live object still names stays until that object releases it. The `key_env` of
     * each object goes with its row; the caller checkpoints (§11.1) and the files go with the reconcile. Returns the objects deleted.
     */
    fun deleteObjectsOfMessages(tx: SyncTransaction, messageIds: List<ByteArray>): Int {
        var deleted = 0
        for (chunk in messageIds.chunked(CHUNK)) {
            val messages = chunk.map { Fields.bytes("media_object.message_id", it, 16) }
            val hashes = LinkedHashSet<List<Byte>>()
            for (message in messages) {
                for (objectId in objectsOfMessage(tx.sql, message)) for (hash in fragments.hashesOf(tx.sql, objectId)) hashes += hash.toList()
            }
            deleted += tx.sql.execUpdate("DELETE FROM media_object WHERE message_id IN (${Fields.marks(messages.size)})", messages)
            fragments.deleteUnnamed(tx, hashes.map { it.toByteArray() }, ReleasePolicy.ERASE)
        }
        return deleted
    }

    // ---------------------------------------------------------------- internals

    private fun move(tx: SyncTransaction, objectId: ByteArray, from: List<ObjectState>, to: ObjectState) {
        for (state in from) check(state.allows(to)) { "a transition the machine of §7.6 does not have" }
        val clearKey = if (to.keyless) ", key_env = NULL" else ""
        val changed = tx.sql.execUpdate(
            "UPDATE media_object SET state = ?$clearKey WHERE object_id = ? AND state IN (${Fields.marks(from.size)})",
            listOf(to.code, Fields.objectId(objectId)) + from.map { it.code },
        )
        if (changed != 1) throw missing(tx.sql, objectId)
    }

    /** The error for a guarded write that changed nothing: the row is not there, or it is not in a state the machine moves from. */
    private fun missing(sql: SqlExecutor, objectId: ByteArray): MediaStoreException =
        MediaStoreException(if (exists(sql, objectId)) MediaStoreError.ILLEGAL_TRANSITION else MediaStoreError.MISSING_ROW, "media_object.state")

    /** The state as stored, whatever the age of the object. */
    private fun rawState(sql: SqlExecutor, objectId: ByteArray): ObjectState? {
        var out: ObjectState? = null
        sql.query(RAW_STATE, listOf(objectId)) { out = ObjectState.of(it.string(0)) }
        return out
    }

    private fun ids(sql: SqlExecutor, query: String, args: List<Any?>): List<ByteArray> {
        val out = ArrayList<ByteArray>()
        sql.query(query, args) { out += it.blob(0) }
        return out
    }

    private fun readObject(row: SqlExecutor.Row): MediaObject = MediaObject(
        objectId = row.blob(0),
        role = MediaRole.of(row.string(1)),
        destId = row.blob(2),
        kind = MediaKind.of(row.long(3).toInt()),
        viewOnce = row.long(4) == 1L,
        classCode = row.long(5).toInt(),
        manifestHash = row.blob(6),
        keyEnv = if (row.isNull(7)) null else row.blob(7),
        state = ObjectState.of(row.string(8)),
        messageId = if (row.isNull(9)) null else row.blob(9),
        decodeFailures = row.long(10).toInt(),
        incompleteAfterHour = if (row.isNull(11)) null else row.long(11),
    )

    private companion object {
        const val CHUNK = 400

        const val BY_ID =
            "SELECT o.object_id, o.role, o.dest_id, o.kind, o.view_once, o.class_code, o.manifest_hash, " +
                "CASE WHEN o.state IN ('awaiting', 'fetching') AND o.incomplete_after_hour <= ? THEN NULL ELSE o.key_env END, " +
                "CASE WHEN o.state = 'uploading' AND u.deadline_hour <= ? THEN 'failed' " +
                "WHEN o.state IN ('awaiting', 'fetching') AND o.incomplete_after_hour <= ? THEN 'incomplete' ELSE o.state END, " +
                "o.message_id, o.decode_failures, o.incomplete_after_hour " +
                "FROM media_object o LEFT JOIN media_upload u ON u.object_id = o.object_id " +
                "LEFT JOIN dm_message m ON m.message_id = o.message_id " +
                "WHERE o.object_id = ? AND (m.message_id IS NULL OR m.delete_at_minute IS NULL OR m.delete_at_minute > ?)"

        const val BY_MESSAGE =
            "SELECT o.object_id, o.role, o.dest_id, o.kind, o.view_once, o.class_code, o.manifest_hash, " +
                "CASE WHEN o.state IN ('awaiting', 'fetching') AND o.incomplete_after_hour <= ? THEN NULL ELSE o.key_env END, " +
                "CASE WHEN o.state = 'uploading' AND u.deadline_hour <= ? THEN 'failed' " +
                "WHEN o.state IN ('awaiting', 'fetching') AND o.incomplete_after_hour <= ? THEN 'incomplete' ELSE o.state END, " +
                "o.message_id, o.decode_failures, o.incomplete_after_hour " +
                "FROM media_object o LEFT JOIN media_upload u ON u.object_id = o.object_id " +
                "LEFT JOIN dm_message m ON m.message_id = o.message_id " +
                "WHERE o.message_id = ? AND (m.message_id IS NULL OR m.delete_at_minute IS NULL OR m.delete_at_minute > ?)"

        const val UPLOAD_OF =
            "SELECT u.object_id, u.namespace_id, u.ttl_seconds, u.deadline_hour, u.retry_gen FROM media_upload u " +
                "JOIN media_object o ON o.object_id = u.object_id LEFT JOIN dm_message m ON m.message_id = o.message_id " +
                "WHERE u.object_id = ? AND (m.message_id IS NULL OR m.delete_at_minute IS NULL OR m.delete_at_minute > ?)"

        const val ACTIVE_UPLOADS =
            "SELECT o.object_id FROM media_object o JOIN media_upload u ON u.object_id = o.object_id " +
                "LEFT JOIN dm_message m ON m.message_id = o.message_id " +
                "WHERE o.state = 'uploading' AND u.deadline_hour > ? " +
                "AND (m.message_id IS NULL OR m.delete_at_minute IS NULL OR m.delete_at_minute > ?) " +
                "ORDER BY u.deadline_hour, o.object_id LIMIT ?"

        const val PENDING_DOWNLOADS =
            "SELECT o.object_id FROM media_object o LEFT JOIN dm_message m ON m.message_id = o.message_id " +
                "WHERE o.state IN ('awaiting', 'fetching') AND o.incomplete_after_hour > ? " +
                "AND (m.message_id IS NULL OR m.delete_at_minute IS NULL OR m.delete_at_minute > ?) " +
                "ORDER BY o.incomplete_after_hour, o.object_id LIMIT ?"

        const val TO_VERIFY =
            "SELECT o.object_id FROM media_object o LEFT JOIN dm_message m ON m.message_id = o.message_id " +
                "WHERE o.state = 'complete' AND (m.message_id IS NULL OR m.delete_at_minute IS NULL OR m.delete_at_minute > ?) " +
                "ORDER BY o.object_id LIMIT ?"

        const val VIEWING =
            "SELECT o.object_id FROM media_object o LEFT JOIN dm_message m ON m.message_id = o.message_id " +
                "WHERE o.state = 'viewing' AND (m.message_id IS NULL OR m.delete_at_minute IS NULL OR m.delete_at_minute > ?) " +
                "ORDER BY o.object_id LIMIT ?"

        const val EXISTS = "SELECT count(*) FROM media_object WHERE object_id = ?"
        const val EXISTS_FOR_MESSAGE = "SELECT count(*) FROM media_object WHERE message_id = ?"
        const val OBJECTS_OF_MESSAGE = "SELECT object_id FROM media_object WHERE message_id = ? ORDER BY object_id"
        const val RAW_STATE = "SELECT state FROM media_object WHERE object_id = ?"
        const val DECODE_FAILURES_OF = "SELECT decode_failures FROM media_object WHERE object_id = ?"

        const val INCOMPLETE_DUE =
            "SELECT o.object_id FROM media_object o LEFT JOIN dm_message m ON m.message_id = o.message_id " +
                "WHERE o.state IN ('awaiting', 'fetching') AND o.incomplete_after_hour <= ? " +
                "AND (m.message_id IS NULL OR m.delete_at_minute IS NULL OR m.delete_at_minute > ?) " +
                "ORDER BY o.incomplete_after_hour, o.object_id LIMIT ?"

        const val PAST_DEADLINE =
            "SELECT o.object_id FROM media_object o JOIN media_upload u ON u.object_id = o.object_id " +
                "LEFT JOIN dm_message m ON m.message_id = o.message_id " +
                "WHERE o.state = 'uploading' AND u.deadline_hour <= ? " +
                "AND (m.message_id IS NULL OR m.delete_at_minute IS NULL OR m.delete_at_minute > ?) " +
                "ORDER BY u.deadline_hour, o.object_id LIMIT ?"
    }
}

/** What [MediaObjects.onDescriptor] did with a descriptor. */
enum class DescriptorResult {
    /** The object was created, `awaiting`. */
    CREATED,

    /** An object with that id exists: the descriptor is `drop(duplicate_object)` for the object and nothing was written. */
    DUPLICATE_OBJECT,
}

/** The answer to the user's retry of an upload (§6.4, `retryMedia`). */
enum class RetryResult {
    /** The generation went up, the object is `uploading` and its failed ordinals `unsent`. */
    RETRIED,

    /** There is no such object (or it is gone with its message). */
    NO_SUCH_OBJECT,

    /** The object is not in the `failed` state: nothing to retry. */
    NOT_FAILED,

    /** The deadline of the upload has passed: the user must pick the file again (a new object). */
    DEADLINE_PASSED,

    /** Three retries were made already. */
    RETRIES_EXHAUSTED,
}
