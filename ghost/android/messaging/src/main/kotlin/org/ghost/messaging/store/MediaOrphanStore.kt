package org.ghost.messaging.store

import org.ghost.storage.SqlExecutor
import org.ghost.storage.queryLong
import org.ghost.sync.api.SyncTransaction

/**
 * The `M_c` orphan rule's rows (Phase 11 design §5.1), the contact-media half of
 * `dm_orphan_namespace`.
 *
 * **Why a separate store.** The rule reads the five media tables, and every production read of an
 * expiring media table must be registered with `:storage`'s expired-row lint (ME-16): the three
 * SELECTs below are registered verbatim in `MediaQueryTexts` (`MediaExpiredRowLint`), the
 * upload-blocker as a read (the live filter of §10.7 point 4, exactly as the `:media` DAOs apply
 * it), the op-blocker as a bound (it must see the expired rows, like the triggers) and the sweep
 * candidates as a sweep select (it names exactly the rows the sweep is about to take).
 *
 * **No `REPLACE`, no upsert** (G-DM4): the orphan row itself is written by [ContactStore.addOrphan]
 * (the guarded UPDATE-then-INSERT pair), which this store reuses.
 *
 * **No read of an expiring table unregistered:** see the class comment; the `dm_outbound_item`
 * half of the descriptor check names no media table and no `dm_message`, so it is not in the
 * lint's set.
 */
internal class MediaOrphanStore {

    /**
     * §5.1's first clause: an `out` object of c still `uploading` with a live deadline blocks the
     * orphan. An `uploading` row whose deadline has passed reads as the `failed`-past-deadline the
     * clause counts as "past its upload" (the same read-through-the-deadline rule as
     * `MediaObjects.byId`, §22.5 row 12), and an object whose message has expired is the sweep's
     * own deletion, one clause down.
     */
    fun uploadBlockers(sql: SqlExecutor, contactId: ByteArray, nowSeconds: Long): Long =
        sql.queryLong(MEDIA_ORPHAN_UPLOAD_BLOCKERS, listOf(contactId, nowSeconds, nowSeconds)) ?: 0L

    /**
     * §5.1's second clause: a descriptor item of c (kind 5) with no final outcome blocks the
     * orphan — `pending`/`enqueued` outright, `failed` until its deadline passes (the user may
     * retry until then, §7.5). `sent`/`degraded`/`indeterminate` are final.
     */
    fun descriptorBlockers(sql: SqlExecutor, contactId: ByteArray, nowSeconds: Long): Long =
        sql.queryLong(MEDIA_ORPHAN_DESCRIPTOR_BLOCKERS, listOf(contactId, nowSeconds)) ?: 0L

    /**
     * §5.1's third clause: a media op of c that has not been released blocks the orphan. The
     * release is Phase 7's (`Outbox.release` sets `released = 1`; the row is garbage-collected
     * later), so this joins the media op mapping to the operation row. After the object's message
     * has been swept the mapping rows are gone with their fragments and the clause reads as
     * released — which is right: the namespace's removal then waits only for the operations to
     * drain, which is exactly what `Namespaces.remove` answers false for (§21.12 point 3).
     */
    fun opBlockers(sql: SqlExecutor, contactId: ByteArray, nowSeconds: Long): Long =
        sql.queryLong(MEDIA_ORPHAN_OP_BLOCKERS, listOf(contactId, nowSeconds)) ?: 0L

    /**
     * SWEEP's candidates (§5.1's "or SWEEP"): the contacts with `out` objects whose message is
     * expired — the rows SWEEP is about to cascade. Read before the deletion and evaluated after
     * it: post-cascade the three clauses read as "over, final and released", which is what makes
     * the expired-descriptor path record the orphan at all (nothing later looks at the contact's
     * media rows again — the mapping that could join to the operations is gone).
     */
    fun candidates(sql: SqlExecutor, nowMinute: Long): List<ByteArray> {
        val out = ArrayList<ByteArray>()
        sql.query(MEDIA_ORPHAN_CANDIDATES, listOf(nowMinute)) { out += it.blob(0) }
        return out
    }

    /**
     * The second half of the recording: c's `media_upload` rows hold the only foreign key into
     * `M_c`'s `sync_namespace` row (§5.1) — deleting them is what lets SWEEP's discharge remove
     * the namespace. All of a contact's uploads name `M_c`, so the namespace id is the key.
     * A write, not a read: no `SELECT`, so the expired-row lint does not scan it.
     */
    fun deleteUploadsOf(tx: SyncTransaction, mediaNamespace: ByteArray): Int =
        tx.sql.execUpdate(MEDIA_ORPHAN_DELETE_UPLOADS, listOf(mediaNamespace))

    companion object {
        /** §5.1 clause 1 — registered in `MediaDaoQueries` (a read: the live filter applies). */
        const val MEDIA_ORPHAN_UPLOAD_BLOCKERS =
            "SELECT count(*) FROM media_object o JOIN media_upload u ON u.object_id = o.object_id " +
                "LEFT JOIN dm_message m ON m.message_id = o.message_id " +
                "WHERE o.role = 'out' AND o.dest_id = ? AND o.state = 'uploading' AND u.deadline_hour > ? " +
                "AND (m.message_id IS NULL OR m.delete_at_minute IS NULL OR m.delete_at_minute > ?)"

        /** §5.1 clause 2 — `dm_outbound_item` is not one of the lint's tables. */
        const val MEDIA_ORPHAN_DESCRIPTOR_BLOCKERS =
            "SELECT count(*) FROM dm_outbound_item WHERE contact_id = ? AND kind = 5 " +
                "AND (state IN ('pending', 'enqueued') OR (state = 'failed' AND deadline_hour > ?))"

        /** §5.1 clause 3 — registered in `MediaBoundQueries` (a bound: it must see the expired rows). */
        const val MEDIA_ORPHAN_OP_BLOCKERS =
            "SELECT count(*) FROM media_outbound_op p JOIN outbox_op oo ON oo.operation_id = p.operation_id " +
                "JOIN media_object o ON o.object_id = p.object_id " +
                "LEFT JOIN dm_message m ON m.message_id = o.message_id " +
                "WHERE o.dest_id = ? AND oo.released = 0 " +
                "AND (m.message_id IS NULL OR m.delete_at_minute IS NULL OR m.delete_at_minute > ?)"

        /** SWEEP's candidates — registered in `MediaSweepQueries` (it names exactly the expiring rows). */
        const val MEDIA_ORPHAN_CANDIDATES =
            "SELECT DISTINCT o.dest_id FROM media_object o JOIN dm_message m ON m.message_id = o.message_id " +
                "WHERE o.role = 'out' AND m.delete_at_minute <= ?"

        /** The upload rows that pin `M_c` — a write, unscanned by the lint. */
        const val MEDIA_ORPHAN_DELETE_UPLOADS = "DELETE FROM media_upload WHERE namespace_id = ?"
    }
}
