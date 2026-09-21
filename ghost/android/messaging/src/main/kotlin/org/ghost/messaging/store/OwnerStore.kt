package org.ghost.messaging.store

import org.ghost.storage.SqlExecutor
import org.ghost.sync.api.SyncTransaction

/**
 * The owner-side rows of schema v5: `dm_self`, `dm_own_namespace` and `olm_prekey_gen` (Phase 9
 * design §13.6 step 5, §13.1 `…messaging.store`).
 *
 * **Every write goes through the caller's [SyncTransaction].** The owner steps of §7.2 are each
 * exactly one `SyncDatabase.transaction`, so this class opens none of its own: a DAO that opened
 * a transaction would break the atomicity SEND, ACTIVATE and OWNER-WEEK rely on, and would nest
 * inside the caller's (which `SyncDatabase` refuses).
 *
 * **No `REPLACE`, no upsert** (gate G-DM4, §13.6's `<table>_no_replace` guards). A row that may or
 * may not exist is written as a guarded `UPDATE` whose changed-row count decides whether an
 * `INSERT` follows — the "UPDATE-then-INSERT pair" the design names — so the guards never fire and
 * a concurrent writer cannot be silently deleted.
 *
 * **No read of an expiring table.** These three tables carry no `delete_at_minute`, so nothing
 * here has to register a query with `:storage`'s `DmExpiredRowLint` (§22.10 item 3 "Scope"); the
 * first read of `dm_message` is S7's, and it must.
 */
internal class OwnerStore {

    /** The `dm_self` row, or null before ACTIVATE has run (§21.12 point 2). */
    class SelfRow(
        val cardIndex: Int,
        /** The key of the D3 dedup tags (§7.6); read by `RECV` since S7. */
        val seenKey: ByteArray,
        val contentKeyWrapped: ByteArray,
        val stateKeyWrapped: ByteArray,
        val bundleWeek: Long?,
        val bundlePublishedWeek: Long?,
        val expiryClockMinute: Long,
        val acceptAfterMinute: Long?,
    ) {
        /** Never shows a wrapped key (T3). */
        override fun toString(): String = "SelfRow(redacted)"
    }

    /** A row of `olm_prekey_gen`. `supersededDay` null means it is the current generation. */
    class GenerationRow(
        val genId: Long,
        val bundleWeek: Long,
        val fallbackPublic: ByteArray,
        val secretsEnv: ByteArray,
        val supersededDay: Long?,
        val deleteAfterDay: Long?,
    ) {
        override fun toString(): String = "GenerationRow(redacted)"
    }

    // ---- dm_self ----

    fun self(sql: SqlExecutor): SelfRow? {
        var row: SelfRow? = null
        sql.query(
            "SELECT card_index, seen_key, content_key_wrapped, state_key_wrapped, bundle_week, " +
                "bundle_published_week, expiry_clock_minute, accept_after_minute FROM dm_self WHERE id = 1",
        ) { r ->
            row = SelfRow(
                cardIndex = r.long(0).toInt(),
                seenKey = r.blob(1),
                contentKeyWrapped = r.blob(2),
                stateKeyWrapped = r.blob(3),
                bundleWeek = if (r.isNull(4)) null else r.long(4),
                bundlePublishedWeek = if (r.isNull(5)) null else r.long(5),
                expiryClockMinute = r.long(6),
                acceptAfterMinute = if (r.isNull(7)) null else r.long(7),
            )
        }
        return row
    }

    /**
     * Inserts the one identity row. A plain `INSERT`: the caller has already established that no
     * row exists inside this same transaction, and a second one would violate `CHECK (id = 1)` —
     * which is the guard, not a race to paper over.
     */
    fun insertSelf(
        tx: SyncTransaction,
        cardIndex: Int,
        seenKey: ByteArray,
        contentKeyWrapped: ByteArray,
        stateKeyWrapped: ByteArray,
        expiryClockMinute: Long,
        acceptAfterMinute: Long?,
    ) {
        tx.sql.exec(
            "INSERT INTO dm_self(id, card_index, seen_key, content_key_wrapped, state_key_wrapped, " +
                "bundle_week, bundle_published_week, expiry_clock_minute, accept_after_minute) " +
                "VALUES (1, ?, ?, ?, ?, NULL, NULL, ?, ?)",
            listOf(cardIndex.toLong(), seenKey, contentKeyWrapped, stateKeyWrapped, expiryClockMinute, acceptAfterMinute),
        )
    }

    /**
     * OWNER-WEEK's week guard (§5.4 "Idempotent per week (guard `bundle_week < w`)"). Returns
     * true when this call is the one that moved the week, so a re-execution after a crash — or a
     * second time-triggered pass in the same week — publishes nothing a second time.
     *
     * The `dm_self_monotonic` trigger refuses a decrease outright; the `IS NULL` arm is what makes
     * the very first rotation after ACTIVATE match.
     */
    fun claimBundleWeek(tx: SyncTransaction, week: Long): Boolean =
        tx.sql.execUpdate(
            "UPDATE dm_self SET bundle_week = ? WHERE id = 1 AND (bundle_week IS NULL OR bundle_week < ?)",
            listOf(week, week),
        ) == 1

    /** OUTCOME's record that the bundle of [week] really reached the relays (§21.8 point 5). */
    fun markBundlePublished(tx: SyncTransaction, week: Long): Boolean =
        tx.sql.execUpdate(
            "UPDATE dm_self SET bundle_published_week = ? " +
                "WHERE id = 1 AND (bundle_published_week IS NULL OR bundle_published_week < ?)",
            listOf(week, week),
        ) == 1

    // ---- dm_own_namespace ----

    /** The own namespaces, by role. */
    fun ownNamespaces(sql: SqlExecutor, cardIndex: Int): Map<String, ByteArray> {
        val out = LinkedHashMap<String, ByteArray>()
        sql.query(
            "SELECT role, namespace_id FROM dm_own_namespace WHERE card_index = ?",
            listOf(cardIndex.toLong()),
        ) { r -> out[r.string(0)] = r.blob(1) }
        return out
    }

    /**
     * Records `X_0` or `P_0`. Idempotent by the UPDATE-then-INSERT pair: the namespace of a role
     * and card index is an HKDF output, so a second ACTIVATE of the same identity computes the
     * same bytes and changes nothing.
     */
    fun putOwnNamespace(tx: SyncTransaction, namespace: ByteArray, role: String, cardIndex: Int) {
        val changed = tx.sql.execUpdate(
            "UPDATE dm_own_namespace SET namespace_id = ? WHERE role = ? AND card_index = ?",
            listOf(namespace, role, cardIndex.toLong()),
        )
        if (changed == 0) {
            tx.sql.exec(
                "INSERT INTO dm_own_namespace(namespace_id, role, card_index) VALUES (?, ?, ?)",
                listOf(namespace, role, cardIndex.toLong()),
            )
        }
    }

    // ---- olm_prekey_gen ----

    /** The current generation (the one with no `superseded_day`), or null before the first. */
    fun currentGeneration(sql: SqlExecutor): GenerationRow? {
        var row: GenerationRow? = null
        sql.query(
            "SELECT gen_id, bundle_week, fallback_pub, secrets_env, superseded_day, delete_after_day " +
                "FROM olm_prekey_gen WHERE superseded_day IS NULL",
        ) { r -> row = readGeneration(r) }
        return row
    }

    /** Every generation the device still holds, newest bundle week first (CS-8: at most 14). */
    fun generations(sql: SqlExecutor): List<GenerationRow> {
        val out = ArrayList<GenerationRow>()
        sql.query(
            "SELECT gen_id, bundle_week, fallback_pub, secrets_env, superseded_day, delete_after_day " +
                "FROM olm_prekey_gen ORDER BY bundle_week DESC, gen_id DESC",
        ) { r -> out += readGeneration(r) }
        return out
    }

    /** The generation ids in use, so a new one can be drawn distinct from all of them (§3.1). */
    fun generationIds(sql: SqlExecutor): Set<Long> {
        val out = HashSet<Long>()
        sql.query("SELECT gen_id FROM olm_prekey_gen") { r -> out += r.long(0) }
        return out
    }

    fun insertGeneration(
        tx: SyncTransaction,
        genId: Long,
        bundleWeek: Long,
        fallbackPublic: ByteArray,
        secretsEnv: ByteArray,
    ) {
        tx.sql.exec(
            "INSERT INTO olm_prekey_gen(gen_id, bundle_week, fallback_pub, secrets_env, superseded_day, delete_after_day) " +
                "VALUES (?, ?, ?, ?, NULL, NULL)",
            listOf(genId, bundleWeek, fallbackPublic, secretsEnv),
        )
    }

    /**
     * Supersedes [genId] at [supersededDay], with `delete_after_day = superseded_day + 91` (§5.4;
     * the schema CHECK ties the two, and `olm_prekey_gen_fixed` makes both write-once).
     *
     * The `superseded_day IS NULL` guard is what makes OWNER-WEEK idempotent on this half too: a
     * re-execution after a crash finds the row already superseded and changes nothing, rather than
     * moving the retention window forward by a day each time.
     */
    fun supersede(tx: SyncTransaction, genId: Long, supersededDay: Long): Boolean =
        tx.sql.execUpdate(
            "UPDATE olm_prekey_gen SET superseded_day = ?, delete_after_day = ? " +
                "WHERE gen_id = ? AND superseded_day IS NULL",
            listOf(supersededDay, supersededDay + RETENTION_DAYS, genId),
        ) == 1

    private fun readGeneration(r: SqlExecutor.Row) = GenerationRow(
        genId = r.long(0),
        bundleWeek = r.long(1),
        fallbackPublic = r.blob(2),
        secretsEnv = r.blob(3),
        supersededDay = if (r.isNull(4)) null else r.long(4),
        deleteAfterDay = if (r.isNull(5)) null else r.long(5),
    )

    // ---- dm_outbound_op (the bundle half only; the item half is S7's) ----

    /** Records the outbox operation that carries a bundle of [bundleWeek] (§7.2 OWNER-WEEK). */
    fun insertBundleOp(tx: SyncTransaction, operationId: ByteArray, bundleWeek: Long, blob: ByteArray, deadlineHour: Long) {
        tx.sql.exec(
            "INSERT INTO dm_outbound_op(operation_id, purpose, item_id, bundle_week, blob, resend_count, deadline_hour) " +
                "VALUES (?, 'bundle', NULL, ?, ?, 0, ?)",
            listOf(operationId, bundleWeek, blob, deadlineHour),
        )
    }

    // No "has this week a bundle op?" read lives here. `dm_outbound_op` carries no outcome column
    // (§13.6 step 5), so such a query cannot tell an undecided operation from a decided or failed
    // one, and OWNER-WEEK's guard is `dm_self.bundle_week` alone (§5.4).
    //
    // **`dm_self.bundle_published_week` still has no reader**, and the S7 review was right that it
    // is written and never read. The step that should read it is §21.8 point 5's re-seal of a
    // FAILED or INDETERMINATE publication, and it cannot be written in `:messaging` alone: the
    // rule says "new salt, same generation and `bundle_rank`", the closed surface of §2.6 offers
    // only `bundleCreate` (a fresh generation), and the identical-bytes alternative is refused by
    // Phase 7's `outbox_op UNIQUE (namespace_id, blob_hash)`. Deferred in §22.12 with what the
    // next slice must add.

    companion object {
        /** `delete_after_day = superseded_day + 91` (§5.4; 7 + 28 + 45 + 6 days, rounded to 13 weeks). */
        const val RETENTION_DAYS: Long = 91

        const val ROLE_INBOX: String = "inbox"
        const val ROLE_BUNDLE: String = "bundle"
    }
}
