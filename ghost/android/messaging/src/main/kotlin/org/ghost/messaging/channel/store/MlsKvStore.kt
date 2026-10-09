package org.ghost.messaging.channel.store

import org.ghost.storage.SqlExecutor
import org.ghost.sync.api.SyncTransaction

/**
 * The rows OpenMLS writes through `GhostKv` (Phase 10 design §3.4, §9): `mls_kv` (group-scoped: tree, context,
 * message secrets and one row per past epoch, …) and `mls_global_kv` (KeyPackages and key pairs, tagged with
 * the channel of the call and, for a KeyPackage's rows, the day they die).
 *
 * **The contract with `ghost-client-mls` (`client-core/mls/src/kv.rs`, read and not changed by this slice).**
 * A row is `(scope, key, env)`: `scope` is 1 for `mls_kv` ([Scope.GROUP]) and 2 for `mls_global_kv`
 * ([Scope.GLOBAL]) — the byte that also binds the envelope's associated data —, `key` is `label ‖ 0x00 ‖
 * json` (a BLOB, never TEXT: it holds a NUL), `env` is `nonce(12) ‖ ChaCha20-Poly1305 ‖ tag(16)` under the
 * channel state key, at least 28 bytes. A call **loads** every row of the channel ([rows]) and returns a
 * **change-set** of `(scope, key, env?)` entries, net (at most one per key), `env == null` meaning delete;
 * Kotlin **applies it in the same SQLCipher transaction** as the rows the call affects ([apply]) and only when
 * the call returned OK. Kotlin never opens, parses or interprets an `env`: the store moves bytes and
 * enforces sizes and scope, nothing else (ADR-19).
 *
 * **What this store adds that `GhostKv` does not know:** the channel a global row was written for (it is the
 * channel of the call) and the day it dies (`delete_after_day`, the KeyPackage's `expiry_day`; 7 days for a
 * rejoin), which the caller supplies for the puts of a call that makes a KeyPackage. [rows] applies the
 * expiry filter to the global rows, so a KeyPackage's private keys past their day are not handed to a call even
 * if `CH-SWEEP` has not deleted them (T25). **The day only moves earlier and a KeyPackage always has one**: a put
 * of a row that exists keeps the earlier of the two days (a re-put, which the adapter's net change-set makes of
 * a row it rewrote, can no longer give a KeyPackage's private keys a longer life; `mls_global_kv_fixed` holds
 * the same rule in the schema), and a **new** `KeyPackage` row with no day is [ChannelStoreError.BAD_VALUE]
 * (the review of S3: a row stored with no day was loaded at any day and kept until the channel went).
 *
 * **No `REPLACE`, no upsert** (G-DM4, the `*_no_replace` guards): a put is a guarded `UPDATE` followed by an
 * `INSERT` when no row matched. **Every write goes through the caller's [SyncTransaction].**
 */
internal class MlsKvStore {

    /** `GhostKv`'s `Scope` byte. */
    enum class Scope(val tag: Int) {
        GROUP(1),
        GLOBAL(2),
        ;

        companion object {
            fun of(tag: Int): Scope = entries.single { it.tag == tag }
        }
    }

    /** A stored row as a call loads it. Shows no key and no envelope (T3). */
    class KvRow(val scope: Scope, val key: ByteArray, val env: ByteArray) {
        override fun toString(): String = "KvRow(scope=${scope.name})"
    }

    /** One entry of a change-set: a wrapped value to put, or (`env == null`) a delete. */
    class KvChange(val scope: Scope, val key: ByteArray, val env: ByteArray?) {
        override fun toString(): String = "KvChange(scope=${scope.name}, ${if (env == null) "delete" else "put"})"
    }

    /** What [apply] did: the rows it put (inserted or updated) and the rows it deleted. */
    class Applied(val puts: Int, val deletes: Int) {
        override fun toString(): String = "Applied(puts=$puts, deletes=$deletes)"
    }

    /**
     * Every row a call on [channelId] loads: the group-scoped rows, then the global rows tagged with the channel
     * that are still within their day, each by key. These are the `rows` of §10.2.
     */
    fun rows(sql: SqlExecutor, channelId: ByteArray, today: Long): List<KvRow> {
        val out = ArrayList<KvRow>()
        sql.query(GROUP_ROWS, listOf(channelId)) { r -> out += KvRow(Scope.GROUP, r.blob(0), r.blob(1)) }
        sql.query(GLOBAL_ROWS, listOf(channelId, today)) { r -> out += KvRow(Scope.GLOBAL, r.blob(0), r.blob(1)) }
        return out
    }

    /**
     * Only the global rows: a rejoin's or restore's `welcomeJoin` is passed the KeyPackage's rows and none of the
     * old group's (§6.2.5), so `OpenMLS`'s `GroupAlreadyExists` check does not fire.
     */
    fun globalRows(sql: SqlExecutor, channelId: ByteArray, today: Long): List<KvRow> {
        val out = ArrayList<KvRow>()
        sql.query(GLOBAL_ROWS, listOf(channelId, today)) { r -> out += KvRow(Scope.GLOBAL, r.blob(0), r.blob(1)) }
        return out
    }

    fun groupRowCount(sql: SqlExecutor, channelId: ByteArray): Int {
        var n = 0
        sql.query(GROUP_COUNT, listOf(channelId)) { r -> n = r.long(0).toInt() }
        return n
    }

    /**
     * Applies a change-set, in the caller's transaction (§3.4 point 4). A put of a group-scoped key writes
     * `mls_kv`; a put of a global key writes `mls_global_kv` tagged with [channelId] and, for a row that is new,
     * with [globalDeleteAfterDay] (a row that exists keeps its day, or takes the call's when that is earlier or the
     * row has none; a day never moves later). A key that is
     * already a global row of **another** channel is [ChannelStoreError.ROW_EXISTS]: the key of a KeyPackage or
     * a key pair is unique across channels. A delete of a row that is not there is no error: the adapter's
     * change-set is the net of the call, and a row it created and removed in one call was never written.
     */
    fun apply(
        tx: SyncTransaction,
        channelId: ByteArray,
        changes: List<KvChange>,
        globalDeleteAfterDay: Long? = null,
        /**
         * Gives [globalDeleteAfterDay] to the `KeyPackage` rows only, and no day to the other global rows (slice S4,
         * §19.37): `CH-ACCEPT`'s KeyPackage dies at the join's expiry if no Welcome comes, but the leaf's key pairs the same
         * call writes become the joined group's once the Welcome is processed, and a day — which only moves earlier —
         * would delete them under a live group. A join that expires deletes every global row of the channel instead.
         */
        keyPackagesOnly: Boolean = false,
    ): Applied {
        Fields.nonNegativeOrNull("mls_global_kv.delete_after_day", globalDeleteAfterDay)
        for (c in changes) {
            Fields.bytesBetween("mls_kv.k", c.key, 2, MAX_KEY)
            if (c.env != null) Fields.bytesBetween("mls_kv.v_env", c.env, MIN_ENV, MAX_ENV)
        }
        var puts = 0
        var deletes = 0
        for (c in changes) {
            val env = c.env
            when {
                c.scope == Scope.GROUP && env != null -> {
                    putGroup(tx, channelId, c.key, env)
                    puts++
                }
                c.scope == Scope.GROUP -> deletes += tx.sql.execUpdate(
                    "DELETE FROM mls_kv WHERE channel_id = ? AND k = ?",
                    listOf(channelId, c.key),
                )
                env != null -> {
                    val day = if (keyPackagesOnly && !isKeyPackageRow(c.key)) null else globalDeleteAfterDay
                    putGlobal(tx, channelId, c.key, env, day)
                    puts++
                }
                else -> deletes += tx.sql.execUpdate(
                    "DELETE FROM mls_global_kv WHERE k = ? AND channel_id = ?",
                    listOf(c.key, channelId),
                )
            }
        }
        return Applied(puts, deletes)
    }

    private fun putGroup(tx: SyncTransaction, channelId: ByteArray, key: ByteArray, env: ByteArray) {
        val updated = tx.sql.execUpdate(
            "UPDATE mls_kv SET v_env = ? WHERE channel_id = ? AND k = ?",
            listOf(env, channelId, key),
        )
        if (updated == 0) {
            tx.sql.exec("INSERT INTO mls_kv(channel_id, k, v_env) VALUES (?, ?, ?)", listOf(channelId, key, env))
        }
    }

    private fun putGlobal(tx: SyncTransaction, channelId: ByteArray, key: ByteArray, env: ByteArray, deleteAfterDay: Long?) {
        // The day of a row that exists: the call's when the row has none, else the earlier of the two (a row's
        // death day never moves later; `mls_global_kv_fixed` refuses it too).
        val updated = tx.sql.execUpdate(
            "UPDATE mls_global_kv SET v_env = ?, delete_after_day = CASE WHEN ? IS NULL THEN delete_after_day " +
                "WHEN delete_after_day IS NULL OR delete_after_day > ? THEN ? ELSE delete_after_day END " +
                "WHERE k = ? AND channel_id = ?",
            listOf(env, deleteAfterDay, deleteAfterDay, deleteAfterDay, key, channelId),
        )
        if (updated == 0) {
            // A KeyPackage's row holds its private keys until the KeyPackage is used or expires: no day, no row.
            if (deleteAfterDay == null && isKeyPackageRow(key)) {
                throw ChannelStoreException(ChannelStoreError.BAD_VALUE, "mls_global_kv.delete_after_day")
            }
            val inserted = tx.sql.execUpdate(
                "INSERT INTO mls_global_kv(k, v_env, channel_id, delete_after_day) SELECT ?, ?, ?, ? " +
                    "WHERE NOT EXISTS (SELECT 1 FROM mls_global_kv WHERE k = ?)",
                listOf(key, env, channelId, deleteAfterDay, key),
            )
            if (inserted != 1) throw ChannelStoreException(ChannelStoreError.ROW_EXISTS, "mls_global_kv")
        }
    }

    /**
     * A rejoin or a restore replaces the old group's state: the same transaction deletes the old group-scoped
     * rows and then applies the Welcome's change-set (§6.2.5, §19.16). Returns how many rows went.
     */
    fun deleteGroupRows(tx: SyncTransaction, channelId: ByteArray): Int =
        tx.sql.execUpdate("DELETE FROM mls_kv WHERE channel_id = ?", listOf(channelId))

    /** The join expired without a Welcome: the KeyPackage's private keys go (§6.2.2). */
    fun deleteGlobalRows(tx: SyncTransaction, channelId: ByteArray): Int =
        tx.sql.execUpdate("DELETE FROM mls_global_kv WHERE channel_id = ?", listOf(channelId))

    /**
     * A rejoin's give-up (§6.7): the pending KeyPackage's private keys go with the `reinvite_needed`
     * deadline. Only KeyPackage rows carry a death day ([apply] gives one to no other global row), so
     * `delete_after_day IS NOT NULL` names exactly them; the live group's key-pair rows (no day) stay.
     */
    fun deleteKeyPackages(tx: SyncTransaction, channelId: ByteArray): Int =
        tx.sql.execUpdate(
            "DELETE FROM mls_global_kv WHERE channel_id = ? AND delete_after_day IS NOT NULL",
            listOf(channelId),
        )

    /** SWEEP's read (§6.2.2, §6.12): the global rows past their day, oldest first. */
    fun expiredGlobal(sql: SqlExecutor, today: Long, batch: Int): List<ByteArray> {
        val out = ArrayList<ByteArray>()
        sql.query(EXPIRED_GLOBAL, listOf(today, batch.toLong())) { r -> out += r.blob(0) }
        return out
    }

    fun deleteGlobal(tx: SyncTransaction, key: ByteArray): Boolean =
        tx.sql.execUpdate("DELETE FROM mls_global_kv WHERE k = ?", listOf(key)) == 1

    /** Whether [key] is a `KeyPackage` row: the label before the first NUL (`label ‖ 0x00 ‖ json`, `kv.rs`'s `L_KEY_PACKAGE`). */
    private fun isKeyPackageRow(key: ByteArray): Boolean {
        val nul = key.indexOf(0)
        return nul == KEY_PACKAGE_LABEL.size && key.copyOfRange(0, nul).contentEquals(KEY_PACKAGE_LABEL)
    }

    companion object {
        /** The label of the one global row that is a KeyPackage's: `kv.rs`'s `L_KEY_PACKAGE`, pinned by `MlsKvStoreTest`. */
        val KEY_PACKAGE_LABEL: ByteArray = "KeyPackage".toByteArray(Charsets.US_ASCII)

        /** The longest key a row of §3.4 has is a few hundred bytes (a label and the JSON of a group id or a reference). */
        const val MAX_KEY: Int = 1024

        /** `nonce(12) ‖ tag(16)` around an empty value. */
        const val MIN_ENV: Int = 28

        /** Ten times the largest value measured (the tree of a 100-member channel, 125 KB; V10-5). */
        const val MAX_ENV: Int = 4_194_304

        const val GROUP_ROWS: String = "SELECT k, v_env FROM mls_kv WHERE channel_id = ? ORDER BY k"
        const val GROUP_COUNT: String = "SELECT count(*) FROM mls_kv WHERE channel_id = ?"

        const val GLOBAL_ROWS: String =
            "SELECT k, v_env FROM mls_global_kv WHERE channel_id = ? AND (delete_after_day IS NULL OR delete_after_day >= ?) ORDER BY k"

        /** SWEEP's own batch. */
        const val EXPIRED_GLOBAL: String =
            "SELECT k FROM mls_global_kv WHERE delete_after_day < ? ORDER BY delete_after_day, k LIMIT ?"
    }
}
