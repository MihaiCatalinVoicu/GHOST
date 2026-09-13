package org.ghost.entitlement.store

import org.ghost.network.EntitlementCrypto
import org.ghost.network.OnionAddress
import org.ghost.storage.SqlExecutor
import org.ghost.sync.api.NamespaceId
import org.ghost.sync.api.RelayId
import org.ghost.sync.api.SyncTransaction
import java.security.MessageDigest

/** Collects every row before returning, so no write ever runs while a device cursor is open. */
internal fun <T> SqlExecutor.rows(sql: String, args: List<Any?> = emptyList(), map: (SqlExecutor.Row) -> T): List<T> {
    val out = ArrayList<T>()
    query(sql, args) { out += map(it) }
    return out
}

/** One row or null; throws if the query returns more than one row. */
internal fun <T> SqlExecutor.single(sql: String, args: List<Any?> = emptyList(), map: (SqlExecutor.Row) -> T): T? {
    val all = rows(sql, args, map)
    check(all.size <= 1) { "expected at most one row" }
    return all.firstOrNull()
}

/** A guarded statement that must change exactly [expected] rows (design §11.4: `execUpdate == 1`). */
internal fun SqlExecutor.updateExactly(expected: Int, sql: String, args: List<Any?>) {
    val changed = execUpdate(sql, args)
    check(changed == expected) { "guarded entitlement update changed an unexpected number of rows" }
}

internal fun SqlExecutor.Row.longOrNull(index: Int): Long? = if (isNull(index)) null else long(index)

internal fun SqlExecutor.Row.blobOrNull(index: Int): ByteArray? = if (isNull(index)) null else blob(index)

internal fun SqlExecutor.Row.stringOrNull(index: Int): String? = if (isNull(index)) null else string(index)

internal fun sha256(vararg parts: ByteArray): ByteArray {
    val md = MessageDigest.getInstance("SHA-256")
    parts.forEach(md::update)
    return md.digest()
}

/** Token kinds as the schema spells them (`ent_key.kind`, `ent_token.kind`) and as the JNI numbers them. */
internal object Kinds {
    const val ACCESS = "access"
    const val INVITE = "invite"
    const val CREDIT = "credit"

    fun code(kind: Int): String = when (kind) {
        EntitlementCrypto.KIND_ACCESS -> ACCESS
        EntitlementCrypto.KIND_INVITE -> INVITE
        EntitlementCrypto.KIND_CREDIT -> CREDIT
        else -> throw IllegalArgumentException("unknown token kind")
    }

    fun of(code: String): Int = when (code) {
        ACCESS -> EntitlementCrypto.KIND_ACCESS
        INVITE -> EntitlementCrypto.KIND_INVITE
        CREDIT -> EntitlementCrypto.KIND_CREDIT
        else -> throw IllegalStateException("unknown token kind")
    }
}

/**
 * Read-only access to the sync tables the engine joins (Phase 7 schema v2): the relay directory (a
 * token reservation names `relay_directory.relay_id`, design §11.3), the registration of a namespace,
 * and the expiry of a usable write capability. Writes to sync tables go through the sync API only.
 */
internal object SyncTables {
    class Relay(val id: RelayId, val address: OnionAddress, operatorId: ByteArray, val active: Boolean) {
        private val operator = operatorId.copyOf()
        fun operatorKey(): List<Byte> = operator.toList()
        override fun toString(): String = "Relay(redacted)"
    }

    fun relays(tx: SyncTransaction): List<Relay> =
        tx.sql.rows("SELECT relay_id, onion_address, operator_id, state FROM relay_directory ORDER BY relay_id") {
            Relay(RelayId(it.long(0)), OnionAddress.parse(it.string(1)), it.blob(2), it.string(3) == "active")
        }

    fun relayKnown(tx: SyncTransaction, relay: RelayId): Boolean =
        tx.sql.single("SELECT 1 FROM relay_directory WHERE relay_id = ?1", listOf(relay.value)) { 1 } != null

    fun namespaceRegistered(tx: SyncTransaction, ns: NamespaceId): Boolean =
        tx.sql.single("SELECT 1 FROM sync_namespace WHERE namespace_id = ?1", listOf(ns.toByteArray())) { 1 } != null

    /** The expiry hour of the pair's usable write capability, or null (none, or no known expiry). */
    fun usableWriteExpiry(tx: SyncTransaction, relay: RelayId, ns: NamespaceId): Long? =
        tx.sql.single(
            "SELECT expires_hour FROM relay_capability WHERE relay_id = ?1 AND namespace_id = ?2 AND kind = 'write' AND state = 'usable'",
            listOf(relay.value, ns.toByteArray()),
        ) { it.longOrNull(0) }
}
