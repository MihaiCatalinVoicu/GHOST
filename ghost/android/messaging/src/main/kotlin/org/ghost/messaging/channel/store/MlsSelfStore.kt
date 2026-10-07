package org.ghost.messaging.channel.store

import org.ghost.storage.SqlExecutor
import org.ghost.sync.api.SyncTransaction

/**
 * `mls_self` (Phase 10 design §10.4 "State key"; amended into migration 7 by slice S4, §19.37, §19.35 F-9): the one row
 * that holds the channel state key, wrapped by a non-exportable Keystore key (the F9 §2.5 `session_state_key` pattern,
 * one key for all channels). The key itself never reaches this store unwrapped and never leaves the native context once
 * it is opened (`ChannelCrypto.open`); this store moves the wrapped bytes and nothing else.
 *
 * **Written once.** The key is created at the first channel use and every envelope of every channel is bound to it, so
 * the row is inserted when absent and never rewritten (`mls_self_fixed`); a wipe deletes it with the database.
 */
internal class MlsSelfStore {

    /** The wrapped state key, or `null` before the first channel use. */
    fun stateKeyWrapped(sql: SqlExecutor): ByteArray? {
        var wrapped: ByteArray? = null
        sql.query(STATE_KEY, emptyList()) { r -> wrapped = r.blob(0) }
        return wrapped
    }

    /**
     * Inserts [wrapped] when no key is stored yet; true when this call stored it. A second caller (a crash between the
     * insert's commit and its use) finds the first key and keeps it.
     */
    fun insertIfAbsent(tx: SyncTransaction, wrapped: ByteArray): Boolean {
        Fields.bytesBetween("mls_self.state_key_wrapped", wrapped, 40, 256)
        return tx.sql.execUpdate(
            "INSERT INTO mls_self(id, state_key_wrapped) SELECT 1, ? WHERE NOT EXISTS (SELECT 1 FROM mls_self WHERE id = 1)",
            listOf(wrapped),
        ) == 1
    }

    override fun toString(): String = "MlsSelfStore"

    companion object {
        const val STATE_KEY: String = "SELECT state_key_wrapped FROM mls_self WHERE id = 1"
    }
}
