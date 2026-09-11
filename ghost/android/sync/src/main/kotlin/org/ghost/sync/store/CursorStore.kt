package org.ghost.sync.store

import org.ghost.sync.api.NamespaceId
import org.ghost.sync.api.RelayId
import org.ghost.sync.api.SyncTransaction

/**
 * `relay_cursor` (design §4.1). Cursors are opaque: Kotlin never interprets them. Only non-empty
 * cursors are stored; an absent row means "from the beginning". A cursor is written only by
 * [InboxStore.commitPage], in the transaction that inserted the page it came with (IN-3).
 */
internal class CursorStore {

    fun cursor(tx: SyncTransaction, relay: RelayId, ns: NamespaceId): ByteArray? =
        tx.sql.single(
            "SELECT cursor FROM relay_cursor WHERE relay_id = ?1 AND namespace_id = ?2",
            listOf(relay.value, ns.raw),
        ) { it.blob(0) }

    /** Upsert of a non-empty cursor. */
    fun put(tx: SyncTransaction, relay: RelayId, ns: NamespaceId, cursor: ByteArray) {
        require(cursor.size == StoreLimits.CURSOR_SIZE) { "cursor has the wrong length" }
        tx.sql.updateExactly(
            1,
            "INSERT INTO relay_cursor(relay_id, namespace_id, cursor) VALUES (?1, ?2, ?3) " +
                "ON CONFLICT(relay_id, namespace_id) DO UPDATE SET cursor = excluded.cursor",
            listOf(relay.value, ns.raw, cursor),
        )
    }
}
