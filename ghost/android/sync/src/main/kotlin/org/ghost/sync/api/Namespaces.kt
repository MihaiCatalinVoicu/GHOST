package org.ghost.sync.api

interface Namespaces {
    /**
     * Registers the namespace, or re-registers a known one (the row is reused, so tombstones keep
     * deduplicating). A known namespace keeps its consumer: a different one throws. Then applies
     * [relays] as in [setRelays]. `listen = false` means write-only (no inbox rows are kept);
     * registering a known write-only namespace with `listen = true` turns listening on as
     * [setListening] does.
     */
    fun register(
        tx: SyncTransaction,
        namespace: NamespaceId,
        consumer: Consumer,
        relays: Set<RelayId>,
        listen: Boolean,
        sendDelay: SendDelay = SendDelay.DEFAULT,
    )

    /** Replaces the relay set and repairs deliveries (design §3.9). */
    fun setRelays(tx: SyncTransaction, namespace: NamespaceId, relays: Set<RelayId>)

    /** Cursors are kept. */
    fun setListening(tx: SyncTransaction, namespace: NamespaceId, listen: Boolean)

    fun setSendDelay(tx: SyncTransaction, namespace: NamespaceId, sendDelay: SendDelay)

    /**
     * False while the namespace has operations or fetched, unconsumed blobs. Otherwise stops
     * listening, drops its relay set, cursors, capabilities and not-yet-fetched rows, and keeps the
     * consumed-blob tombstones until their retention day; the namespace row itself is removed by
     * garbage collection once nothing refers to it (design §11.2 #19).
     */
    fun remove(tx: SyncTransaction, namespace: NamespaceId): Boolean
}
