package org.ghost.sync.api

/** A fetched blob handed to its consumer. The ciphertext is hash-verified; its content is not. */
class InboundBlob(val namespace: NamespaceId, val hash: BlobHash, ciphertext: ByteArray) {
    private val payload: ByteArray = ciphertext.copyOf()

    val ciphertext: ByteArray get() = payload.copyOf()

    override fun toString(): String = "InboundBlob(redacted)"
}

interface Inbox {
    /**
     * Commits an offer counter first (poison guard), then returns blobs in local arrival order.
     * A row already offered twice without being consumed is returned alone (design §11.2 #3).
     * Runs its own short transaction: do not call it inside [SyncDatabase.transaction].
     */
    fun claim(consumer: Consumer, limit: Int): List<InboundBlob>

    /** True exactly once per (namespace, hash). Call it for every blob, including rejected ones. */
    fun markConsumed(tx: SyncTransaction, namespace: NamespaceId, hash: BlobHash): Boolean

    /** Re-offer later (e.g. an MLS message for a future epoch); 1 second to 7 days. */
    fun defer(tx: SyncTransaction, namespace: NamespaceId, hash: BlobHash, seconds: Int): Boolean

    fun setListener(listener: SyncListener?)
}
