package org.ghost.sync.api

/**
 * A fetched blob handed to its consumer. The ciphertext is hash-verified; its content is not.
 *
 * [relayExpiryHour] is the relay expiry of the blob floored to the hour, recorded at the fetch and
 * dropped again when the row is consumed (Phase 9 design §13.3 item 2): the DM consumer needs it to
 * bound the lifetime of a message it holds back. It is 0 for a row fetched before schema v4, which
 * recorded no relay expiry. [offers] is the offer count committed before this hand-off (the poison
 * guard of design §11.2 #3).
 */
class InboundBlob(
    val namespace: NamespaceId,
    val hash: BlobHash,
    ciphertext: ByteArray,
    val relayExpiryHour: Long,
    val offers: Int,
) {
    private val payload: ByteArray = ciphertext.copyOf()

    val ciphertext: ByteArray get() = payload.copyOf()

    override fun toString(): String = "InboundBlob(redacted)"
}

/**
 * A read-only view of a fetched row: what [Inbox.peek] returns. Nothing about the row changes, so a
 * consumer may order a batch before claiming any of it (Phase 9 design §7.7, §13.3 item 10).
 */
class PeekedBlob(
    val namespace: NamespaceId,
    val hash: BlobHash,
    ciphertext: ByteArray,
    val relayExpiryHour: Long,
) {
    private val payload: ByteArray = ciphertext.copyOf()

    val ciphertext: ByteArray get() = payload.copyOf()

    override fun toString(): String = "PeekedBlob(redacted)"
}

interface Inbox {
    /**
     * Commits an offer counter first (poison guard), then returns blobs in local arrival order.
     * A row already offered twice without being consumed is returned alone (design §11.2 #3).
     * Runs its own short transaction: do not call it inside [SyncDatabase.transaction].
     */
    fun claim(consumer: Consumer, limit: Int): List<InboundBlob>

    /**
     * Up to [limit] fetched rows of [consumer] in local arrival order, read in one transaction that
     * changes nothing: no offer counter moves and no row is claimed. For ordering only; a row it
     * shows is claimed with [claimOne]. Runs its own short transaction.
     */
    fun peek(consumer: Consumer, limit: Int): List<PeekedBlob>

    /**
     * Claims the named row if it is still fetched, with the offer rules of [claim] (the counter
     * commits before the hand-off). Null when the row is gone, already consumed or not due for an
     * offer. Runs its own short transaction: do not call it inside [SyncDatabase.transaction].
     */
    fun claimOne(consumer: Consumer, namespace: NamespaceId, hash: BlobHash): InboundBlob?

    /** True exactly once per (namespace, hash). Call it for every blob, including rejected ones. */
    fun markConsumed(tx: SyncTransaction, namespace: NamespaceId, hash: BlobHash): Boolean

    /** Re-offer later (e.g. an MLS message for a future epoch); 1 second to 7 days. */
    fun defer(tx: SyncTransaction, namespace: NamespaceId, hash: BlobHash, seconds: Int): Boolean

    /**
     * Forgets the consumed-blob tombstones of a [Consumer.PREKEYS] namespace (Phase 9 design §21.7
     * point 2): a bundle consumed during an earlier establishment must be fetchable again after a
     * reset, a key change or a re-added contact, and re-consuming a bundle is idempotent. Refused
     * for every other consumer, whose exactly-once argument rests on those tombstones. Tombstones of
     * the namespace's own blobs are kept. Returns the number of tombstones deleted.
     */
    fun forgetConsumed(tx: SyncTransaction, namespace: NamespaceId): Int

    fun setListener(listener: SyncListener?)
}
