package org.ghost.sync.port

import org.ghost.network.OnionAddress
import org.ghost.sync.api.BlobHash
import org.ghost.sync.api.NamespaceId

/**
 * Blocking relay calls (design §1.6). Failures: `NetworkException(category)` or
 * [IllegalArgumentException] (Kotlin `require`). The engine catches nothing else and never catches
 * JVM errors. Production adapter: `org.ghost.network.RelayTransport` (TorRelayTransport).
 */
interface RelayPort {
    fun store(
        relay: OnionAddress,
        ns: NamespaceId,
        capability: ByteArray,
        ciphertext: ByteArray,
        ttlSeconds: Int,
        deadlineMillis: Int,
    ): StoreReceipt

    fun get(relay: OnionAddress, ns: NamespaceId, capability: ByteArray, hash: BlobHash, deadlineMillis: Int): FetchedBlob

    /** `cursor` is empty (from the beginning) or 8 opaque bytes. */
    fun list(relay: OnionAddress, ns: NamespaceId, capability: ByteArray, cursor: ByteArray, limit: Int, deadlineMillis: Int): ListPage

    /**
     * Which of `hashes` the relay holds. `hashes` must be distinct (1..256; the engine sends at most
     * 64); the answer is a subset of the request.
     */
    fun check(relay: OnionAddress, ns: NamespaceId, capability: ByteArray, hashes: List<BlobHash>, deadlineMillis: Int): Set<BlobHash>
}

/** A store receipt: the hash the relay stored and the expiry it holds (unix seconds). */
class StoreReceipt(val blobHash: BlobHash, val expiryUnixSeconds: Long) {
    override fun toString(): String = "StoreReceipt(redacted)"
}

/** A fetched, hash-verified, bucket-sized ciphertext and the relay's expiry for it (unix seconds). */
class FetchedBlob(ciphertext: ByteArray, val expiryUnixSeconds: Long) {
    private val payload: ByteArray = ciphertext.copyOf()

    val ciphertext: ByteArray get() = payload.copyOf()

    override fun toString(): String = "FetchedBlob(size=${payload.size})"
}

/** One list page. `nextCursor` is empty when the listing is complete ("caught up"), otherwise 8 bytes. */
class ListPage(val hashes: List<BlobHash>, nextCursor: ByteArray) {
    private val cursor: ByteArray = nextCursor.copyOf()

    val nextCursor: ByteArray get() = cursor.copyOf()

    override fun toString(): String = "ListPage(size=${hashes.size})"
}
