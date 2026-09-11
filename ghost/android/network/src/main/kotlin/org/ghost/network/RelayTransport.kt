package org.ghost.network

/**
 * Blocking relay calls over the embedded Tor client (ADR-19). [TorRelayTransport] is the
 * implementation; callers such as the sync engine's adapter depend on this interface so they can
 * be tested on the JVM without the native library.
 *
 * Failures are [NetworkException] with a constant category (`client-core/README.md`), or
 * [IllegalArgumentException] for arguments rejected before the native call. Every relay call takes
 * a deadline in milliseconds, 1..[MAX_DEADLINE_MILLIS]; the overloads without one use
 * [MAX_DEADLINE_MILLIS]. The capability must name `namespace` and fit the call (write for store;
 * read or write for get, list, check); otherwise the native side fails with `invalid_argument`
 * before any network I/O (T21).
 */
interface RelayTransport : AutoCloseable {
    /** Bootstraps Tor (bounded natively at 180 s). */
    fun bootstrap()

    /** Stores an encrypted, bucket-sized blob; see [TorRelayTransport.store]. */
    fun store(
        relay: OnionAddress,
        namespace: ByteArray,
        capability: ByteArray,
        ciphertext: ByteArray,
        ttlSeconds: Int,
        deadlineMillis: Int,
    ): StoreReceipt

    fun store(relay: OnionAddress, namespace: ByteArray, capability: ByteArray, ciphertext: ByteArray, ttlSeconds: Int): StoreReceipt =
        store(relay, namespace, capability, ciphertext, ttlSeconds, MAX_DEADLINE_MILLIS)

    /** Fetches a blob: the hash-verified ciphertext and the relay's expiry for it. */
    fun get(relay: OnionAddress, namespace: ByteArray, capability: ByteArray, blobHash: ByteArray, deadlineMillis: Int): FetchedBlob

    fun get(relay: OnionAddress, namespace: ByteArray, capability: ByteArray, blobHash: ByteArray): FetchedBlob =
        get(relay, namespace, capability, blobHash, MAX_DEADLINE_MILLIS)

    /** Lists one page; `cursor` is empty (from the beginning) or 8 bytes, `limit` 1..[MAX_BATCH]. */
    fun list(relay: OnionAddress, namespace: ByteArray, capability: ByteArray, cursor: ByteArray, limit: Int, deadlineMillis: Int): Page

    fun list(relay: OnionAddress, namespace: ByteArray, capability: ByteArray, cursor: ByteArray, limit: Int): Page =
        list(relay, namespace, capability, cursor, limit, MAX_DEADLINE_MILLIS)

    /**
     * Returns which of `hashes` (1..[MAX_BATCH] distinct hashes of 32 bytes) the relay holds in
     * `namespace`. The answer is decoded strictly: whole 32-byte hashes, each one of the requested
     * hashes, none twice (so no more than requested); anything else is `malformed_response`.
     */
    fun check(relay: OnionAddress, namespace: ByteArray, capability: ByteArray, hashes: List<ByteArray>, deadlineMillis: Int): List<ByteArray>

    /** Drops every isolation token so the next request per scope builds fresh circuits. */
    fun rotateCircuits()

    /** Idempotent, any thread; in-flight calls fail with category `closed`. */
    override fun close()

    /** A store receipt: the blob hash and the expiry the relay holds for it (unix seconds). */
    data class StoreReceipt(val blobHash: ByteArray, val expiryUnixSeconds: Long)

    /** One list page. `nextCursor` is empty when the listing is complete, otherwise 8 bytes. */
    data class Page(val hashes: List<ByteArray>, val nextCursor: ByteArray)

    /**
     * A fetched blob: the bucket-sized ciphertext (hash already verified natively) and the expiry
     * the relay declares for it, in unix seconds (natively bounded to at most now + 93 days).
     */
    class FetchedBlob(val ciphertext: ByteArray, val expiryUnixSeconds: Long) {
        override fun toString(): String = "FetchedBlob(size=${ciphertext.size})"
    }

    companion object {
        /** Upper bound of a call's deadline, equal to the native `RELAY_RPC_DEADLINE`. */
        const val MAX_DEADLINE_MILLIS: Int = 60_000

        /** Largest check request and list page (relay `MAX_BATCH`). */
        const val MAX_BATCH: Int = 256
    }
}
