package org.ghost.network

import java.io.File
import java.lang.ref.Reference
import java.util.concurrent.atomic.AtomicLong

/**
 * Constant-category failure from the native layer; carries no relay or network detail (§11.1).
 * The category strings are listed in `client-core/README.md` (source: `categories.rs`).
 * Kept by R8 (`consumer-rules.pro`): native code throws it by class name.
 */
class NetworkException(val category: String) : RuntimeException(category)

/**
 * Android face of the Rust network core (`libghost_client_net.so`, ADR-19). All traffic goes
 * through the embedded Tor client to [OnionAddress] destinations; there is no other path. Each
 * namespace uses its own circuit isolation (ADR-09).
 *
 * Blocking calls: run them off the main thread. Every relay call is bounded natively (60 s), and
 * [close] may be called from any thread at any time: it is idempotent, never frees state under an
 * in-flight call, and makes in-flight calls fail with category `closed`.
 *
 * Blobs must already be encrypted and exactly bucket-sized ([BUCKET_SIZES]); padding belongs
 * inside the AEAD plaintext of the encrypting layer, never on the ciphertext.
 */
class TorRelayTransport private constructor(id: Long) : AutoCloseable {
    private val handle = AtomicLong(id)

    /**
     * Bootstraps Tor (bounded natively at 180 s). [close] from another thread aborts it. After a
     * failure with category `tor_bootstrap_timeout` (or an aborted attempt) this transport cannot
     * bootstrap again: [close] it and [create] a new one.
     */
    fun bootstrap() = call { nativeBootstrap(it) }

    data class StoreReceipt(val blobHash: ByteArray, val expiryUnixSeconds: Long)

    /**
     * Stores an encrypted, bucket-sized blob. `ttlSeconds` is rounded up natively to the next
     * allowed bucket (1, 7, 30 or 90 days; relays only ever see the bucket); values above 90 days
     * are rejected. The receipt's expiry is checked natively against the bucketed TTL (category
     * `not_stored` if the relay would drop the blob early).
     */
    fun store(relay: OnionAddress, namespace: ByteArray, capability: ByteArray, ciphertext: ByteArray, ttlSeconds: Int): StoreReceipt {
        require(namespace.size == 32) { "namespace must be 32 bytes" }
        require(ttlSeconds in 1..MAX_TTL_SECONDS) { "ttl must be 1 s .. 90 days" }
        require(ciphertext.size in BUCKET_SIZES) { "ciphertext must be exactly one padding bucket" }
        val raw = call { nativeStore(it, relay.toString(), namespace, capability, ciphertext, ttlSeconds) }
        return decodeReceipt(raw)
    }

    fun get(relay: OnionAddress, namespace: ByteArray, capability: ByteArray, blobHash: ByteArray): ByteArray {
        require(namespace.size == 32 && blobHash.size == 32)
        return call { nativeGet(it, relay.toString(), namespace, capability, blobHash) }
    }

    data class Page(val hashes: List<ByteArray>, val nextCursor: ByteArray)

    fun list(relay: OnionAddress, namespace: ByteArray, capability: ByteArray, cursor: ByteArray, limit: Int): Page {
        require(namespace.size == 32 && limit in 1..256 && (cursor.isEmpty() || cursor.size == 8))
        val raw = call { nativeList(it, relay.toString(), namespace, capability, cursor, limit) }
        return decodePage(raw, limit)
    }

    /** Drops every isolation token so the next request per scope builds fresh circuits. */
    fun rotateCircuits() = call { nativeRotateCircuits(it) }

    override fun close() {
        val id = handle.getAndSet(0L)
        if (id != 0L) nativeStop(id)
    }

    /**
     * Backstop for a transport that was never closed (e.g. a caller abandoned a stalled
     * bootstrap): stops the native Tor client instead of letting it run for the process lifetime.
     * java.lang.ref.Cleaner is only available from API 33; minSdk is 29.
     */
    @Suppress("deprecation")
    protected fun finalize() = close()

    private fun requireHandle(): Long {
        val id = handle.get()
        if (id == 0L) throw NetworkException("closed")
        return id
    }

    /**
     * Runs a native call with this transport's id. The native methods only receive the id, so
     * without the fence the runtime could finalize this object mid-call (finalize -> close) and
     * cancel the call with a spurious `closed`.
     */
    private inline fun <T> call(block: (Long) -> T): T {
        val id = requireHandle()
        try {
            return block(id)
        } finally {
            Reference.reachabilityFence(this)
        }
    }

    companion object {
        /** Exact blob sizes a relay accepts (FR-2.5, ADR-09). */
        val BUCKET_SIZES: Set<Int> = setOf(1024, 4096, 16384, 65536)

        const val MAX_TTL_SECONDS: Int = 90 * 86_400

        /**
         * Loaded on first use, not at class load, so pure-JVM code paths stay testable. A missing
         * or unloadable library surfaces as category `native_missing`, not as an Error.
         */
        private val nativeLibrary: Unit by lazy {
            try {
                System.loadLibrary("ghost_client_net")
            } catch (e: UnsatisfiedLinkError) {
                throw NetworkException("native_missing")
            }
        }

        /**
         * Creates the Tor client without network access. State lives under `stateDir` (must be
         * app-private, no-backup). `bridgeLines` empty = direct Tor; otherwise plain
         * `IP:PORT FINGERPRINT` bridges only (pluggable transports arrive in Faza 12; other lines
         * fail with category `bridge_config`). Call [bootstrap] next, or use [start].
         */
        fun create(stateDir: File, cacheDir: File, bridgeLines: List<String> = emptyList()): TorRelayTransport {
            nativeLibrary
            stateDir.mkdirs(); cacheDir.mkdirs()
            val id = nativeCreate(stateDir.absolutePath, cacheDir.absolutePath, bridgeLines.joinToString("\n"))
            if (id == 0L) throw NetworkException("internal")
            return TorRelayTransport(id)
        }

        /**
         * [create] + [bootstrap]; closes the transport if bootstrap fails. Blocks up to 180 s and
         * cannot be interrupted from outside: callers that need to abort use [create], keep the
         * reference, and [close] it from another thread.
         */
        fun start(stateDir: File, cacheDir: File, bridgeLines: List<String> = emptyList()): TorRelayTransport {
            val t = create(stateDir, cacheDir, bridgeLines)
            try {
                t.bootstrap()
            } catch (e: Throwable) {
                t.close()
                throw e
            }
            return t
        }

        /** Wire format from the native side: `blobHash(32) || expiryUnixSeconds(8, big-endian)`. */
        internal fun decodeReceipt(raw: ByteArray): StoreReceipt {
            if (raw.size != 40) throw NetworkException("malformed_response")
            var expiry = 0L
            for (i in 32 until 40) expiry = (expiry shl 8) or (raw[i].toLong() and 0xff)
            return StoreReceipt(raw.copyOfRange(0, 32), expiry)
        }

        /**
         * Wire format from the native side: `cursorLen(1) || cursor || hashes(32 each)`, cursor 0
         * or 8 bytes, at most [limit] hashes (the native side enforces the same bounds).
         */
        internal fun decodePage(raw: ByteArray, limit: Int): Page {
            if (raw.isEmpty()) throw NetworkException("malformed_response")
            val cursorLen = raw[0].toInt() and 0xff
            if ((cursorLen != 0 && cursorLen != 8) || raw.size < 1 + cursorLen || (raw.size - 1 - cursorLen) % 32 != 0) {
                throw NetworkException("malformed_response")
            }
            if ((raw.size - 1 - cursorLen) / 32 > limit) throw NetworkException("malformed_response")
            val cursor = raw.copyOfRange(1, 1 + cursorLen)
            val hashes = ArrayList<ByteArray>()
            var i = 1 + cursorLen
            while (i < raw.size) { hashes += raw.copyOfRange(i, i + 32); i += 32 }
            return Page(hashes, cursor)
        }

        @JvmStatic private external fun nativeCreate(stateDir: String, cacheDir: String, bridgeLines: String): Long
        @JvmStatic private external fun nativeBootstrap(id: Long)
        @JvmStatic private external fun nativeStop(id: Long)
        @JvmStatic private external fun nativeRotateCircuits(id: Long)
        @JvmStatic private external fun nativeStore(id: Long, relay: String, namespace: ByteArray, capability: ByteArray, ciphertext: ByteArray, ttlSeconds: Int): ByteArray
        @JvmStatic private external fun nativeGet(id: Long, relay: String, namespace: ByteArray, capability: ByteArray, blobHash: ByteArray): ByteArray
        @JvmStatic private external fun nativeList(id: Long, relay: String, namespace: ByteArray, capability: ByteArray, cursor: ByteArray, limit: Int): ByteArray
    }
}
