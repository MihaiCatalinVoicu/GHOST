package org.ghost.network

import java.io.File

/** Constant-category failure from the native layer; carries no relay or network detail (§11.1). */
class NetworkException(category: String) : RuntimeException(category)

/**
 * Android face of the Rust network core (`libghost_client_net.so`, ADR-19). All traffic goes
 * through the embedded Tor client to [OnionAddress] destinations; there is no other path. Each
 * namespace uses its own circuit isolation (ADR-09). Blocking calls: run off the main thread.
 */
class TorRelayTransport private constructor(private var handle: Long) : AutoCloseable {

    fun store(relay: OnionAddress, namespace: ByteArray, capability: ByteArray, payload: ByteArray, ttlSeconds: Int): ByteArray {
        require(namespace.size == 32 && ttlSeconds > 0)
        return nativeStore(requireHandle(), relay.toString(), namespace, capability, payload, ttlSeconds)
    }

    fun get(relay: OnionAddress, namespace: ByteArray, capability: ByteArray, blobHash: ByteArray): ByteArray {
        require(namespace.size == 32 && blobHash.size == 32)
        return nativeGet(requireHandle(), relay.toString(), namespace, capability, blobHash)
    }

    data class Page(val hashes: List<ByteArray>, val nextCursor: ByteArray)

    fun list(relay: OnionAddress, namespace: ByteArray, capability: ByteArray, cursor: ByteArray, limit: Int): Page {
        require(namespace.size == 32 && limit in 1..256)
        val raw = nativeList(requireHandle(), relay.toString(), namespace, capability, cursor, limit)
        return decodePage(raw)
    }

    /** Drops every isolation token so the next request per scope builds fresh circuits. */
    fun rotateCircuits() = nativeRotateCircuits(requireHandle())

    override fun close() {
        if (handle != 0L) {
            nativeStop(handle)
            handle = 0L
        }
    }

    private fun requireHandle(): Long {
        check(handle != 0L) { "transport is closed" }
        return handle
    }

    companion object {
        /** Loaded on first [start], not at class load, so pure-JVM code paths stay testable. */
        private val nativeLibrary: Unit by lazy { System.loadLibrary("ghost_client_net") }

        /**
         * Bootstraps Tor with state under `stateDir` (must be app-private, no-backup). `bridgeLines`
         * empty = direct Tor; otherwise only the given bridges are used (ADR-16).
         */
        fun start(stateDir: File, cacheDir: File, bridgeLines: List<String> = emptyList()): TorRelayTransport {
            nativeLibrary
            stateDir.mkdirs(); cacheDir.mkdirs()
            val handle = nativeStart(stateDir.absolutePath, cacheDir.absolutePath, bridgeLines.joinToString("\n"))
            if (handle == 0L) throw NetworkException("tor_bootstrap")
            return TorRelayTransport(handle)
        }

        /** Wire format from the native side: `cursorLen(1) || cursor || hashes(32 each)`. */
        internal fun decodePage(raw: ByteArray): Page {
            if (raw.isEmpty()) throw NetworkException("malformed_response")
            val cursorLen = raw[0].toInt() and 0xff
            if (raw.size < 1 + cursorLen || (raw.size - 1 - cursorLen) % 32 != 0) throw NetworkException("malformed_response")
            val cursor = raw.copyOfRange(1, 1 + cursorLen)
            val hashes = ArrayList<ByteArray>()
            var i = 1 + cursorLen
            while (i < raw.size) { hashes += raw.copyOfRange(i, i + 32); i += 32 }
            return Page(hashes, cursor)
        }

        @JvmStatic private external fun nativeStart(stateDir: String, cacheDir: String, bridgeLines: String): Long
        @JvmStatic private external fun nativeStop(handle: Long)
        @JvmStatic private external fun nativeRotateCircuits(handle: Long)
        @JvmStatic private external fun nativeStore(handle: Long, relay: String, namespace: ByteArray, capability: ByteArray, payload: ByteArray, ttlSeconds: Int): ByteArray
        @JvmStatic private external fun nativeGet(handle: Long, relay: String, namespace: ByteArray, capability: ByteArray, blobHash: ByteArray): ByteArray
        @JvmStatic private external fun nativeList(handle: Long, relay: String, namespace: ByteArray, capability: ByteArray, cursor: ByteArray, limit: Int): ByteArray
    }
}
