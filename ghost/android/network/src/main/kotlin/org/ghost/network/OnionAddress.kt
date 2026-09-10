package org.ghost.network

/**
 * v3 onion address, the only destination type the network layer accepts (ADR-01, T6). Mirrors the
 * strict parser in the Rust core (`client-core/net/src/onion.rs`); validating on both sides means a
 * clearnet host can neither be typed in the UI nor smuggled through the JNI boundary.
 */
class OnionAddress private constructor(val host: String, val port: Int) {
    override fun toString(): String = "$host:$port"
    override fun equals(other: Any?): Boolean = other is OnionAddress && other.host == host && other.port == port
    override fun hashCode(): Int = 31 * host.hashCode() + port

    companion object {
        private const val V3_LABEL_LENGTH = 56
        private const val SUFFIX = ".onion"
        private val BASE32 = Regex("^[a-z2-7]+$")

        fun parse(text: String): OnionAddress {
            val t = text.trim()
            if (t.contains("://") || t.contains('/') || t.contains('?') || t.contains('#') || t.contains('@')) {
                throw IllegalArgumentException("address must be host:port without scheme or path")
            }
            val sep = t.lastIndexOf(':')
            if (sep <= 0) throw IllegalArgumentException("port is missing")
            val port = t.substring(sep + 1).toIntOrNull() ?: throw IllegalArgumentException("port is invalid")
            if (port !in 1..65535) throw IllegalArgumentException("port is invalid")
            val host = t.substring(0, sep).lowercase()
            if (!host.endsWith(SUFFIX)) throw IllegalArgumentException("address is not a .onion host")
            val label = host.removeSuffix(SUFFIX)
            if (label.length != V3_LABEL_LENGTH) throw IllegalArgumentException("onion address has wrong length")
            if (!BASE32.matches(label)) throw IllegalArgumentException("onion address contains invalid characters")
            return OnionAddress(host, port)
        }

        fun parseOrNull(text: String): OnionAddress? = try { parse(text) } catch (e: IllegalArgumentException) { null }
    }
}
