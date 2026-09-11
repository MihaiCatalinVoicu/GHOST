package org.ghost.network

import org.bouncycastle.crypto.digests.SHA3Digest

/**
 * v3 onion address, the only destination type the network layer accepts (ADR-01, T6). Mirrors the
 * strict parser in the Rust core (`client-core/net/src/onion.rs`), including the v3 version byte
 * and SHA3-256 checksum; both are tested against the same vector file
 * (`protocol/test-vectors/onion_addresses.txt`), so a clearnet host or a mistyped address can
 * neither be entered in the UI nor smuggled through the JNI boundary.
 */
class OnionAddress private constructor(val host: String, val port: Int) {
    override fun toString(): String = "$host:$port"
    override fun equals(other: Any?): Boolean = other is OnionAddress && other.host == host && other.port == port
    override fun hashCode(): Int = 31 * host.hashCode() + port

    companion object {
        private const val V3_LABEL_LENGTH = 56
        private const val SUFFIX = ".onion"
        private const val BASE32 = "abcdefghijklmnopqrstuvwxyz234567"
        private val CHECKSUM_PREFIX = ".onion checksum".toByteArray(Charsets.US_ASCII)
        private const val VERSION: Byte = 3

        fun parse(text: String): OnionAddress {
            // Only ASCII space and tab are trimmed, exactly like the Rust parser (String.trim()
            // would also strip other control characters and disagree with Rust).
            val t = text.trim { it == ' ' || it == '\t' }
            if (t.any { it.code >= 0x80 }) throw IllegalArgumentException("address must be ASCII")
            if (t.any { it.code < 0x20 || it.code == 0x7f }) throw IllegalArgumentException("address contains control characters")
            if (t.contains("://") || t.contains('/') || t.contains('?') || t.contains('#') || t.contains('@')) {
                throw IllegalArgumentException("address must be host:port without scheme or path")
            }
            val sep = t.lastIndexOf(':')
            if (sep <= 0) throw IllegalArgumentException("port is missing")
            val port = t.substring(sep + 1).toIntOrNull() ?: throw IllegalArgumentException("port is invalid")
            if (port !in 1..65535) throw IllegalArgumentException("port is invalid")
            val host = asciiLower(t.substring(0, sep))
            if (!host.endsWith(SUFFIX)) throw IllegalArgumentException("address is not a .onion host")
            val label = host.removeSuffix(SUFFIX)
            if (label.length != V3_LABEL_LENGTH) throw IllegalArgumentException("onion address has wrong length")
            if (label.any { BASE32.indexOf(it) < 0 }) throw IllegalArgumentException("onion address contains invalid characters")
            if (!checksumValid(label)) throw IllegalArgumentException("onion address has a wrong v3 version or checksum")
            return OnionAddress(host, port)
        }

        fun parseOrNull(text: String): OnionAddress? = try { parse(text) } catch (e: IllegalArgumentException) { null }

        /** Lowercases A-Z only (the Rust side uses to_ascii_lowercase; no Unicode case folding). */
        private fun asciiLower(s: String): String =
            buildString(s.length) { for (c in s) append(if (c in 'A'..'Z') c + 32 else c) }

        /** 35 bytes = pubkey(32) || checksum(2) || version(1); checksum = SHA3-256(prefix||pubkey||version)[0..2]. */
        private fun checksumValid(label: String): Boolean {
            val raw = base32Decode(label) ?: return false
            if (raw.size != 35 || raw[34] != VERSION) return false
            val digest = SHA3Digest(256)
            digest.update(CHECKSUM_PREFIX, 0, CHECKSUM_PREFIX.size)
            digest.update(raw, 0, 32)
            digest.update(VERSION)
            val out = ByteArray(32)
            digest.doFinal(out, 0)
            return out[0] == raw[32] && out[1] == raw[33]
        }

        private fun base32Decode(s: String): ByteArray? {
            val out = ByteArray(s.length * 5 / 8)
            var buffer = 0
            var bits = 0
            var i = 0
            for (c in s) {
                val v = BASE32.indexOf(c)
                if (v < 0) return null
                buffer = (buffer shl 5) or v
                bits += 5
                if (bits >= 8) {
                    bits -= 8
                    out[i++] = ((buffer shr bits) and 0xff).toByte()
                }
            }
            return out
        }
    }
}
