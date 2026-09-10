package org.ghost.identity

import java.security.MessageDigest

/**
 * Public identity string (FR-1.3): `ghost1` + z-base-32(version || SHA-256(publicKey) || checksum),
 * where checksum = first 4 bytes of SHA-256(version || hash). 37 payload bytes → 60 characters.
 * The parser rejects wrong prefix, version, length, alphabet and checksum.
 */
data class GhostIdentity(val version: Int, val publicKeyHash: ByteArray) {
    init {
        require(version == VERSION) { "unsupported identity version" }
        require(publicKeyHash.size == HASH_BYTES) { "identity hash must be 32 bytes" }
    }

    fun encode(): String = PREFIX + ZBase32.encode(payloadWithChecksum())

    private fun payloadWithChecksum(): ByteArray {
        val body = byteArrayOf(version.toByte()) + publicKeyHash
        return body + checksum(body)
    }

    override fun equals(other: Any?): Boolean =
        other is GhostIdentity && other.version == version && other.publicKeyHash.contentEquals(publicKeyHash)

    override fun hashCode(): Int = 31 * version + publicKeyHash.contentHashCode()

    override fun toString(): String = encode()

    companion object {
        const val PREFIX = "ghost1"
        const val VERSION = 1
        private const val HASH_BYTES = 32
        private const val CHECKSUM_BYTES = 4
        private const val PAYLOAD_BYTES = 1 + HASH_BYTES + CHECKSUM_BYTES
        const val ENCODED_LENGTH = 6 + 60

        fun fromPublicKey(publicKey: ByteArray): GhostIdentity {
            require(publicKey.size == Ed25519KeyPair.PUBLIC_KEY_BYTES) { "Ed25519 public key must be 32 bytes" }
            return GhostIdentity(VERSION, sha256(publicKey))
        }

        fun parse(text: String): GhostIdentity {
            val t = text.trim()
            if (t.length != ENCODED_LENGTH) throw IllegalArgumentException("identity length invalid")
            if (!t.startsWith(PREFIX)) throw IllegalArgumentException("identity prefix invalid")
            val payload = ZBase32.decode(t.substring(PREFIX.length), PAYLOAD_BYTES)
            val version = payload[0].toInt() and 0xff
            if (version != VERSION) throw IllegalArgumentException("identity version unsupported")
            val body = payload.copyOfRange(0, 1 + HASH_BYTES)
            val checksum = payload.copyOfRange(1 + HASH_BYTES, PAYLOAD_BYTES)
            if (!checksum.contentEquals(checksum(body))) throw IllegalArgumentException("identity checksum mismatch")
            return GhostIdentity(version, body.copyOfRange(1, 1 + HASH_BYTES))
        }

        private fun checksum(body: ByteArray): ByteArray = sha256(body).copyOfRange(0, CHECKSUM_BYTES)

        private fun sha256(data: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(data)
    }
}
