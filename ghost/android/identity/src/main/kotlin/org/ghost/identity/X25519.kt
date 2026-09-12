package org.ghost.identity

import org.bouncycastle.crypto.params.X25519PrivateKeyParameters
import org.bouncycastle.crypto.params.X25519PublicKeyParameters
import java.security.SecureRandom

/**
 * X25519 (RFC 7748) key pair on BouncyCastle, used only for referral-credit drops ([DropSeal],
 * Phase 8 design §9.3; ADR-24 extends the BouncyCastle surface of ADR-17 from Ed25519 to X25519 and
 * ChaCha20-Poly1305, deviation X15). The secret is kept clamped (RFC 7748 §5), so a derived drop key
 * and its vector are the scalar actually used.
 */
class X25519KeyPair private constructor(private val priv: X25519PrivateKeyParameters) {
    val publicKey: ByteArray get() = priv.generatePublicKey().encoded

    /**
     * X25519(secret, [peerPublicKey]). A peer key whose shared secret is all zero (a point of small
     * order, RFC 7748 §6.1) is refused, so no caller ever keys an AEAD with a public constant. Only
     * canonical encodings are accepted (bit 255 clear): RFC 7748 masks that bit, which would give
     * every key a second spelling, so one sealed blob could be re-sent under a second hash.
     */
    internal fun agree(peerPublicKey: ByteArray): ByteArray {
        require(peerPublicKey.size == KEY_BYTES) { "X25519 public key must be 32 bytes" }
        require((peerPublicKey[KEY_BYTES - 1].toInt() and 0x80) == 0) { "X25519 public key not canonical" }
        val shared = ByteArray(KEY_BYTES)
        try {
            priv.generateSecret(X25519PublicKeyParameters(peerPublicKey, 0), shared, 0)
        } catch (e: IllegalStateException) {
            // BouncyCastle refuses an all-zero result itself; both paths end in the same refusal.
            throw IllegalArgumentException("X25519 agreement refused")
        }
        require(shared.any { it != 0.toByte() }) { "X25519 agreement refused" }
        return shared
    }

    override fun toString(): String = "X25519KeyPair(redacted)"

    companion object {
        const val KEY_BYTES = 32

        /** A fresh key pair from the platform CSPRNG (an ephemeral sealing key). */
        fun generate(random: SecureRandom = SecureRandom()): X25519KeyPair {
            val secret = ByteArray(KEY_BYTES).also(random::nextBytes)
            try {
                return fromSecret(secret)
            } finally {
                secret.fill(0)
            }
        }

        /** The key pair of a 32-byte secret, clamped first; [secret] itself is left unchanged. */
        internal fun fromSecret(secret: ByteArray): X25519KeyPair {
            require(secret.size == KEY_BYTES) { "X25519 secret must be 32 bytes" }
            val clamped = clamp(secret)
            try {
                return X25519KeyPair(X25519PrivateKeyParameters(clamped, 0))
            } finally {
                clamped.fill(0)
            }
        }

        /** RFC 7748 §5 decodeScalar25519 bit operations, on a copy. */
        internal fun clamp(secret: ByteArray): ByteArray = secret.copyOf().also {
            it[0] = (it[0].toInt() and 0xf8).toByte()
            it[31] = ((it[31].toInt() and 0x7f) or 0x40).toByte()
        }

        /** Fixed probe scalar: with a clamped scalar the product is zero exactly for small-order points. */
        private val ORDER_PROBE: X25519KeyPair by lazy { fromSecret(ByteArray(KEY_BYTES) { 0x5a }) }

        /** True when [publicKey] is 32 bytes and not a point of small order. */
        internal fun isUsablePublicKey(publicKey: ByteArray): Boolean {
            if (publicKey.size != KEY_BYTES) return false
            return try {
                ORDER_PROBE.agree(publicKey).fill(0)
                true
            } catch (e: IllegalArgumentException) {
                false
            }
        }
    }
}
