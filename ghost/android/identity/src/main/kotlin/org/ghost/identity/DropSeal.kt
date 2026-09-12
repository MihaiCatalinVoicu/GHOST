package org.ghost.identity

import org.bouncycastle.crypto.InvalidCipherTextException
import org.bouncycastle.crypto.modes.ChaCha20Poly1305
import org.bouncycastle.crypto.params.AEADParameters
import org.bouncycastle.crypto.params.KeyParameter
import java.security.SecureRandom

/**
 * Sealed referral-credit drop (Phase 8 design §9.3, §19.12; ADR-24, deviation X15). An invited
 * identity writes exactly one blob into its inviter's drop namespace: the credit of its first XMR
 * pack, or a dummy sealed identically, so relays cannot tell the two apart.
 *
 * ```
 * eph  <- X25519 key pair (fresh)
 * key  = HKDF-SHA256(ikm = X25519(eph, drop_key), salt = drop_namespace, info = "ghost/v1/drop-seal", L = 32)
 * blob = eph_pub(32) || ChaCha20-Poly1305(key, nonce = 0^12, aad = drop_namespace,
 *                                         plaintext = 0x01 || credit_token(354) || zero padding to 976 bytes)
 *      = 32 + 976 + 16 = 1 024 bytes: exactly one 1 KiB bucket (T9)
 * ```
 *
 * A dummy's plaintext is `0x00` followed by zeros. The all-zero nonce is safe because every blob
 * has a fresh ephemeral key and therefore a fresh AEAD key. HKDF is the platform one ([Hkdf]); X25519
 * and the AEAD are BouncyCastle. The credit token is opaque here (RFC 9578 type 0x0002, verified
 * against the Entitlement Schedule by the receiver before any use).
 */
object DropSeal {
    const val BLOB_BYTES = 1024
    const val PLAINTEXT_BYTES = 976
    const val CREDIT_TOKEN_BYTES = 354
    const val NAMESPACE_BYTES = 32
    private const val TAG_BYTES = 16
    private const val NONCE_BYTES = 12
    private const val TAG_BITS = TAG_BYTES * 8
    private const val MARK_DUMMY: Byte = 0x00
    private const val MARK_CREDIT: Byte = 0x01
    private val INFO = "ghost/v1/drop-seal".toByteArray(Charsets.UTF_8)

    /** What an inviter finds in a drop blob. [Invalid] blobs are consumed and dropped by the caller. */
    sealed class Opened {
        object Dummy : Opened() {
            override fun toString(): String = "Dummy"
        }

        class Credit internal constructor(token: ByteArray) : Opened() {
            private val raw = token.copyOf()
            val token: ByteArray get() = raw.copyOf()
            override fun toString(): String = "Credit(redacted)"
        }

        object Invalid : Opened() {
            override fun toString(): String = "Invalid"
        }
    }

    /** Seals [creditToken] to the drop ([dropKey], [dropNamespace]) of an invite. */
    fun sealCredit(creditToken: ByteArray, dropKey: ByteArray, dropNamespace: ByteArray, random: SecureRandom = SecureRandom()): ByteArray {
        require(creditToken.size == CREDIT_TOKEN_BYTES) { "credit token must be $CREDIT_TOKEN_BYTES bytes" }
        val plaintext = ByteArray(PLAINTEXT_BYTES)
        plaintext[0] = MARK_CREDIT
        creditToken.copyInto(plaintext, 1)
        return sealWithFreshKey(plaintext, dropKey, dropNamespace, random)
    }

    /** Seals the dummy, indistinguishable from a credit blob without the drop key. */
    fun sealDummy(dropKey: ByteArray, dropNamespace: ByteArray, random: SecureRandom = SecureRandom()): ByteArray =
        sealWithFreshKey(ByteArray(PLAINTEXT_BYTES), dropKey, dropNamespace, random)

    private fun sealWithFreshKey(plaintext: ByteArray, dropKey: ByteArray, dropNamespace: ByteArray, random: SecureRandom): ByteArray {
        try {
            return seal(plaintext, dropKey, dropNamespace, X25519KeyPair.generate(random))
        } finally {
            plaintext.fill(0)
        }
    }

    /** The sealing construction with an explicit ephemeral key (vectors). */
    internal fun seal(plaintext: ByteArray, dropKey: ByteArray, dropNamespace: ByteArray, ephemeral: X25519KeyPair): ByteArray {
        require(plaintext.size == PLAINTEXT_BYTES) { "drop plaintext must be $PLAINTEXT_BYTES bytes" }
        require(dropNamespace.size == NAMESPACE_BYTES) { "drop namespace must be $NAMESPACE_BYTES bytes" }
        val key = blobKey(ephemeral, dropKey, dropNamespace)
        try {
            return ephemeral.publicKey + aead(encrypt = true, key = key, nonce = ByteArray(NONCE_BYTES), aad = dropNamespace, input = plaintext)
        } finally {
            key.fill(0)
        }
    }

    /**
     * Opens a blob with the inviter's [drop] key pair. Anything but an authentic blob of exactly one
     * of the two plaintext shapes (credit with zero padding, all-zero dummy) is [Opened.Invalid].
     */
    fun open(blob: ByteArray, drop: X25519KeyPair, dropNamespace: ByteArray): Opened {
        require(dropNamespace.size == NAMESPACE_BYTES) { "drop namespace must be $NAMESPACE_BYTES bytes" }
        if (blob.size != BLOB_BYTES) return Opened.Invalid
        val ephemeralPublic = blob.copyOfRange(0, X25519KeyPair.KEY_BYTES)
        val key = try {
            blobKey(drop, ephemeralPublic, dropNamespace)
        } catch (e: IllegalArgumentException) {
            return Opened.Invalid
        }
        val plaintext = try {
            aead(encrypt = false, key = key, nonce = ByteArray(NONCE_BYTES), aad = dropNamespace, input = blob.copyOfRange(X25519KeyPair.KEY_BYTES, BLOB_BYTES))
        } catch (e: InvalidCipherTextException) {
            return Opened.Invalid
        } finally {
            key.fill(0)
        }
        try {
            return when (plaintext[0]) {
                MARK_DUMMY -> if (allZero(plaintext, 1)) Opened.Dummy else Opened.Invalid
                MARK_CREDIT ->
                    if (allZero(plaintext, 1 + CREDIT_TOKEN_BYTES)) Opened.Credit(plaintext.copyOfRange(1, 1 + CREDIT_TOKEN_BYTES)) else Opened.Invalid
                else -> Opened.Invalid
            }
        } finally {
            plaintext.fill(0)
        }
    }

    /** HKDF-SHA256(ikm = X25519(own, peer), salt = namespace, info = "ghost/v1/drop-seal", 32). */
    private fun blobKey(own: X25519KeyPair, peerPublicKey: ByteArray, dropNamespace: ByteArray): ByteArray {
        val shared = own.agree(peerPublicKey)
        try {
            return Hkdf.derive(ikm = shared, salt = dropNamespace, info = INFO, length = 32)
        } finally {
            shared.fill(0)
        }
    }

    /** ChaCha20-Poly1305 (RFC 8439) with a 16-byte tag appended to the ciphertext. */
    internal fun aead(encrypt: Boolean, key: ByteArray, nonce: ByteArray, aad: ByteArray, input: ByteArray): ByteArray {
        val cipher = ChaCha20Poly1305()
        cipher.init(encrypt, AEADParameters(KeyParameter(key), TAG_BITS, nonce, aad))
        val out = ByteArray(cipher.getOutputSize(input.size))
        val written = cipher.processBytes(input, 0, input.size, out, 0)
        val total = written + cipher.doFinal(out, written)
        return if (total == out.size) out else out.copyOf(total)
    }

    private fun allZero(bytes: ByteArray, from: Int): Boolean {
        var acc = 0
        for (i in from until bytes.size) acc = acc or bytes[i].toInt()
        return acc == 0
    }
}
