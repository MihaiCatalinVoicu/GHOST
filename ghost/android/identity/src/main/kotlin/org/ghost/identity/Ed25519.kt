package org.ghost.identity

import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters
import org.bouncycastle.crypto.signers.Ed25519Signer

/** Ed25519 (RFC 8032) key pair derived deterministically from a 32-byte seed (ADR-17). */
class Ed25519KeyPair private constructor(private val priv: Ed25519PrivateKeyParameters) {
    val publicKey: ByteArray get() = priv.generatePublicKey().encoded

    fun sign(message: ByteArray): ByteArray {
        val signer = Ed25519Signer()
        signer.init(true, priv)
        signer.update(message, 0, message.size)
        return signer.generateSignature()
    }

    companion object {
        const val SEED_BYTES = 32
        const val PUBLIC_KEY_BYTES = 32
        const val SIGNATURE_BYTES = 64

        fun fromSeed(seed: ByteArray): Ed25519KeyPair {
            require(seed.size == SEED_BYTES) { "Ed25519 seed must be 32 bytes" }
            return Ed25519KeyPair(Ed25519PrivateKeyParameters(seed, 0))
        }

        fun verify(publicKey: ByteArray, message: ByteArray, signature: ByteArray): Boolean {
            if (publicKey.size != PUBLIC_KEY_BYTES || signature.size != SIGNATURE_BYTES) return false
            return try {
                val verifier = Ed25519Signer()
                verifier.init(false, Ed25519PublicKeyParameters(publicKey, 0))
                verifier.update(message, 0, message.size)
                verifier.verifySignature(signature)
            } catch (e: IllegalArgumentException) {
                false
            }
        }
    }
}
