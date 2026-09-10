package org.ghost.identity

import java.nio.ByteBuffer

/**
 * Device/identity revocation certificate (FR-1.9, ADR-14). Signed with the identity key and
 * published as an opaque blob in the identity's namespace; contacts and groups that fetch it stop
 * trusting the revoked key. Recovery: re-derive from the mnemonic on a clean device and re-verify
 * safety numbers.
 *
 * ```
 * version(1) || identityPublicKey(32) || issuedAtUnixSeconds(8) || reason(1) || signature(64)
 * ```
 */
data class RevocationCertificate(
    val version: Int,
    val identityPublicKey: ByteArray,
    val issuedAtUnixSeconds: Long,
    val reason: Reason,
    val signature: ByteArray,
) {
    enum class Reason(val code: Byte) {
        DEVICE_LOST(1),
        DEVICE_COMPROMISED(2),
        KEY_ROTATION(3);

        companion object {
            fun fromCode(code: Byte): Reason? = entries.firstOrNull { it.code == code }
        }
    }

    init {
        require(version == VERSION)
        require(identityPublicKey.size == Ed25519KeyPair.PUBLIC_KEY_BYTES && signature.size == Ed25519KeyPair.SIGNATURE_BYTES)
    }

    fun bytes(): ByteArray = signedPortion(version, identityPublicKey, issuedAtUnixSeconds, reason) + signature

    /** The identity this certificate revokes; consumers compare it with the contact's known identity. */
    fun revokedIdentity(): GhostIdentity = GhostIdentity.fromPublicKey(identityPublicKey)

    override fun equals(other: Any?): Boolean = other is RevocationCertificate && other.bytes().contentEquals(bytes())

    override fun hashCode(): Int = bytes().contentHashCode()

    companion object {
        const val VERSION = 1
        private const val TOTAL_BYTES = 1 + 32 + 8 + 1 + 64

        fun issue(identity: Ed25519KeyPair, issuedAtUnixSeconds: Long, reason: Reason): RevocationCertificate {
            val pub = identity.publicKey
            val sig = identity.sign(signedPortion(VERSION, pub, issuedAtUnixSeconds, reason))
            return RevocationCertificate(VERSION, pub, issuedAtUnixSeconds, reason, sig)
        }

        /** Parses and verifies; a certificate that does not verify under its own key is rejected. */
        fun parseAndVerify(bytes: ByteArray): RevocationCertificate {
            if (bytes.size != TOTAL_BYTES) throw IllegalArgumentException("revocation certificate length invalid")
            val buf = ByteBuffer.wrap(bytes)
            val version = buf.get().toInt() and 0xff
            if (version != VERSION) throw IllegalArgumentException("revocation certificate version unsupported")
            val pub = ByteArray(32).also(buf::get)
            val issuedAt = buf.getLong()
            val reason = Reason.fromCode(buf.get()) ?: throw IllegalArgumentException("revocation reason unknown")
            val sig = ByteArray(64).also(buf::get)
            if (!Ed25519KeyPair.verify(pub, signedPortion(version, pub, issuedAt, reason), sig)) {
                throw IllegalArgumentException("revocation certificate signature invalid")
            }
            return RevocationCertificate(version, pub, issuedAt, reason, sig)
        }

        private fun signedPortion(version: Int, pub: ByteArray, issuedAt: Long, reason: Reason): ByteArray =
            ByteBuffer.allocate(1 + 32 + 8 + 1).put(version.toByte()).put(pub).putLong(issuedAt).put(reason.code).array()
    }
}
