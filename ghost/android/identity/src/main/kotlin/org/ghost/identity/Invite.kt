package org.ghost.identity

import java.nio.ByteBuffer
import java.security.SecureRandom

/**
 * Invite payload (ADR-05, FR-1.5). Contains no identity key of the inviter and no web host:
 *
 * ```
 * version(1) || inviteToken(32) || referralCommitment(32) || nonce(16) || expiryUnixSeconds(8)
 * || inviteSigningPublicKey(32) || signature(64 over everything before it)
 * ```
 *
 * Wire form: `ghost://invite/` + z-base-32(payload). The invite token is a blind-signed token
 * from the issuer; its validity is checked offline by the issuer's public key at redeem time
 * (Phase 8). The inviter is identified to the invitee only by an ephemeral invite-signing key.
 */
data class Invite(
    val version: Int,
    val inviteToken: ByteArray,
    val referralCommitment: ByteArray,
    val nonce: ByteArray,
    val expiryUnixSeconds: Long,
    val inviteSigningPublicKey: ByteArray,
    val signature: ByteArray,
) {
    init {
        require(version == VERSION) { "unsupported invite version" }
        require(inviteToken.size == 32 && referralCommitment.size == 32 && nonce.size == 16)
        require(inviteSigningPublicKey.size == 32 && signature.size == 64)
    }

    fun encode(): String = SCHEME + ZBase32.encode(bytes())

    fun bytes(): ByteArray = signedPortion() + signature

    private fun signedPortion(): ByteArray = signedPortion(version, inviteToken, referralCommitment, nonce, expiryUnixSeconds, inviteSigningPublicKey)

    override fun equals(other: Any?): Boolean = other is Invite && other.bytes().contentEquals(bytes())

    override fun hashCode(): Int = bytes().contentHashCode()

    /** Replay protection: an invite nonce is accepted at most once per device (FR-1.6). */
    interface NonceStore {
        /** Returns true if the nonce was not seen before and is now recorded. */
        fun recordIfFresh(nonce: ByteArray): Boolean
    }

    class InMemoryNonceStore : NonceStore {
        private val seen = HashSet<String>()
        override fun recordIfFresh(nonce: ByteArray): Boolean = seen.add(nonce.joinToString("") { "%02x".format(it) })
    }

    sealed class Rejection(message: String) : IllegalArgumentException(message) {
        class Malformed(msg: String) : Rejection(msg)
        class Expired : Rejection("invite expired")
        class BadSignature : Rejection("invite signature invalid")
        class Replayed : Rejection("invite already used")
    }

    companion object {
        const val VERSION = 1
        const val SCHEME = "ghost://invite/"
        private const val PAYLOAD_BYTES = 1 + 32 + 32 + 16 + 8 + 32 + 64

        /** Creates a signed invite. `inviteSigning` is the inviter's ephemeral key (never the identity key). */
        fun create(
            inviteToken: ByteArray,
            referralCommitment: ByteArray,
            expiryUnixSeconds: Long,
            inviteSigning: Ed25519KeyPair,
            random: SecureRandom = SecureRandom(),
        ): Invite {
            val nonce = ByteArray(16).also(random::nextBytes)
            val pub = inviteSigning.publicKey
            val signature = inviteSigning.sign(signedPortion(VERSION, inviteToken, referralCommitment, nonce, expiryUnixSeconds, pub))
            return Invite(VERSION, inviteToken, referralCommitment, nonce, expiryUnixSeconds, pub, signature)
        }

        /**
         * Parses and fully validates an invite string. Order of checks: scheme/length/alphabet,
         * version, signature, expiry, replay. Fails closed on every error.
         */
        fun parseAndVerify(text: String, nowUnixSeconds: Long, nonceStore: NonceStore): Invite {
            val t = text.trim()
            if (!t.startsWith(SCHEME)) throw Rejection.Malformed("invite scheme invalid")
            val encoded = t.substring(SCHEME.length)
            if (encoded.contains('/') || encoded.contains('?') || encoded.contains('#') || encoded.contains('.')) {
                throw Rejection.Malformed("invite payload contains URL structure")
            }
            val payload = try {
                ZBase32.decode(encoded, PAYLOAD_BYTES)
            } catch (e: IllegalArgumentException) {
                throw Rejection.Malformed("invite payload undecodable")
            }
            val buf = ByteBuffer.wrap(payload)
            val version = buf.get().toInt() and 0xff
            if (version != VERSION) throw Rejection.Malformed("invite version unsupported")
            val token = ByteArray(32).also(buf::get)
            val commitment = ByteArray(32).also(buf::get)
            val nonce = ByteArray(16).also(buf::get)
            val expiry = buf.getLong()
            val pub = ByteArray(32).also(buf::get)
            val sig = ByteArray(64).also(buf::get)
            val signed = signedPortion(version, token, commitment, nonce, expiry, pub)
            if (!Ed25519KeyPair.verify(pub, signed, sig)) throw Rejection.BadSignature()
            if (expiry <= nowUnixSeconds) throw Rejection.Expired()
            if (!nonceStore.recordIfFresh(nonce)) throw Rejection.Replayed()
            return Invite(version, token, commitment, nonce, expiry, pub, sig)
        }

        private fun signedPortion(
            version: Int,
            token: ByteArray,
            commitment: ByteArray,
            nonce: ByteArray,
            expiry: Long,
            pub: ByteArray,
        ): ByteArray = ByteBuffer.allocate(1 + 32 + 32 + 16 + 8 + 32)
            .put(version.toByte()).put(token).put(commitment).put(nonce).putLong(expiry).put(pub).array()
    }
}
