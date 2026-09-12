package org.ghost.identity

import java.nio.ByteBuffer
import java.security.SecureRandom

/**
 * Invite v2 (Phase 8 design §8.2; ADR-05 as amended by ADR-24). It carries no identity key of the
 * inviter, no web host and no payout address (T16):
 *
 * ```
 * version(1) = 2 || invite_token(354) || nonce(16) || expiry_day(4, BE, days since 1970-01-01)
 * || drop_namespace(32) || drop_slots(3, ES slot numbers, distinct) || drop_key(32, X25519 public)
 * || invite_signing_public_key(32) || signature(64, Ed25519 over everything before it)   = 538 bytes
 * ```
 *
 * Wire form: `ghost://invite/` + z-base-32(538 bytes) = 876 characters (one QR code, version 21-L).
 *
 * The invite token is a blind-signed INVITE token (RFC 9578 type 0x0002; its format belongs to the
 * Rust crate `ghost-entitlement`). Here it is opaque bytes: the only local structure check is the
 * token type, and its validity comes from [TokenCheck], the offline check against the Entitlement
 * Schedule built into the native library. The signing key, the drop namespace and the drop key are
 * derived per invite index ([RootEntropy.inviteKeys]), so two invites of one inviter share no key.
 * The invite is usable on days before `expiry_day`, and `expiry_day` never lies after the start of
 * its token's invite epoch + 2 ([maxExpiryDay]), the end of the issuer's acceptance window. Version 1
 * is refused: no v1 invite ever carried a real token.
 */
class Invite(
    inviteToken: ByteArray,
    nonce: ByteArray,
    val expiryDay: Long,
    dropNamespace: ByteArray,
    dropSlots: List<Int>,
    dropKey: ByteArray,
    inviteSigningPublicKey: ByteArray,
    signature: ByteArray,
) {
    private val token = inviteToken.copyOf()
    private val nonceBytes = nonce.copyOf()
    private val namespace = dropNamespace.copyOf()
    private val slots = dropSlots.toList()
    private val dropPublic = dropKey.copyOf()
    private val signingPublic = inviteSigningPublicKey.copyOf()
    private val sig = signature.copyOf()

    init {
        require(token.size == TOKEN_BYTES && nonceBytes.size == NONCE_BYTES && namespace.size == NAMESPACE_BYTES)
        require(dropPublic.size == KEY_BYTES && signingPublic.size == KEY_BYTES && sig.size == SIGNATURE_BYTES)
        require(expiryDay in 0..MAX_U32) { "expiry day out of range" }
        require(slotsWellFormed(slots)) { "drop slots must be $DROP_SLOTS distinct ES slot numbers" }
    }

    val version: Int get() = VERSION
    val inviteToken: ByteArray get() = token.copyOf()
    val nonce: ByteArray get() = nonceBytes.copyOf()
    val dropNamespace: ByteArray get() = namespace.copyOf()
    val dropSlots: List<Int> get() = slots
    val dropKey: ByteArray get() = dropPublic.copyOf()
    val inviteSigningPublicKey: ByteArray get() = signingPublic.copyOf()
    val signature: ByteArray get() = sig.copyOf()

    fun encode(): String = SCHEME + ZBase32.encode(bytes())

    fun bytes(): ByteArray = signedPortion(VERSION, token, nonceBytes, expiryDay, namespace, slots, dropPublic, signingPublic) + sig

    override fun equals(other: Any?): Boolean = other is Invite && other.bytes().contentEquals(bytes())

    override fun hashCode(): Int = bytes().contentHashCode()

    override fun toString(): String = "Invite(redacted)"

    /** Replay protection: an invite nonce is accepted at most once per device (FR-1.6). */
    interface NonceStore {
        /** Returns true if the nonce was not seen before and is now recorded. */
        fun recordIfFresh(nonce: ByteArray): Boolean
    }

    class InMemoryNonceStore : NonceStore {
        private val seen = HashSet<String>()
        override fun recordIfFresh(nonce: ByteArray): Boolean = seen.add(nonce.joinToString("") { "%02x".format(it) })
    }

    /**
     * Offline check of the invite token against the Entitlement Schedule (design §8.2), in
     * production the JNI `EntitlementCrypto.nativeVerifyToken(token, INVITE)`; the ES lives only in
     * the native library, so :identity sees the token as opaque bytes.
     */
    fun interface TokenCheck {
        /**
         * The INVITE epoch of [token], or null when the schedule refuses it: unknown or revoked key,
         * a token of another kind, a wrong challenge (origin, redemption context) or authenticator.
         */
        fun inviteEpoch(token: ByteArray): Long?
    }

    sealed class Rejection(message: String) : IllegalArgumentException(message) {
        class Malformed(msg: String) : Rejection(msg)
        class UnsupportedVersion : Rejection("invite version unsupported")
        class BadSignature : Rejection("invite signature invalid")
        class TokenRefused(msg: String) : Rejection(msg)
        class Expired : Rejection("invite expired")
        class Replayed : Rejection("invite already used")
    }

    companion object {
        const val VERSION = 2
        const val SCHEME = "ghost://invite/"
        const val TOKEN_BYTES = 354
        const val NONCE_BYTES = 16
        const val NAMESPACE_BYTES = 32
        const val DROP_SLOTS = 3
        const val PAYLOAD_BYTES = 1 + TOKEN_BYTES + NONCE_BYTES + 4 + NAMESPACE_BYTES + DROP_SLOTS + 32 + 32 + 64
        private const val KEY_BYTES = 32
        private const val SIGNATURE_BYTES = 64
        private const val MAX_U32 = 0xFFFF_FFFFL

        /** ES slot numbers are 0..31 (ES slot table, design §3.1). */
        const val MAX_SLOT = 31

        /** RFC 9578 token type of every GHOST token (big-endian at offset 0). */
        private const val TOKEN_TYPE = 0x0002

        // The access grid of design §4.1: ISO weeks start at 345 600 s (Monday 1970-01-05 UTC, day
        // 4), 604 800 s long; an invite epoch is 4 weeks, so invite epoch e starts on day 4 + 28·e.
        private const val DAY_SECONDS = 86_400L
        private const val FIRST_WEEK_DAY = 4L
        private const val DAYS_PER_INVITE_EPOCH = 28L

        /**
         * The latest `expiry_day` an invite whose token has INVITE epoch [inviteEpoch] may carry: the
         * start day of epoch + 2, when the issuer stops accepting that epoch (design §3.4, §8.2).
         */
        fun maxExpiryDay(inviteEpoch: Long): Long = FIRST_WEEK_DAY + DAYS_PER_INVITE_EPOCH * (inviteEpoch + 2)

        /** The invite epoch of a UTC day (days since 1970-01-01). */
        internal fun inviteEpochOfDay(day: Long): Long = Math.floorDiv(day - FIRST_WEEK_DAY, DAYS_PER_INVITE_EPOCH)

        /**
         * Creates a signed invite from index-derived [keys] (never the identity key). [inviteToken] is
         * a verified INVITE token of epoch [inviteEpoch]; [dropSlots] are 3 distinct ES slot numbers.
         */
        fun create(
            inviteToken: ByteArray,
            inviteEpoch: Long,
            expiryDay: Long,
            dropSlots: List<Int>,
            keys: InviteKeys,
            random: SecureRandom = SecureRandom(),
        ): Invite {
            require(inviteToken.size == TOKEN_BYTES && tokenType(inviteToken) == TOKEN_TYPE) { "not an RFC 9578 type 0x0002 token" }
            require(expiryDay in 0..maxExpiryDay(inviteEpoch)) { "expiry day outside the invite token's acceptance window" }
            require(slotsWellFormed(dropSlots)) { "drop slots must be $DROP_SLOTS distinct ES slot numbers" }
            val nonce = ByteArray(NONCE_BYTES).also(random::nextBytes)
            val dropPublic = keys.drop.publicKey
            val signingPublic = keys.signing.publicKey
            val namespace = keys.dropNamespace
            val signature = keys.signing.sign(signedPortion(VERSION, inviteToken, nonce, expiryDay, namespace, dropSlots, dropPublic, signingPublic))
            return Invite(inviteToken, nonce, expiryDay, namespace, dropSlots, dropPublic, signingPublic, signature)
        }

        /**
         * Parses and fully validates an invite string; fails closed on every error. Order: scheme; no
         * URL structure; exact-length decode; version; token structure; drop structure (distinct slot
         * numbers, a usable X25519 key); signature; the offline token check ([tokens]), which yields
         * the invite epoch; `expiry_day` ≤ [maxExpiryDay]; not expired; the token's epoch already
         * open; nonce replay last, so a refused invite never consumes its nonce.
         */
        fun parseAndVerify(text: String, nowUnixSeconds: Long, tokens: TokenCheck, nonceStore: NonceStore): Invite {
            val t = text.trim()
            if (!t.startsWith(SCHEME)) throw Rejection.Malformed("invite scheme invalid")
            val encoded = t.substring(SCHEME.length)
            if (encoded.contains('/') || encoded.contains('?') || encoded.contains('#') || encoded.contains('.')) {
                throw Rejection.Malformed("invite payload contains URL structure")
            }
            val payload = try {
                ZBase32.decode(encoded, PAYLOAD_BYTES)
            } catch (e: IllegalArgumentException) {
                if (peekVersion(encoded).let { it != null && it != VERSION }) throw Rejection.UnsupportedVersion()
                throw Rejection.Malformed("invite payload undecodable")
            }
            val buf = ByteBuffer.wrap(payload)
            if ((buf.get().toInt() and 0xff) != VERSION) throw Rejection.UnsupportedVersion()
            val token = ByteArray(TOKEN_BYTES).also(buf::get)
            val nonce = ByteArray(NONCE_BYTES).also(buf::get)
            val expiry = buf.getInt().toLong() and MAX_U32
            val namespace = ByteArray(NAMESPACE_BYTES).also(buf::get)
            val slots = List(DROP_SLOTS) { buf.get().toInt() and 0xff }
            val dropPublic = ByteArray(KEY_BYTES).also(buf::get)
            val signingPublic = ByteArray(KEY_BYTES).also(buf::get)
            val sig = ByteArray(SIGNATURE_BYTES).also(buf::get)
            if (tokenType(token) != TOKEN_TYPE) throw Rejection.Malformed("invite token structure invalid")
            if (!slotsWellFormed(slots)) throw Rejection.Malformed("invite drop slots invalid")
            if (!X25519KeyPair.isUsablePublicKey(dropPublic)) throw Rejection.Malformed("invite drop key invalid")
            val signed = signedPortion(VERSION, token, nonce, expiry, namespace, slots, dropPublic, signingPublic)
            if (!Ed25519KeyPair.verify(signingPublic, signed, sig)) throw Rejection.BadSignature()
            val epoch = tokens.inviteEpoch(token) ?: throw Rejection.TokenRefused("invite token refused by the schedule")
            if (epoch < 0 || expiry > maxExpiryDay(epoch)) throw Rejection.Malformed("invite expiry outside its token's acceptance window")
            val today = Math.floorDiv(nowUnixSeconds, DAY_SECONDS)
            if (expiry <= today) throw Rejection.Expired()
            if (epoch > inviteEpochOfDay(today)) throw Rejection.TokenRefused("invite token not yet valid")
            if (!nonceStore.recordIfFresh(nonce)) throw Rejection.Replayed()
            return Invite(token, nonce, expiry, namespace, slots, dropPublic, signingPublic, sig)
        }

        /** The version byte of a canonically encoded payload of another length (a v1 invite), or null. */
        private fun peekVersion(encoded: String): Int? {
            val bytes = encoded.length * 5 / 8
            if (bytes == 0 || (bytes * 8 + 4) / 5 != encoded.length) return null
            return try {
                ZBase32.decode(encoded, bytes)[0].toInt() and 0xff
            } catch (e: IllegalArgumentException) {
                null
            }
        }

        private fun tokenType(token: ByteArray): Int = ((token[0].toInt() and 0xff) shl 8) or (token[1].toInt() and 0xff)

        private fun slotsWellFormed(slots: List<Int>): Boolean =
            slots.size == DROP_SLOTS && slots.all { it in 0..MAX_SLOT } && slots.toSet().size == DROP_SLOTS

        private fun signedPortion(
            version: Int,
            token: ByteArray,
            nonce: ByteArray,
            expiryDay: Long,
            namespace: ByteArray,
            slots: List<Int>,
            dropPublic: ByteArray,
            signingPublic: ByteArray,
        ): ByteArray = ByteBuffer.allocate(PAYLOAD_BYTES - SIGNATURE_BYTES)
            .put(version.toByte()).put(token).put(nonce).putInt(expiryDay.toInt()).put(namespace)
            .put(ByteArray(DROP_SLOTS) { slots[it].toByte() }).put(dropPublic).put(signingPublic).array()
    }
}

/**
 * The per-invite key material of invite index [index] (design §8.4): Ed25519 signing key, drop
 * namespace and X25519 drop key, all derived from the root entropy ([RootEntropy.inviteKeys]), so an
 * inviter can re-derive them after a restore and never stores the drop key.
 */
class InviteKeys internal constructor(
    val index: Int,
    val signing: Ed25519KeyPair,
    dropNamespace: ByteArray,
    val drop: X25519KeyPair,
) {
    private val namespace = dropNamespace.copyOf()
    val dropNamespace: ByteArray get() = namespace.copyOf()

    override fun toString(): String = "InviteKeys(redacted)"
}
