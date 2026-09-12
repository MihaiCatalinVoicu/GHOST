package org.ghost.identity

import java.security.SecureRandom

/**
 * The root of the key hierarchy (spec v2.0 §7.1, Figure 2). 256 bits from the platform CSPRNG,
 * backed up as a 24-word mnemonic, never derived from an address or a reusable signature.
 */
class RootEntropy private constructor(private val bytes: ByteArray) {
    init {
        require(bytes.size == Bip39.ENTROPY_BYTES) { "root entropy must be 32 bytes" }
    }

    fun toMnemonic(): List<String> = Bip39.encode(bytes)

    /** Raw entropy for the Keystore-wrapped envelope only (TB-1). Never logged, never exported in clear. */
    fun rawForWrapping(): ByteArray = bytes.copyOf()

    /** HKDF-SHA-256 over the root entropy with a versioned domain label (§7.1 step 3). */
    fun deriveBranch(label: String, length: Int = 32): ByteArray =
        Hkdf.derive(ikm = bytes, salt = null, info = label.toByteArray(Charsets.UTF_8), length = length)

    /**
     * Per-channel pseudonym seed (ADR-04): info = label || len(channelId) || channelId. The length
     * prefix makes the encoding injective, so no two channel ids can produce the same info.
     */
    fun deriveChannelPseudonymSeed(channelId: ByteArray): ByteArray {
        require(channelId.size in 1..255) { "channel id must be 1..255 bytes" }
        val info = DerivationLabels.CHANNEL_PSEUDONYM.toByteArray(Charsets.UTF_8) +
            byteArrayOf(channelId.size.toByte()) + channelId
        return Hkdf.derive(ikm = bytes, salt = null, info = info, length = 32)
    }

    /**
     * Per-invite branch (Phase 8 design §8.4, ADR-24): info = label || u16_be(index). The suffix has
     * a fixed length, so the encoding is injective and never equals a bare label (no label is a
     * prefix of another, see DerivationLabelsTest).
     */
    private fun deriveInviteBranch(label: String, index: Int): ByteArray {
        require(index in 0..MAX_INVITE_INDEX) { "invite index must be 0..$MAX_INVITE_INDEX" }
        val info = label.toByteArray(Charsets.UTF_8) + byteArrayOf((index ushr 8).toByte(), index.toByte())
        return Hkdf.derive(ikm = bytes, salt = null, info = info, length = 32)
    }

    fun identityKeyPair(): Ed25519KeyPair = Ed25519KeyPair.fromSeed(deriveBranch(DerivationLabels.IDENTITY))

    /** Signing key of invite [index]; two invites of one identity never share it (ADR-24). */
    fun inviteSigningKeyPair(index: Int): Ed25519KeyPair {
        val seed = deriveInviteBranch(DerivationLabels.INVITE_SIGNING, index)
        try {
            return Ed25519KeyPair.fromSeed(seed)
        } finally {
            seed.fill(0)
        }
    }

    /** Drop namespace of invite [index], where its invitee writes one sealed blob (design §9.3). */
    fun inviteDropNamespace(index: Int): ByteArray = deriveInviteBranch(DerivationLabels.INVITE_DROP_NAMESPACE, index)

    /** X25519 drop key of invite [index] (clamped secret); re-derived to open drop blobs, never stored. */
    fun inviteDropKeyPair(index: Int): X25519KeyPair {
        val secret = deriveInviteBranch(DerivationLabels.INVITE_DROP_KEY, index)
        try {
            return X25519KeyPair.fromSecret(secret)
        } finally {
            secret.fill(0)
        }
    }

    /** Every key of invite [index] (design §8.4): signing key, drop namespace, drop key. */
    fun inviteKeys(index: Int): InviteKeys =
        InviteKeys(index, inviteSigningKeyPair(index), inviteDropNamespace(index), inviteDropKeyPair(index))

    fun channelPseudonymKeyPair(channelId: ByteArray): Ed25519KeyPair =
        Ed25519KeyPair.fromSeed(deriveChannelPseudonymSeed(channelId))

    fun publicIdentity(): GhostIdentity = GhostIdentity.fromPublicKey(identityKeyPair().publicKey)

    fun zeroize() = bytes.fill(0)

    companion object {
        /** Invite indices are u16 (`ent_state.next_invite_index`, design §11.3). */
        const val MAX_INVITE_INDEX = 65535

        /** FR-1.1: 256 bits from `SecureRandom` (platform CSPRNG). Two installs never collide. */
        fun generate(random: SecureRandom = SecureRandom()): RootEntropy =
            RootEntropy(ByteArray(Bip39.ENTROPY_BYTES).also(random::nextBytes))

        fun fromMnemonic(words: List<String>): RootEntropy {
            val entropy = Bip39.decode(words)
            require(entropy.size == Bip39.ENTROPY_BYTES) { "GHOST backups are 24 words (256 bits)" }
            return RootEntropy(entropy)
        }

        fun fromRaw(bytes: ByteArray): RootEntropy = RootEntropy(bytes.copyOf())
    }
}
