package org.ghost.identity

import java.security.MessageDigest
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

    fun identityKeyPair(): Ed25519KeyPair = Ed25519KeyPair.fromSeed(deriveBranch(DerivationLabels.IDENTITY))

    fun inviteSigningKeyPair(): Ed25519KeyPair = Ed25519KeyPair.fromSeed(deriveBranch(DerivationLabels.INVITE_SIGNING))

    fun channelPseudonymKeyPair(channelId: ByteArray): Ed25519KeyPair =
        Ed25519KeyPair.fromSeed(deriveChannelPseudonymSeed(channelId))

    fun referralSecret(): ByteArray = deriveBranch(DerivationLabels.REFERRAL_SECRET)

    /** Commitment to the referral secret that travels inside invites (ADR-05); the secret never does. */
    fun referralCommitment(): ByteArray =
        MessageDigest.getInstance("SHA-256").digest("ghost/v1/referral-commitment".toByteArray() + referralSecret())

    fun publicIdentity(): GhostIdentity = GhostIdentity.fromPublicKey(identityKeyPair().publicKey)

    fun zeroize() = bytes.fill(0)

    companion object {
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
