package org.ghost.messaging.port

/**
 * The pseudonym seed of a channel (Phase 10 design §5.1, D12; ADR-04 unchanged):
 * `ps = HKDF-SHA256(root entropy, ∅, "ghost/v1/channel-pseudonym" ‖ u8(32) ‖ channel_id, 32)`, which `:identity`'s
 * `RootEntropy.deriveChannelPseudonymSeed` computes. The channel engine hands it to the native context once per
 * channel and per unlock (`channelOpen`, §10.2 fn 2), where it becomes the member's MLS signer, and zeroes its copy.
 *
 * **Why a port.** `:messaging` holds no root entropy: the wiring derives the seed from the identity it unwraps for the
 * call, and a JVM world from a fixed root. Null means the identity is locked or absent, which every caller turns into
 * `CRYPTO_UNAVAILABLE`.
 */
fun interface ChannelSeeds {
    /** The 32-byte seed for [channelId], a fresh array the caller zeroes; or null when the identity is not available. */
    fun pseudonymSeed(channelId: ByteArray): ByteArray?
}
