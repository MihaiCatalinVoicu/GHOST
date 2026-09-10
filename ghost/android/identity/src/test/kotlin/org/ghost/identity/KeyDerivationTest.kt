package org.ghost.identity

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Deterministic derivation vectors (FR-1.2 acceptance: "test vectors prove deterministic recovery
 * and separation between branches") and invariant T14 (per-channel pseudonyms, ADR-04).
 */
class KeyDerivationTest {
    private fun ByteArray.hex(): String = joinToString("") { "%02x".format(it) }
    private val fixedEntropy = ByteArray(32) { it.toByte() } // 00 01 02 ... 1f

    @Test
    fun fixedEntropyProducesPinnedVectors() {
        val root = RootEntropy.fromRaw(fixedEntropy)
        val expected = javaClass.getResourceAsStream("/derivation_vectors.txt")!!.bufferedReader().readLines()
            .filter { it.isNotBlank() && !it.startsWith("#") }
            .associate { line -> line.substringBefore('=').trim() to line.substringAfter('=').trim() }
        val actual = mapOf(
            "mnemonic" to root.toMnemonic().joinToString(" "),
            "identity_seed" to root.deriveBranch(DerivationLabels.IDENTITY).hex(),
            "identity_pub" to root.identityKeyPair().publicKey.hex(),
            "identity" to root.publicIdentity().encode(),
            "messaging_seed" to root.deriveBranch(DerivationLabels.MESSAGING).hex(),
            "backup_wrap" to root.deriveBranch(DerivationLabels.BACKUP_WRAP).hex(),
            "invite_signing_pub" to root.inviteSigningKeyPair().publicKey.hex(),
            "referral_commitment" to root.referralCommitment().hex(),
            "pseudonym_pub_channel_a" to root.channelPseudonymKeyPair("channel-a".toByteArray()).publicKey.hex(),
        )
        val mismatches = actual.filter { (k, v) -> expected[k] != v }
        if (mismatches.isNotEmpty()) {
            val dump = actual.entries.joinToString("\n") { "${it.key} = ${it.value}" }
            throw AssertionError("derivation vectors changed for ${mismatches.keys}; actual values:\n$dump")
        }
    }

    @Test
    fun branchesAreSeparated() {
        val root = RootEntropy.fromRaw(fixedEntropy)
        val seeds = DerivationLabels.ALL.map { root.deriveBranch(it).hex() }
        assertEquals(seeds.size, seeds.toSet().size)
        assertFalse(seeds.contains(fixedEntropy.hex()))
    }

    @Test
    fun t14PseudonymsAreUnlinkableAcrossChannels() {
        val root = RootEntropy.fromRaw(fixedEntropy)
        val a = root.channelPseudonymKeyPair("channel-a".toByteArray()).publicKey
        val b = root.channelPseudonymKeyPair("channel-b".toByteArray()).publicKey
        val base = root.identityKeyPair().publicKey
        assertFalse(a.contentEquals(b))
        assertFalse(a.contentEquals(base))
        assertFalse(b.contentEquals(base))
        // Same channel, same seed → same pseudonym (needed for MLS credential stability).
        assertArrayEquals(a, root.channelPseudonymKeyPair("channel-a".toByteArray()).publicKey)
        // A different root never produces the same pseudonym for the same channel.
        val other = RootEntropy.generate()
        assertFalse(a.contentEquals(other.channelPseudonymKeyPair("channel-a".toByteArray()).publicKey))
    }

    @Test
    fun channelInfoEncodingIsInjective() {
        val root = RootEntropy.fromRaw(fixedEntropy)
        // "ab" + "c" vs "a" + "bc" style collisions are impossible thanks to the length prefix.
        val x = root.deriveChannelPseudonymSeed(byteArrayOf(1, 2))
        val y = root.deriveChannelPseudonymSeed(byteArrayOf(1))
        assertNotEquals(x.hex(), y.hex())
    }

    @Test
    fun twoFreshInstallsDiffer() {
        val a = RootEntropy.generate()
        val b = RootEntropy.generate()
        assertNotEquals(a.publicIdentity(), b.publicIdentity())
        assertTrue(a.toMnemonic() != b.toMnemonic())
    }

    @Test
    fun signaturesVerifyAndRejectTamper() {
        val kp = RootEntropy.fromRaw(fixedEntropy).identityKeyPair()
        val msg = "hello".toByteArray()
        val sig = kp.sign(msg)
        assertTrue(Ed25519KeyPair.verify(kp.publicKey, msg, sig))
        assertFalse(Ed25519KeyPair.verify(kp.publicKey, "hellp".toByteArray(), sig))
        sig[0] = (sig[0].toInt() xor 1).toByte()
        assertFalse(Ed25519KeyPair.verify(kp.publicKey, msg, sig))
    }
}
