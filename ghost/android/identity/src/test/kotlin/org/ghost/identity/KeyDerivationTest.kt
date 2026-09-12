package org.ghost.identity

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import java.security.MessageDigest

/**
 * Deterministic derivation vectors (FR-1.2 acceptance: "test vectors prove deterministic recovery
 * and separation between branches"), invariant T14 (per-channel pseudonyms, ADR-04) and the Phase 8
 * per-invite branches (design §8.4, ADR-24).
 */
class KeyDerivationTest {
    private fun ByteArray.hex(): String = joinToString("") { "%02x".format(it) }
    private fun unhex(s: String) = ByteArray(s.length / 2) { s.substring(2 * it, 2 * it + 2).toInt(16).toByte() }
    private val fixedEntropy = ByteArray(32) { it.toByte() } // 00 01 02 ... 1f

    /** HKDF(root, info = label || u16_be(index)), computed here from the raw entropy (design §8.4). */
    private fun inviteBranch(root: RootEntropy, label: String, index: Int): ByteArray =
        Hkdf.derive(root.rawForWrapping(), null, label.toByteArray(Charsets.UTF_8) + byteArrayOf((index ushr 8).toByte(), index.toByte()), 32)

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
            // Retired by ADR-24 and no longer derived by production code; still pinned, so the reserved
            // labels can never silently change meaning.
            "invite_signing_pub" to Ed25519KeyPair.fromSeed(root.deriveBranch(DerivationLabels.INVITE_SIGNING)).publicKey.hex(),
            "referral_commitment" to MessageDigest.getInstance("SHA-256")
                .digest("ghost/v1/referral-commitment".toByteArray() + root.deriveBranch(DerivationLabels.REFERRAL_SECRET)).hex(),
            "pseudonym_pub_channel_a" to root.channelPseudonymKeyPair("channel-a".toByteArray()).publicKey.hex(),
            // Phase 8 per-invite branches.
            "invite_0_signing_seed" to inviteBranch(root, DerivationLabels.INVITE_SIGNING, 0).hex(),
            "invite_0_signing_pub" to root.inviteSigningKeyPair(0).publicKey.hex(),
            "invite_1_signing_pub" to root.inviteSigningKeyPair(1).publicKey.hex(),
            "invite_65535_signing_pub" to root.inviteSigningKeyPair(65535).publicKey.hex(),
            "invite_0_drop_namespace" to root.inviteDropNamespace(0).hex(),
            "invite_1_drop_namespace" to root.inviteDropNamespace(1).hex(),
            "invite_0_drop_secret" to X25519KeyPair.clamp(inviteBranch(root, DerivationLabels.INVITE_DROP_KEY, 0)).hex(),
            "invite_0_drop_pub" to root.inviteDropKeyPair(0).publicKey.hex(),
            "invite_1_drop_pub" to root.inviteDropKeyPair(1).publicKey.hex(),
        )
        assertEquals("every pinned vector is checked", expected.keys, actual.keys)
        val mismatches = actual.filter { (k, v) -> expected[k] != v }
        if (mismatches.isNotEmpty()) {
            val dump = actual.entries.joinToString("\n") { "${it.key} = ${it.value}" }
            throw AssertionError("derivation vectors changed for ${mismatches.keys}; actual values:\n$dump")
        }
        // The pinned secrets are the ones behind the production keys.
        assertArrayEquals(root.inviteSigningKeyPair(0).publicKey, Ed25519KeyPair.fromSeed(unhex(expected.getValue("invite_0_signing_seed"))).publicKey)
        assertArrayEquals(root.inviteDropKeyPair(0).publicKey, X25519KeyPair.fromSecret(unhex(expected.getValue("invite_0_drop_secret"))).publicKey)
    }

    @Test
    fun branchesAreSeparated() {
        val root = RootEntropy.fromRaw(fixedEntropy)
        val seeds = DerivationLabels.ALL.map { root.deriveBranch(it).hex() }
        assertEquals(seeds.size, seeds.toSet().size)
        assertFalse(seeds.contains(fixedEntropy.hex()))
    }

    @Test
    fun perInviteKeysAreDistinctAcrossIndicesAndFromEveryOtherBranch() {
        val root = RootEntropy.fromRaw(fixedEntropy)
        val indices = (0 until 64) + listOf(255, 256, 65535)
        val derived = indices.map { root.inviteSigningKeyPair(it).publicKey.hex() } +
            indices.map { root.inviteDropNamespace(it).hex() } +
            indices.map { root.inviteDropKeyPair(it).publicKey.hex() }
        assertEquals(derived.size, derived.toSet().size)
        val others = DerivationLabels.ALL.map { root.deriveBranch(it).hex() } +
            root.identityKeyPair().publicKey.hex() +
            Ed25519KeyPair.fromSeed(root.deriveBranch(DerivationLabels.INVITE_SIGNING)).publicKey.hex()
        assertTrue(derived.none { it in others })
    }

    @Test
    fun perInviteKeysAreStableAcrossRestore() {
        val root = RootEntropy.fromRaw(fixedEntropy)
        val restored = RootEntropy.fromMnemonic(root.toMnemonic())
        for (i in listOf(0, 1, 7, 65535)) {
            assertArrayEquals(root.inviteSigningKeyPair(i).publicKey, restored.inviteSigningKeyPair(i).publicKey)
            assertArrayEquals(root.inviteDropNamespace(i), restored.inviteDropNamespace(i))
            assertArrayEquals(root.inviteDropKeyPair(i).publicKey, restored.inviteDropKeyPair(i).publicKey)
            val keys = restored.inviteKeys(i)
            assertEquals(i, keys.index)
            assertArrayEquals(root.inviteDropNamespace(i), keys.dropNamespace)
            assertArrayEquals(root.inviteDropKeyPair(i).publicKey, keys.drop.publicKey)
        }
        // Another identity never derives the same invite keys.
        val other = RootEntropy.generate()
        assertFalse(root.inviteDropNamespace(0).contentEquals(other.inviteDropNamespace(0)))
        assertFalse(root.inviteSigningKeyPair(0).publicKey.contentEquals(other.inviteSigningKeyPair(0).publicKey))
    }

    @Test
    fun theInviteIndexIsAU16() {
        val root = RootEntropy.fromRaw(fixedEntropy)
        for (bad in listOf(-1, 65536, Int.MAX_VALUE, Int.MIN_VALUE)) {
            assertThrows(IllegalArgumentException::class.java) { root.inviteSigningKeyPair(bad) }
            assertThrows(IllegalArgumentException::class.java) { root.inviteDropNamespace(bad) }
            assertThrows(IllegalArgumentException::class.java) { root.inviteDropKeyPair(bad) }
        }
    }

    @Test
    fun theDropSecretIsClampedWithoutChangingTheKey() {
        val raw = inviteBranch(RootEntropy.fromRaw(fixedEntropy), DerivationLabels.INVITE_DROP_KEY, 0)
        val clamped = X25519KeyPair.clamp(raw)
        assertEquals(0, clamped[0].toInt() and 0x07)
        assertEquals(0x40, clamped[31].toInt() and 0xc0)
        // RFC 7748 clamps inside the scalar multiplication too: both spellings are one key.
        assertArrayEquals(X25519KeyPair.fromSecret(raw).publicKey, X25519KeyPair.fromSecret(clamped).publicKey)
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
