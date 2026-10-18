package org.ghost.identity

import java.security.SecureRandom
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Phase 13 §3.3, §3.6, §5.6: the index form of the mnemonic (F-U4 — no string of bits anywhere
 * on the path), the round trips, and the carried backup challenge.
 */
class MnemonicIndicesTest {
    private val entropy = ByteArray(32) { (it * 7 + 3).toByte() }

    @Test
    fun encodeIndicesMatchesTheWordFormAndRoundTrips() {
        val indices = Bip39.encodeIndices(entropy)
        assertEquals(24, indices.size)
        val words = indices.map { Bip39.wordlist[it] }
        assertEquals(Bip39.encode(entropy), words)
        assertArrayEquals(entropy, Bip39.decodeIndices(indices))
        assertArrayEquals(entropy, Bip39.decode(words))
    }

    @Test
    fun indicesOfMnemonicIsTheInverseOfTheWordForm() {
        val words = Bip39.encode(entropy)
        assertArrayEquals(Bip39.encodeIndices(entropy), Bip39.indicesOfMnemonic(words))
        assertThrows(IllegalArgumentException::class.java) {
            Bip39.indicesOfMnemonic(listOf("notaword"))
        }
    }

    @Test
    fun decodeIndicesRejectsWhatDecodeRejects() {
        val good = Bip39.encodeIndices(entropy)
        assertThrows(IllegalArgumentException::class.java) { Bip39.decodeIndices(good.copyOf(23)) }
        assertThrows(IllegalArgumentException::class.java) {
            Bip39.decodeIndices(good.copyOf().also { it[0] = 2048 })
        }
        val corrupted = good.copyOf().also { it[5] = it[5] xor 1 }
        if (corrupted.contentEquals(good)) return // the flip hit nothing (impossible for xor 1)
        assertThrows(IllegalArgumentException::class.java) { Bip39.decodeIndices(corrupted) }
    }

    @Test
    fun toMnemonicIndicesIsTheRootsWordIndices() {
        val root = RootEntropy.fromRaw(entropy)
        val indices = root.toMnemonicIndices()
        assertEquals(24, indices.size)
        assertEquals(Bip39.encode(entropy), indices.map { Bip39.wordlist[it] })
    }

    @Test
    fun theCarriedChallengeKeepsEveryMissedPosition() {
        val manager = IdentityManager(SoftwareWrapper(), MemoryStore(), SecureRandom())
        val missed = listOf(2, 7, 19)
        val challenge = manager.backupChallenge(4, carried = missed)
        assertEquals(4, challenge.size)
        assertTrue("every carried position is in the next challenge", challenge.containsAll(missed))
        assertEquals(challenge.size, challenge.toSet().size)
        // The remaining position is fresh, not a duplicate of a carried one.
        assertNotEquals(missed.toSet(), challenge.toSet())
    }

    @Test
    fun theCarriedChallengeRefusesMoreCarriedThanCount() {
        val manager = IdentityManager(SoftwareWrapper(), MemoryStore(), SecureRandom())
        assertThrows(IllegalArgumentException::class.java) {
            manager.backupChallenge(2, carried = listOf(1, 2, 3))
        }
    }

    @Test
    fun verifyBackupIndicesComparesAtThePositions() {
        val manager = IdentityManager(SoftwareWrapper(), MemoryStore(), SecureRandom())
        val indices = Bip39.encodeIndices(entropy)
        val answers = intArrayOf(indices[5], indices[11])
        assertTrue(manager.verifyBackupIndices(indices, listOf(5, 11), answers))
        val wrong = intArrayOf(indices[5], (indices[11] + 1) % 2048)
        if (wrong[1] != indices[11]) {
            assertTrue(!manager.verifyBackupIndices(indices, listOf(5, 11), wrong))
        }
    }

    /** An identity-touching test needs no real wrapper: the challenges never unwrap. */
    private class SoftwareWrapper : SecretWrapper {
        override fun wrap(plaintext: ByteArray): ByteArray = plaintext.copyOf()

        override fun unwrap(envelope: ByteArray): ByteArray = envelope.copyOf()
    }

    private class MemoryStore : WrappedSecretStore {
        private val map = HashMap<String, ByteArray>()
        override fun read(name: String): ByteArray? = map[name]
        override fun write(name: String, envelope: ByteArray) {
            map[name] = envelope
        }

        override fun delete(name: String) {
            map.remove(name)
        }
    }
}
