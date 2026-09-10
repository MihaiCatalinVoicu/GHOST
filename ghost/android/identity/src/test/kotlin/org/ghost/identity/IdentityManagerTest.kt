package org.ghost.identity

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/** In-process AES-GCM wrapper standing in for the Android Keystore on the JVM. */
private class JvmAesGcmWrapper : SecretWrapper {
    private val key: SecretKey = KeyGenerator.getInstance("AES").apply { init(256) }.generateKey()
    override fun wrap(plaintext: ByteArray): ByteArray {
        val c = Cipher.getInstance("AES/GCM/NoPadding")
        c.init(Cipher.ENCRYPT_MODE, key)
        return c.iv + c.doFinal(plaintext)
    }
    override fun unwrap(envelope: ByteArray): ByteArray {
        val c = Cipher.getInstance("AES/GCM/NoPadding")
        c.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(128, envelope.copyOfRange(0, 12)))
        return c.doFinal(envelope.copyOfRange(12, envelope.size))
    }
}

class IdentityManagerTest {
    @Test
    fun createThenUnlockGivesSameIdentity() {
        val store = InMemoryWrappedSecretStore()
        val mgr = IdentityManager(JvmAesGcmWrapper(), store)
        assertFalse(mgr.hasIdentity())
        val created = mgr.create(IdentityManager.Activation.Genesis(policyAcknowledged = true))
        assertTrue(mgr.hasIdentity())
        assertEquals(created.identity, mgr.unlock().publicIdentity())
        // Envelope at rest is not the raw entropy.
        assertFalse(store.read(IdentityManager.ENVELOPE_NAME)!!.contentEquals(created.root.rawForWrapping()))
    }

    @Test
    fun reinstallPlusMnemonicRestoresSameIdentity() {
        val first = IdentityManager(JvmAesGcmWrapper(), InMemoryWrappedSecretStore())
        val created = first.create(IdentityManager.Activation.Genesis(policyAcknowledged = true))
        // "Reinstall": new wrapper key, empty store, only the 24 words survive.
        val second = IdentityManager(JvmAesGcmWrapper(), InMemoryWrappedSecretStore())
        val restored = second.restore(created.mnemonic)
        assertEquals(created.identity, restored.publicIdentity())
        assertArrayEquals(
            created.root.channelPseudonymKeyPair("c".toByteArray()).publicKey,
            restored.channelPseudonymKeyPair("c".toByteArray()).publicKey,
        )
    }

    @Test
    fun genesisRequiresExplicitPolicyAndNoDuplicateIdentity() {
        val mgr = IdentityManager(JvmAesGcmWrapper(), InMemoryWrappedSecretStore())
        assertThrows(IllegalStateException::class.java) { mgr.create(IdentityManager.Activation.Genesis(policyAcknowledged = false)) }
        mgr.create(IdentityManager.Activation.Genesis(policyAcknowledged = true))
        assertThrows(IllegalStateException::class.java) { mgr.create(IdentityManager.Activation.Genesis(policyAcknowledged = true)) }
    }

    @Test
    fun tamperedEnvelopeFailsToUnlock() {
        val store = InMemoryWrappedSecretStore()
        val mgr = IdentityManager(JvmAesGcmWrapper(), store)
        mgr.create(IdentityManager.Activation.Genesis(policyAcknowledged = true))
        val env = store.read(IdentityManager.ENVELOPE_NAME)!!
        env[env.size - 1] = (env[env.size - 1].toInt() xor 1).toByte()
        store.write(IdentityManager.ENVELOPE_NAME, env)
        assertThrows(Exception::class.java) { mgr.unlock() }
    }

    @Test
    fun backupChallengeCoversDistinctPositionsAndVerifies() {
        val mgr = IdentityManager(JvmAesGcmWrapper(), InMemoryWrappedSecretStore())
        val created = mgr.create(IdentityManager.Activation.Genesis(policyAcknowledged = true))
        val positions = mgr.backupChallenge(4)
        assertEquals(4, positions.toSet().size)
        assertTrue(positions.all { it in 0..23 })
        val answers = positions.map { created.mnemonic[it] }
        assertTrue(mgr.verifyBackupAnswers(created.mnemonic, positions, answers))
        assertFalse(mgr.verifyBackupAnswers(created.mnemonic, positions, answers.reversed()))
    }

    @Test
    fun wipeRemovesIdentity() {
        val mgr = IdentityManager(JvmAesGcmWrapper(), InMemoryWrappedSecretStore())
        mgr.create(IdentityManager.Activation.Genesis(policyAcknowledged = true))
        mgr.wipe()
        assertFalse(mgr.hasIdentity())
        assertThrows(IllegalStateException::class.java) { mgr.unlock() }
    }
}
