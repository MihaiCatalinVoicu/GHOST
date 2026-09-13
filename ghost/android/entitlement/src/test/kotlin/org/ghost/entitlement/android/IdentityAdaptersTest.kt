package org.ghost.entitlement.android

import org.ghost.entitlement.TestBytes
import org.ghost.identity.DropSeal
import org.ghost.identity.IdentityManager
import org.ghost.identity.InMemoryWrappedSecretStore
import org.ghost.identity.SecretWrapper
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The identity adapters (design §8.3, §8.4, §9.3): the resumed invite path creates an identity like
 * the invite path; per-invite keys and drop keys are re-derived from the root entropy, so an inviter
 * opens exactly the blobs sealed to its invite's drop.
 */
class IdentityAdaptersTest {

    /** A reversible test wrapper (the Keystore contract without the Keystore). */
    private class XorWrapper : SecretWrapper {
        override fun wrap(plaintext: ByteArray): ByteArray = ByteArray(plaintext.size) { (plaintext[it].toInt() xor 0x5a).toByte() }

        override fun unwrap(envelope: ByteArray): ByteArray = wrap(envelope)
    }

    @Test
    fun aResumedTrialCreatesTheIdentityAndAFailureWipesIt() {
        val manager = IdentityManager(XorWrapper(), InMemoryWrappedSecretStore())
        val identity = ManagerIdentity(manager)
        assertFalse(identity.hasIdentity())
        identity.create(null)
        assertTrue(identity.hasIdentity())
        identity.wipe()
        assertFalse(identity.hasIdentity())
    }

    @Test
    fun inviteKeysAndDropsComeFromTheRootOfTheIdentity() {
        val manager = IdentityManager(XorWrapper(), InMemoryWrappedSecretStore())
        val identity = ManagerIdentity(manager)
        identity.create(null)
        val root = manager.unlock()
        val keys = identity.inviteKeys(3)
        assertArrayEquals(root.inviteDropNamespace(3), keys.dropNamespace)
        assertArrayEquals(root.inviteSigningKeyPair(3).publicKey, keys.signing.publicKey)
        val seal = IdentitySeal(manager)
        val credit = TestBytes.token(1)
        val blob = seal.sealCredit(credit, keys.drop.publicKey, keys.dropNamespace)
        val opened = seal.open(3, blob, keys.dropNamespace) as DropSeal.Opened.Credit
        assertArrayEquals(credit, opened.token)
        assertSame("another invite's drop key opens nothing", DropSeal.Opened.Invalid, seal.open(4, blob, keys.dropNamespace))
        assertSame(DropSeal.Opened.Dummy, seal.open(3, seal.sealDummy(keys.drop.publicKey, keys.dropNamespace), keys.dropNamespace))
    }
}
