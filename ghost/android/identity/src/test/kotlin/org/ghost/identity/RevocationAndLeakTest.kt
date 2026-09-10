package org.ghost.identity

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Test

class RevocationAndLeakTest {
    private val root = RootEntropy.fromRaw(ByteArray(32) { it.toByte() })

    @Test
    fun revocationRoundTripAndTamper() {
        val cert = RevocationCertificate.issue(root.identityKeyPair(), 1_757_491_200L, RevocationCertificate.Reason.DEVICE_LOST)
        val parsed = RevocationCertificate.parseAndVerify(cert.bytes())
        assertEquals(cert, parsed)
        assertEquals(root.publicIdentity(), parsed.revokedIdentity())
        val bytes = cert.bytes()
        var rejected = 0
        for (i in bytes.indices) {
            val t = bytes.copyOf().also { it[i] = (it[i].toInt() xor 1).toByte() }
            try { RevocationCertificate.parseAndVerify(t) } catch (e: IllegalArgumentException) { rejected++ }
        }
        assertEquals(bytes.size, rejected)
        assertThrows(IllegalArgumentException::class.java) { RevocationCertificate.parseAndVerify(bytes.dropLast(1).toByteArray()) }
    }

    @Test
    fun anotherIdentityCannotRevokeThisOne() {
        val cert = RevocationCertificate.issue(root.identityKeyPair(), 1L, RevocationCertificate.Reason.KEY_ROTATION)
        val forged = RevocationCertificate(cert.version, RootEntropy.generate().identityKeyPair().publicKey, cert.issuedAtUnixSeconds, cert.reason, cert.signature)
        assertThrows(IllegalArgumentException::class.java) { RevocationCertificate.parseAndVerify(forged.bytes()) }
    }

    /** T3 (in-process part): default string forms of secret holders never expose entropy or words. */
    @Test
    fun secretHoldersDoNotLeakThroughToString() {
        val hex = root.rawForWrapping().joinToString("") { "%02x".format(it) }
        val words = root.toMnemonic()
        val created = IdentityManager.Created(root, IdentityManager.Activation.Genesis(true))
        for (s in listOf(root.toString(), created.toString(), root.identityKeyPair().toString())) {
            assertFalse(s.contains(hex))
            assertFalse(words.any { w -> s.contains(w) && w.length > 3 })
        }
    }
}
