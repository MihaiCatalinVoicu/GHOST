package org.ghost.crypto.bridge

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import java.security.MessageDigest

/**
 * The bearer credential v3 layout and its verifier (Phase 9 design §4.3, §21.2, §22.8.7).
 *
 * The verifier is checked against an **independently written** SHA-256 of the concatenation, not
 * against a value this class produced: the one thing that must not drift is the byte order the
 * relay hashes, and a test that called [CredentialV3.verifier] twice would agree with any order.
 */
class CredentialV3Test {

    private val namespace = ByteArray(32) { (it + 1).toByte() }
    private val secret = ByteArray(32) { (0xa0 + it).toByte() }

    @Test
    fun theCredentialIsTheSixtySevenBytesOfTheDesign() {
        val credential = CredentialV3.credential(CredentialV3.Kind.DEPOSIT, 7, namespace, secret)
        assertEquals(67, credential.size)
        assertEquals(3, credential[0].toInt())
        assertEquals(0x03, credential[1].toInt())
        assertEquals(7, credential[2].toInt())
        assertArrayEquals(namespace, credential.copyOfRange(3, 35))
        assertArrayEquals(secret, credential.copyOfRange(35, 67))
    }

    @Test
    fun theThreeKindCodesAreTheWireBytesAndTwoIsNotAKind() {
        assertEquals(0x01, CredentialV3.Kind.READ.code)
        assertEquals(0x03, CredentialV3.Kind.DEPOSIT.code)
        assertEquals(0x04, CredentialV3.Kind.FETCH.code)
        // 0x02 is Write in capability headers and is never a key kind (§4.3, the T21 matrix).
        assertFalse(CredentialV3.Kind.entries.any { it.code == 0x02 })
        assertEquals(3, CredentialV3.Kind.entries.map { it.code }.toSet().size)
    }

    @Test
    fun theVerifierIsTheLabelledHashTheRelayComputes() {
        for (kind in CredentialV3.Kind.entries) {
            val expected = MessageDigest.getInstance("SHA-256").digest(
                kind.label.toByteArray(Charsets.US_ASCII) + byteArrayOf(11) + namespace + secret,
            )
            assertArrayEquals(
                "verifier of ${kind.name}",
                expected,
                CredentialV3.verifier(kind, 11, namespace, secret),
            )
        }
    }

    @Test
    fun theThreeLabelsAreDistinctAndNoneIsAPrefixOfAnother() {
        val labels = CredentialV3.Kind.entries.map { it.label }
        assertEquals(labels.size, labels.toSet().size)
        for (a in labels) for (b in labels) {
            if (a !== b) assertFalse("$a is a prefix of $b", b.startsWith(a))
        }
    }

    /**
     * The binding of §4.3: a verifier registered for one namespace, one kind or one slot cannot
     * authorize another. Each of the three is varied on its own, so a hash that dropped one field
     * fails on that field alone.
     */
    @Test
    fun theVerifierBindsTheKindTheSlotAndTheNamespace() {
        val base = CredentialV3.verifier(CredentialV3.Kind.READ, 4, namespace, secret)
        assertFalse(base.contentEquals(CredentialV3.verifier(CredentialV3.Kind.DEPOSIT, 4, namespace, secret)))
        assertFalse(base.contentEquals(CredentialV3.verifier(CredentialV3.Kind.FETCH, 4, namespace, secret)))
        assertFalse(base.contentEquals(CredentialV3.verifier(CredentialV3.Kind.READ, 5, namespace, secret)))
        val other = namespace.copyOf().also { it[0] = 0x7f }
        assertFalse(base.contentEquals(CredentialV3.verifier(CredentialV3.Kind.READ, 4, other, secret)))
        val otherSecret = secret.copyOf().also { it[31] = 0x7f }
        assertFalse(base.contentEquals(CredentialV3.verifier(CredentialV3.Kind.READ, 4, namespace, otherSecret)))
    }

    /**
     * P-2, "no sender field in substance" (§4.3, §21.2): the credential carries no nonce, no MAC
     * and no week, so two different card holders depositing into one inbox at one relay present
     * **identical bytes** and therefore one `capability_scope`, in every week.
     */
    @Test
    fun everyHolderOfOneCardPresentsTheSameBytesAndTheSameScope() {
        val alice = CredentialV3.credential(CredentialV3.Kind.DEPOSIT, 9, namespace, secret)
        val bob = CredentialV3.credential(CredentialV3.Kind.DEPOSIT, 9, namespace, secret)
        assertArrayEquals(alice, bob)
        assertArrayEquals(CredentialV3.scope(alice), CredentialV3.scope(bob))
        assertEquals(32, CredentialV3.scope(alice).size)
        // Different kinds at the same relay are different scopes, which is what the capture shows.
        val read = CredentialV3.credential(CredentialV3.Kind.READ, 9, namespace, secret)
        assertNotEquals(
            CredentialV3.scope(read).toList(),
            CredentialV3.scope(alice).toList(),
        )
    }

    @Test
    fun aWrongLengthOrAnOutOfRangeSlotIsRefusedRatherThanTruncated() {
        assertThrows(IllegalArgumentException::class.java) {
            CredentialV3.credential(CredentialV3.Kind.READ, 256, namespace, secret)
        }
        assertThrows(IllegalArgumentException::class.java) {
            CredentialV3.credential(CredentialV3.Kind.READ, -1, namespace, secret)
        }
        assertThrows(IllegalArgumentException::class.java) {
            CredentialV3.credential(CredentialV3.Kind.READ, 0, ByteArray(31), secret)
        }
        assertThrows(IllegalArgumentException::class.java) {
            CredentialV3.credential(CredentialV3.Kind.READ, 0, namespace, ByteArray(33))
        }
        assertThrows(IllegalArgumentException::class.java) {
            CredentialV3.verifier(CredentialV3.Kind.READ, 256, namespace, secret)
        }
        assertThrows(IllegalArgumentException::class.java) {
            CredentialV3.scope(ByteArray(66))
        }
    }

    /** No field of the credential is the whole card secret or anything a relay could derive from. */
    @Test
    fun theCredentialCarriesNoWeek() {
        // A week would have to be a field, and there are exactly five: version, kind, slot,
        // namespace, secret. The arithmetic is the assertion (§21.2 point 2 fixes the layout).
        assertEquals(1 + 1 + 1 + 32 + 32, CredentialV3.CREDENTIAL_BYTES)
        assertTrue(CredentialV3.VERIFIER_BYTES == 32)
    }
}
