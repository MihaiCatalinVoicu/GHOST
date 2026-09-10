package org.ghost.identity

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

/** Invariant T16 and FR-1.5/FR-1.6 acceptance: tampered, expired, replayed invites are rejected. */
class InviteTest {
    private val root = RootEntropy.fromRaw(ByteArray(32) { it.toByte() })
    private val now = 1_757_491_200L
    private val token = ByteArray(32) { 0x42 }

    private fun fresh(expiry: Long = now + 3600): Invite =
        Invite.create(token, root.referralCommitment(), expiry, root.inviteSigningKeyPair())

    @Test
    fun roundTripAcceptsValidInvite() {
        val inv = fresh()
        val text = inv.encode()
        assertTrue(text.startsWith("ghost://invite/"))
        val parsed = Invite.parseAndVerify(text, now, Invite.InMemoryNonceStore())
        assertEquals(inv, parsed)
    }

    @Test
    fun payloadNeverContainsIdentityKeyOrWebHost() {
        val inv = fresh()
        val bytes = inv.bytes()
        val identityPub = root.identityKeyPair().publicKey
        assertFalse("identity key must not appear in invite", bytes.toList().windowed(32).any { it.toByteArray().contentEquals(identityPub) })
        assertFalse(inv.encode().contains("http"))
        assertFalse(inv.encode().substring("ghost://invite/".length).contains('.'))
    }

    @Test
    fun everyByteFlipIsRejected() {
        val inv = fresh()
        val bytes = inv.bytes()
        var rejected = 0
        for (i in bytes.indices) {
            val t = bytes.copyOf()
            t[i] = (t[i].toInt() xor 0x01).toByte()
            try {
                Invite.parseAndVerify(Invite.SCHEME + ZBase32.encode(t), now, Invite.InMemoryNonceStore())
            } catch (e: Invite.Rejection) {
                rejected++
            }
        }
        assertEquals(bytes.size, rejected)
    }

    @Test
    fun expiredIsRejected() {
        val inv = fresh(expiry = now - 1)
        assertThrows(Invite.Rejection.Expired::class.java) {
            Invite.parseAndVerify(inv.encode(), now, Invite.InMemoryNonceStore())
        }
    }

    @Test
    fun replayIsRejected() {
        val inv = fresh()
        val store = Invite.InMemoryNonceStore()
        Invite.parseAndVerify(inv.encode(), now, store)
        assertThrows(Invite.Rejection.Replayed::class.java) { Invite.parseAndVerify(inv.encode(), now, store) }
    }

    @Test
    fun wrongSchemeVersionAndUrlStructureAreRejected() {
        val inv = fresh()
        val body = inv.encode().substring(Invite.SCHEME.length)
        assertThrows(Invite.Rejection.Malformed::class.java) {
            Invite.parseAndVerify("https://example.org/invite/$body", now, Invite.InMemoryNonceStore())
        }
        assertThrows(Invite.Rejection.Malformed::class.java) {
            Invite.parseAndVerify(Invite.SCHEME + body + "?ref=x", now, Invite.InMemoryNonceStore())
        }
        val v2 = inv.bytes().copyOf().also { it[0] = 2 }
        assertThrows(Invite.Rejection.Malformed::class.java) {
            Invite.parseAndVerify(Invite.SCHEME + ZBase32.encode(v2), now, Invite.InMemoryNonceStore())
        }
        assertThrows(Invite.Rejection.Malformed::class.java) {
            Invite.parseAndVerify(Invite.SCHEME + body.dropLast(3), now, Invite.InMemoryNonceStore())
        }
    }

    @Test
    fun signatureFromAnotherKeyIsRejected() {
        val inv = fresh()
        val other = RootEntropy.generate().inviteSigningKeyPair()
        val forged = Invite(inv.version, inv.inviteToken, inv.referralCommitment, inv.nonce, inv.expiryUnixSeconds, other.publicKey, inv.signature)
        assertThrows(Invite.Rejection.BadSignature::class.java) {
            Invite.parseAndVerify(forged.encode(), now, Invite.InMemoryNonceStore())
        }
    }
}
