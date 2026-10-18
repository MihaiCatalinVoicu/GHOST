package org.ghost.identity

import java.nio.ByteBuffer
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Phase 13 §3.6: the local invite preview — version and expiry on an unexpired invite, the
 * constant refusal reasons for a damaged, foreign-version or expired invite, and NO state: a
 * preview never consumes a nonce and never asks the token schedule.
 */
class InvitePreviewTest {
    private val root = RootEntropy.fromRaw(ByteArray(32) { (it * 5 + 1).toByte() })
    private val signer = root.inviteSigningKeyPair(0)
    private val today = 20_000L
    private val DAY_SECONDS = 86_400L

    private fun draft(expiry: Long = today + 14, version: Int = 2, corruptSig: Boolean = false): String {
        val token = ByteArray(Invite.TOKEN_BYTES) { i -> (if (i == 0) 0 else if (i == 1) 2 else 7 + 13 * i).toByte() }
        val signed = ByteBuffer.allocate(Invite.PAYLOAD_BYTES - 64)
            .put(version.toByte()).put(token).put(ByteArray(16) { (0xa0 + it).toByte() })
            .putInt(expiry.toInt())
            .put(root.inviteDropNamespace(0)).put(byteArrayOf(5, 0, 17))
            .put(root.inviteDropKeyPair(0).publicKey).put(signer.publicKey).array()
        val sig = signer.sign(signed)
        if (corruptSig) sig[0] = (sig[0].toInt() xor 0xff).toByte()
        return Invite.SCHEME + ZBase32.encode(signed + sig)
    }

    @Test
    fun anUnexpiredInvitePreviewsOk() {
        val p = Invite.preview(draft(), today * DAY_SECONDS)
        assertTrue(p is Invite.Preview.Ok)
        p as Invite.Preview.Ok
        assertEquals(2, p.version)
        assertEquals(today + 14, p.expiryDay)
    }

    @Test
    fun anExpiredInvitePreviewsRefused() {
        val p = Invite.preview(draft(expiry = today - 1), today * DAY_SECONDS)
        assertEquals(Invite.Preview.Refused(Invite.Preview.Refused.Reason.EXPIRED), p)
    }

    @Test
    fun aCorruptedSignaturePreviewsRefused() {
        val p = Invite.preview(draft(corruptSig = true), today * DAY_SECONDS)
        assertEquals(Invite.Preview.Refused(Invite.Preview.Refused.Reason.BAD_SIGNATURE), p)
    }

    @Test
    fun garbagePreviewsRefusedMalformed() {
        val p = Invite.preview("ghost://invite/not!!zbase32!!", today * DAY_SECONDS)
        assertEquals(Invite.Preview.Refused(Invite.Preview.Refused.Reason.MALFORMED), p)
        val other = Invite.preview("https://example.com/x", today * DAY_SECONDS)
        assertEquals(Invite.Preview.Refused(Invite.Preview.Refused.Reason.MALFORMED), other)
    }

    @Test
    fun twoPreviewsOfTheSameInviteAreIdenticalAndStateless() {
        val text = draft()
        val a = Invite.preview(text, today * DAY_SECONDS)
        val b = Invite.preview(text, today * DAY_SECONDS)
        assertEquals(a, b)
    }
}
