package org.ghost.network

import org.ghost.network.TorIssuerTransport.Companion.CLAIM_ADDRESS_REJECTED
import org.ghost.network.TorIssuerTransport.Companion.CLAIM_CONFLICT
import org.ghost.network.TorIssuerTransport.Companion.CLAIM_CREDITS_SPENT
import org.ghost.network.TorIssuerTransport.Companion.CLAIM_QUEUED
import org.ghost.network.TorIssuerTransport.Companion.INVOICE_CREDITS_SPENT
import org.ghost.network.TorIssuerTransport.Companion.INVOICE_OK
import org.ghost.network.TorIssuerTransport.Companion.INVOICE_WRONG_PERIOD
import org.ghost.network.TorIssuerTransport.Companion.ISSUED_TOKEN_BYTES
import org.ghost.network.TorIssuerTransport.Companion.REFRESH_OK
import org.ghost.network.TorIssuerTransport.Companion.REFRESH_REPLAYED
import org.ghost.network.TorIssuerTransport.Companion.STATE_AWAITING_PAYMENT
import org.ghost.network.TorIssuerTransport.Companion.STATE_OTHER_REQUEST_ISSUED
import org.ghost.network.TorIssuerTransport.Companion.STATE_SIGNED
import org.ghost.network.TorIssuerTransport.Companion.TRIAL_OK
import org.ghost.network.TorIssuerTransport.Companion.TRIAL_REPLAYED
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Decoders of the `TorIssuerTransport` and redemption native layouts (client-core/net/src/
 * issuer_flow.rs, namespace_client.rs), the argument checks made before a native call, and the
 * redacted `toString()` of every holder of secrets (T3). Pure JVM: nothing here loads the native
 * library; the transport under test runs on a handle that fails the test if a call reaches it.
 */
class IssuerWireTest {
    private fun u64(v: Long) = ByteArray(8) { i -> (v ushr (8 * (7 - i))).toByte() }

    private fun u32(v: Long) = ByteArray(4) { i -> (v ushr (8 * (3 - i))).toByte() }

    private fun hex(b: ByteArray) = b.joinToString("") { "%02x".format(it) }

    private val subaddress = "8".repeat(95)

    private fun malformed(block: () -> Unit) {
        val e = assertThrows(NetworkException::class.java) { block() }
        assertEquals("malformed_response", e.category)
    }

    private fun issued(n: Int) = ByteArray(n * ISSUED_TOKEN_BYTES) { (it % 251).toByte() }

    @Test
    fun invoiceDecoding() {
        val id = ByteArray(16) { 9 }
        val xmr = TorIssuerTransport.decodeInvoice(byteArrayOf(1) + id + u64(200_000_000_000) + subaddress.toByteArray() + u32(0), 0)
        assertEquals(INVOICE_OK, xmr.result)
        assertArrayEquals(id, xmr.invoiceId())
        assertEquals(200_000_000_000L, xmr.amountAtomic)
        assertEquals(subaddress, xmr.subaddress)
        val shown = xmr.toString()
        assertFalse(shown.contains(hex(id)) || shown.contains(subaddress) || shown.contains("200000000000"))
        val credits = TorIssuerTransport.decodeInvoice(byteArrayOf(1) + id + u64(0) + u32(0), 10)
        assertEquals(0L, credits.amountAtomic)
        assertNull(credits.subaddress)
        assertEquals(INVOICE_WRONG_PERIOD, TorIssuerTransport.decodeInvoice(byteArrayOf(2) + ByteArray(24) + u32(0), 0).result)
        val spent = TorIssuerTransport.decodeInvoice(byteArrayOf(3) + ByteArray(24) + u32(0x3FF), 10)
        assertEquals(INVOICE_CREDITS_SPENT, spent.result)
        assertEquals(0x3FFL, spent.spentMask)

        val bad = listOf(
            ByteArray(28) to 0,
            ByteArray(30) to 0,
            (byteArrayOf(1) + id + u64(1) + subaddress.toByteArray() + u32(0) + byteArrayOf(0)) to 0,
            (byteArrayOf(0) + ByteArray(24) + u32(0)) to 0, // unspecified
            (byteArrayOf(5) + ByteArray(24) + u32(0)) to 0, // unknown
            (byteArrayOf(1) + id + u64(5) + subaddress.toByteArray() + u32(1)) to 0, // OK with a mask
            (byteArrayOf(1) + id + u64(0) + subaddress.toByteArray() + u32(0)) to 0, // subaddress without amount
            (byteArrayOf(1) + id + u64(5) + u32(0)) to 0, // amount without subaddress
            (byteArrayOf(1) + id + u64(0) + u32(0)) to 0, // a zero-amount invoice paid in XMR
            (byteArrayOf(1) + id + u64(-1) + subaddress.toByteArray() + u32(0)) to 0, // negative amount
            (byteArrayOf(1) + id + u64(5) + " ".repeat(95).toByteArray() + u32(0)) to 0, // not an address text
            (byteArrayOf(2) + id + u64(0) + u32(0)) to 0, // WRONG_PERIOD with an invoice id
            (byteArrayOf(3) + ByteArray(24) + u32(0x3FF)) to 0, // spent credits of a request without credits
            (byteArrayOf(3) + ByteArray(24) + u32(1L shl 10)) to 10, // mask beyond the credits
            (byteArrayOf(3) + ByteArray(24) + u32(0)) to 10, // empty mask
        )
        for ((raw, count) in bad) malformed { TorIssuerTransport.decodeInvoice(raw, count) }
    }

    @Test
    fun signDecoding() {
        val tokens = issued(2)
        val signed = TorIssuerTransport.decodeSign(byteArrayOf(1) + u64(7) + u64(3) + tokens, 2)
        assertEquals(STATE_SIGNED, signed.state)
        assertEquals(7L, signed.creditedAtomic)
        assertEquals(3L, signed.seenAtomic)
        assertEquals(2, signed.tokens.size)
        assertArrayEquals(tokens.copyOfRange(0, 32), signed.tokens[0].nullifier())
        assertArrayEquals(tokens.copyOfRange(32, ISSUED_TOKEN_BYTES), signed.tokens[0].token())
        assertArrayEquals(tokens.copyOfRange(ISSUED_TOKEN_BYTES + 32, 2 * ISSUED_TOKEN_BYTES), signed.tokens[1].token())
        assertEquals("IssuedToken(..)", signed.tokens[0].toString())
        assertFalse(signed.toString().contains(hex(tokens.copyOfRange(0, 32))))
        val waiting = TorIssuerTransport.decodeSign(byteArrayOf(2) + u64(0) + u64(0), 2)
        assertEquals(STATE_AWAITING_PAYMENT, waiting.state)
        assertTrue(waiting.tokens.isEmpty())
        assertEquals(STATE_OTHER_REQUEST_ISSUED, TorIssuerTransport.decodeSign(byteArrayOf(6) + ByteArray(16), 2).state)
        val bad = listOf(
            byteArrayOf(1) + ByteArray(16) + issued(1), // fewer tokens than positions
            byteArrayOf(1) + ByteArray(16) + issued(3),
            byteArrayOf(1) + ByteArray(16) + issued(2).copyOf(2 * ISSUED_TOKEN_BYTES - 1),
            byteArrayOf(2) + ByteArray(16) + issued(2), // tokens with AWAITING_PAYMENT
            byteArrayOf(0) + ByteArray(16),
            byteArrayOf(7) + ByteArray(16),
            byteArrayOf(2) + u64(-1) + u64(0),
            ByteArray(16),
        )
        for (raw in bad) malformed { TorIssuerTransport.decodeSign(raw, 2) }
        // Status: 17 bytes, a known state.
        assertEquals(STATE_SIGNED, TorIssuerTransport.decodeStatus(byteArrayOf(1) + u64(5) + u64(0)).state)
        for (raw in listOf(ByteArray(17), byteArrayOf(7) + ByteArray(16), byteArrayOf(1) + ByteArray(17), byteArrayOf(1) + u64(0) + u64(-3))) {
            malformed { TorIssuerTransport.decodeStatus(raw) }
        }
    }

    @Test
    fun trialAndRefreshDecoding() {
        val ok = TorIssuerTransport.decodeTrial(byteArrayOf(1) + issued(48), 48)
        assertEquals(TRIAL_OK, ok.result)
        assertEquals(48, ok.tokens.size)
        assertEquals(TRIAL_REPLAYED, TorIssuerTransport.decodeTrial(byteArrayOf(2), 48).result)
        for (raw in listOf(ByteArray(0), byteArrayOf(1) + issued(47), byteArrayOf(2) + issued(1), byteArrayOf(0), byteArrayOf(4))) {
            malformed { TorIssuerTransport.decodeTrial(raw, 48) }
        }
        val fresh = TorIssuerTransport.decodeRefresh(byteArrayOf(1) + issued(1))
        assertEquals(REFRESH_OK, fresh.result)
        assertArrayEquals(issued(1).copyOfRange(32, ISSUED_TOKEN_BYTES), fresh.token!!.token())
        val replayed = TorIssuerTransport.decodeRefresh(byteArrayOf(2))
        assertEquals(REFRESH_REPLAYED, replayed.result)
        assertNull(replayed.token)
        for (raw in listOf(ByteArray(0), byteArrayOf(1), byteArrayOf(1) + issued(2), byteArrayOf(2) + issued(1), byteArrayOf(3))) {
            malformed { TorIssuerTransport.decodeRefresh(raw) }
        }
    }

    @Test
    fun claimDecoding() {
        val queued = TorIssuerTransport.decodeClaim(byteArrayOf(1) + u64(200_000_000_000) + u64(0), 10)
        assertEquals(CLAIM_QUEUED, queued.result)
        assertEquals(200_000_000_000L, queued.queuedAtomic)
        assertEquals(CLAIM_CREDITS_SPENT, TorIssuerTransport.decodeClaim(byteArrayOf(2) + u64(0) + u64(1L shl 49), 50).result)
        assertEquals(1L shl 63, TorIssuerTransport.decodeClaim(byteArrayOf(2) + u64(0) + u64(1L shl 63), 64).spentMask)
        assertEquals(CLAIM_CONFLICT, TorIssuerTransport.decodeClaim(byteArrayOf(3) + ByteArray(16), 10).result)
        assertEquals(CLAIM_ADDRESS_REJECTED, TorIssuerTransport.decodeClaim(byteArrayOf(4) + ByteArray(16), 10).result)
        val bad = listOf(
            byteArrayOf(1) + u64(5) + u64(1), // QUEUED with a mask
            byteArrayOf(1) + u64(0) + u64(0), // QUEUED nothing
            byteArrayOf(2) + u64(0) + u64(1L shl 10), // beyond 10 credits
            byteArrayOf(2) + u64(0) + u64(0),
            byteArrayOf(2) + u64(1) + u64(1),
            byteArrayOf(3) + u64(1) + u64(0),
            byteArrayOf(0) + ByteArray(16),
            byteArrayOf(5) + ByteArray(16),
            byteArrayOf(1) + u64(-1) + u64(0),
            ByteArray(16),
            ByteArray(18),
        )
        for (raw in bad) malformed { TorIssuerTransport.decodeClaim(raw, 10) }
    }

    @Test
    fun redeemDecoding() {
        val cap = ByteArray(98) { 0x77 }
        val ok = TorRelayTransport.decodeRedeem(byteArrayOf(1) + u64(2959) + u64(29_812_345) + u64(1_790_000_000) + cap)
        assertEquals(TorRelayTransport.REDEEM_OK, ok.result)
        assertEquals(2959L, ok.relayPeriodId)
        assertEquals(29_812_345L, ok.relayMinute)
        assertEquals(1_790_000_000L, ok.expiryUnixSeconds)
        assertArrayEquals(cap, ok.capability())
        assertFalse(ok.toString().contains(hex(cap)))
        val replayed = TorRelayTransport.decodeRedeem(byteArrayOf(2) + u64(2959) + u64(1) + u64(0))
        assertEquals(TorRelayTransport.REDEEM_REPLAYED, replayed.result)
        assertNull(replayed.capability())
        assertEquals(TorRelayTransport.REDEEM_WRONG_PERIOD, TorRelayTransport.decodeRedeem(byteArrayOf(3) + u64(2960) + u64(1) + u64(0)).result)
        val bad = listOf(
            byteArrayOf(1) + u64(2959) + u64(1) + u64(1_790_000_000), // OK without a capability
            byteArrayOf(1) + u64(2959) + u64(1) + u64(0) + cap, // OK without an expiry
            byteArrayOf(2) + u64(2959) + u64(1) + u64(0) + cap, // REPLAYED with a capability
            byteArrayOf(3) + u64(2959) + u64(1) + u64(5), // WRONG_PERIOD with an expiry
            byteArrayOf(0) + u64(2959) + u64(1) + u64(0),
            byteArrayOf(4) + u64(2959) + u64(1) + u64(0),
            byteArrayOf(2) + u64(-1) + u64(1) + u64(0),
            byteArrayOf(1) + u64(2959) + u64(1) + u64(1) + cap.copyOf(82), // a v1-sized capability
            ByteArray(24),
        )
        for (raw in bad) malformed { TorRelayTransport.decodeRedeem(raw) }
    }

    /** A transport whose every native call fails the test: argument checks must come first. */
    private val unreachable = TorIssuerTransport(TorIssuerTransport.HandleCall { throw AssertionError("native call reached") })

    @Test
    fun argumentsAreCheckedBeforeTheNativeCall() {
        val iae = IllegalArgumentException::class.java
        val flow = TorIssuerTransport.newFlow()
        val t = unreachable
        val token = ByteArray(354)
        assertThrows(iae) { t.requestInvoice(ByteArray(15), ByteArray(32), emptyList(), 2957) }
        assertThrows(iae) { t.requestInvoice(flow, ByteArray(31), emptyList(), 2957) }
        assertThrows(iae) { t.requestInvoice(flow, ByteArray(32), emptyList(), -1) }
        assertThrows(iae) { t.requestInvoice(flow, ByteArray(32), listOf(ByteArray(353)), 2957) }
        assertThrows(iae) { t.requestInvoice(flow, ByteArray(32), List(21) { token }, 2957) }
        assertThrows(iae) { t.requestInvoice(flow, ByteArray(32), emptyList(), 2957, 0) }
        assertThrows(iae) { t.requestInvoice(flow, ByteArray(32), emptyList(), 2957, 60_001) }
        val pack = EntitlementCrypto.PRODUCT_PACK_XMR
        assertThrows(iae) { t.blindSign(flow, ByteArray(15), ByteArray(32), ByteArray(32), pack, 2957, ByteArray(32), 243) }
        assertThrows(iae) { t.blindSign(flow, ByteArray(16), ByteArray(32), ByteArray(31), pack, 2957, ByteArray(32), 243) }
        assertThrows(iae) { t.blindSign(flow, ByteArray(16), ByteArray(32), ByteArray(32), EntitlementCrypto.PRODUCT_TRIAL, 2957, ByteArray(32), 243) }
        assertThrows(iae) { t.blindSign(flow, ByteArray(16), ByteArray(32), ByteArray(32), pack, 2957, ByteArray(32), 0) }
        assertThrows(iae) { t.blindSign(flow, ByteArray(16), ByteArray(32), ByteArray(32), pack, 2957, ByteArray(32), 2564) }
        assertThrows(iae) { t.blindSign(flow, ByteArray(16), ByteArray(32), ByteArray(32), pack, 2957, ByteArray(32), 243, 120_001) }
        assertThrows(iae) { t.invoiceStatus(flow, ByteArray(16), ByteArray(33)) }
        assertThrows(iae) { t.redeemInvite(flow, ByteArray(353), ByteArray(32), 2957, ByteArray(32), 48) }
        assertThrows(iae) { t.redeemInvite(flow, token, ByteArray(32), 2957, ByteArray(32), 48, 0) }
        assertThrows(iae) { t.claimPayout(flow, ByteArray(16), emptyList(), "4") }
        assertThrows(iae) { t.claimPayout(flow, ByteArray(17), List(10) { token }, "4") }
        assertThrows(iae) { t.claimPayout(flow, ByteArray(16), List(65) { token }, "4") }
        assertThrows(iae) { t.refreshCredit(flow, ByteArray(355), ByteArray(32), ByteArray(32)) }
        assertThrows(iae) { t.endFlow(ByteArray(17)) }
        // Flow ids: 16 random bytes each.
        val other = TorIssuerTransport.newFlow()
        assertEquals(16, flow.size)
        assertFalse(flow.contentEquals(other))
    }

    /**
     * `TorRelayTransport.withHandle` throws `closed` once the transport is closed, before any native
     * call. Ending a flow then is a no-op (closing dropped every flow; the native side ignores a
     * stopped handle as well), so a `finally { endFlow(..) }` never replaces a call's outcome.
     */
    @Test
    fun endFlowOnAClosedTransportIsANoOp() {
        val flow = TorIssuerTransport.newFlow()
        val closed = TorIssuerTransport(TorIssuerTransport.HandleCall { throw NetworkException("closed") })
        closed.endFlow(flow)
        closed.endFlow(flow)
        // Every other call on a closed transport still fails with `closed`.
        val e = assertThrows(NetworkException::class.java) { closed.invoiceStatus(flow, ByteArray(16), ByteArray(32)) }
        assertEquals("closed", e.category)
        // Any other failure of the native call still surfaces.
        val broken = TorIssuerTransport(TorIssuerTransport.HandleCall { throw NetworkException("internal") })
        assertEquals("internal", assertThrows(NetworkException::class.java) { broken.endFlow(flow) }.category)
        // On an open transport the call reaches the handle.
        var calls = 0
        val open = TorIssuerTransport(TorIssuerTransport.HandleCall { calls++; ByteArray(0) })
        open.endFlow(flow)
        assertEquals(1, calls)
    }

    @Test
    fun tokenListsArePackedWhole() {
        val a = ByteArray(354) { 1 }
        val b = ByteArray(354) { 2 }
        assertArrayEquals(a + b, TorIssuerTransport.packTokens(listOf(a, b), 20))
        assertEquals(0, TorIssuerTransport.packTokens(emptyList(), 20).size)
        assertThrows(IllegalArgumentException::class.java) { TorIssuerTransport.packTokens(listOf(a, ByteArray(10)), 20) }
        assertThrows(IllegalArgumentException::class.java) { TorIssuerTransport.packTokens(List(3) { a }, 2) }
    }
}
