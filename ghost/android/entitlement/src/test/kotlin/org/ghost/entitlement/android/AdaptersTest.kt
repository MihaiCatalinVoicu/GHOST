package org.ghost.entitlement.android

import org.ghost.entitlement.FakeIssuer
import org.ghost.entitlement.TestBytes
import org.ghost.entitlement.TestOnions
import org.ghost.entitlement.World
import org.ghost.entitlement.api.PayWith
import org.ghost.network.OnionAddress
import org.ghost.network.TorIssuerTransport
import org.ghost.network.TorRelayTransport
import org.ghost.sync.api.IssuerAccess
import org.ghost.sync.api.NamespaceId
import org.ghost.sync.api.ParticipantSession
import org.ghost.sync.api.RelayRedeemAccess
import org.ghost.sync.api.SessionKind
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The Android adapters (design §11.1 `android/`): a session port grants exactly the session's
 * accesses, the Tor ports delegate without logic, and the participant drives the real engine.
 */
class AdaptersTest {

    private class RecordingAccess : IssuerAccess {
        val calls = ArrayList<String>()

        override fun requestInvoice(claimHash: ByteArray, credits: List<ByteArray>, baseWeek: Long, deadlineMillis: Int): TorIssuerTransport.InvoiceAnswer {
            calls += "requestInvoice"
            return TorIssuerTransport.InvoiceAnswer(TorIssuerTransport.INVOICE_WRONG_PERIOD, ByteArray(16), 0, null, 0)
        }

        override fun blindSign(
            invoiceId: ByteArray,
            claimKey: ByteArray,
            seed: ByteArray,
            product: Int,
            baseWeek: Long,
            layoutDigest: ByteArray,
            positions: Int,
            deadlineMillis: Int,
        ): TorIssuerTransport.SignAnswer {
            calls += "blindSign"
            return TorIssuerTransport.SignAnswer(TorIssuerTransport.STATE_AWAITING_PAYMENT, 0, 0, emptyList())
        }

        override fun invoiceStatus(invoiceId: ByteArray, claimKey: ByteArray, deadlineMillis: Int): TorIssuerTransport.StatusAnswer {
            calls += "invoiceStatus"
            return TorIssuerTransport.StatusAnswer(TorIssuerTransport.STATE_AWAITING_PAYMENT, 0, 0)
        }

        override fun redeemInvite(
            inviteToken: ByteArray,
            seed: ByteArray,
            baseWeek: Long,
            layoutDigest: ByteArray,
            positions: Int,
            deadlineMillis: Int,
        ): TorIssuerTransport.TrialAnswer {
            calls += "redeemInvite"
            return TorIssuerTransport.TrialAnswer(TorIssuerTransport.TRIAL_REPLAYED, emptyList())
        }

        override fun claimPayout(claimId: ByteArray, credits: List<ByteArray>, payoutAddress: String, deadlineMillis: Int): TorIssuerTransport.ClaimAnswer {
            calls += "claimPayout"
            return TorIssuerTransport.ClaimAnswer(TorIssuerTransport.CLAIM_CONFLICT, 0, 0)
        }

        override fun refreshCredit(receivedCredit: ByteArray, seed: ByteArray, layoutDigest: ByteArray, deadlineMillis: Int): TorIssuerTransport.RefreshAnswer {
            calls += "refreshCredit"
            return TorIssuerTransport.RefreshAnswer(TorIssuerTransport.REFRESH_REPLAYED, null)
        }
    }

    /** An `IssuerAccess` over the engine tests' fake issuer (as the lease would forward). */
    private class ForwardingAccess(private val issuer: FakeIssuer) : IssuerAccess {
        override fun requestInvoice(claimHash: ByteArray, credits: List<ByteArray>, baseWeek: Long, deadlineMillis: Int) =
            issuer.requestInvoice(claimHash, credits, baseWeek)

        override fun blindSign(
            invoiceId: ByteArray,
            claimKey: ByteArray,
            seed: ByteArray,
            product: Int,
            baseWeek: Long,
            layoutDigest: ByteArray,
            positions: Int,
            deadlineMillis: Int,
        ) = issuer.blindSign(invoiceId, claimKey, seed, product, baseWeek, layoutDigest, positions)

        override fun invoiceStatus(invoiceId: ByteArray, claimKey: ByteArray, deadlineMillis: Int) = issuer.invoiceStatus(invoiceId, claimKey)

        override fun redeemInvite(inviteToken: ByteArray, seed: ByteArray, baseWeek: Long, layoutDigest: ByteArray, positions: Int, deadlineMillis: Int) =
            issuer.redeemInvite(inviteToken, seed, baseWeek, layoutDigest, positions)

        override fun claimPayout(claimId: ByteArray, credits: List<ByteArray>, payoutAddress: String, deadlineMillis: Int) =
            issuer.claimPayout(claimId, credits, payoutAddress)

        override fun refreshCredit(receivedCredit: ByteArray, seed: ByteArray, layoutDigest: ByteArray, deadlineMillis: Int) =
            issuer.refreshCredit(receivedCredit, seed, layoutDigest)
    }

    private class RecordingRedeem : RelayRedeemAccess {
        val calls = ArrayList<OnionAddress>()

        override fun redeem(relay: OnionAddress, namespace: NamespaceId, token: ByteArray, requestId: ByteArray, deadlineMillis: Int): TorRelayTransport.RedeemAnswer {
            calls += relay
            return TorRelayTransport.RedeemAnswer(TorRelayTransport.REDEEM_REPLAYED, 1, 1, 0, null)
        }
    }

    private class Session(
        override val kind: SessionKind,
        override val relayRedeem: RelayRedeemAccess? = null,
        override val issuer: IssuerAccess? = null,
    ) : ParticipantSession {
        var trusted = true
        override var closed = false
        override val deadlineMonotonicMillis: Long = Long.MAX_VALUE
        override fun clockTrusted(): Boolean = trusted
    }

    @Test
    fun aSessionPortGrantsExactlyTheSessionsAccesses() {
        val quiet = ParticipantSessionPort(Session(SessionKind.QUIET, issuer = RecordingAccess()))
        assertTrue(quiet.issuer is TorIssuerPort)
        assertNull(quiet.redeem)
        val relay = Session(SessionKind.FOREGROUND, relayRedeem = RecordingRedeem())
        val port = ParticipantSessionPort(relay)
        assertTrue(port.redeem is TorRedeemPort)
        assertNull(port.issuer)
        assertEquals(SessionKind.FOREGROUND, port.kind)
        assertTrue(port.clockTrusted())
        relay.trusted = false
        relay.closed = true
        assertFalse(port.clockTrusted())
        assertTrue(port.closed)
    }

    @Test
    fun theTorPortsDelegateEveryCall() {
        val access = RecordingAccess()
        val issuer = TorIssuerPort(access)
        val b = ByteArray(32)
        issuer.requestInvoice(b, emptyList(), 1)
        issuer.blindSign(ByteArray(16), b, b, 1, 1, b, 1)
        issuer.invoiceStatus(ByteArray(16), b)
        issuer.redeemInvite(TestBytes.token(1), b, 1, b, 1)
        issuer.claimPayout(ByteArray(16), listOf(TestBytes.token(2)), "5" + "a".repeat(94))
        issuer.refreshCredit(TestBytes.token(3), b, b)
        assertEquals(listOf("requestInvoice", "blindSign", "invoiceStatus", "redeemInvite", "claimPayout", "refreshCredit"), access.calls)
        val redeem = RecordingRedeem()
        TorRedeemPort(redeem).redeem(TestOnions.of(1), NamespaceId(b), TestBytes.token(4), ByteArray(16))
        assertEquals(listOf(TestOnions.of(1)), redeem.calls)
    }

    @Test
    fun theParticipantRunsTheEnginesQuietRunThroughTheIssuerAccess(): Unit = World().use { w ->
        checkNotNull(w.engine.startPurchase(PayWith.XMR))
        val participant = EntitlementParticipant(w.engine)
        participant.onQuietRun(Session(SessionKind.QUIET, issuer = ForwardingAccess(w.issuer)))
        assertEquals(1, w.issuer.named("requestInvoice").size)
        val untrusted = Session(SessionKind.QUIET, issuer = ForwardingAccess(w.issuer)).also { it.trusted = false }
        participant.onQuietRun(untrusted)
        assertEquals("no issuer call without a trusted clock", 1, w.issuer.calls.size)
        // A relay session that is already closed returns at once and never reaches the issuer.
        participant.onRelaySession(Session(SessionKind.FOREGROUND, relayRedeem = RecordingRedeem()).also { it.closed = true })
        assertEquals(1, w.issuer.calls.size)
    }
}
