package org.ghost.sync.engine

import org.ghost.network.NetworkException
import org.ghost.network.OnionAddress
import org.ghost.network.TorIssuerTransport
import org.ghost.network.TorRelayTransport
import org.ghost.sync.api.IssuerAccess
import org.ghost.sync.api.NamespaceId
import org.ghost.sync.api.ParticipantSession
import org.ghost.sync.api.RelayRedeemAccess
import org.ghost.sync.port.EntitlementCalls
import org.ghost.sync.port.SyncClock
import org.ghost.sync.port.TransportLease
import java.util.concurrent.atomic.AtomicBoolean
import org.ghost.sync.api.SessionKind as ParticipantKind

/**
 * [ParticipantSession] over a [TransportLease] (built by [QuietRunScheduler.session]). The gating of
 * Phase 8 design §11.6 and §19.14 lives here and nowhere else:
 *  - redemption in FOREGROUND and BACKGROUND sessions, issuer calls in QUIET and USER_ISSUER_CALL
 *    sessions, never both;
 *  - the issuer access makes at most one call attempt: the first attempt uses it up, whatever its
 *    outcome, and every later one fails `closed` (J9: at most one issuer call per quiet run);
 *  - every issuer call runs on a fresh flow, ended after the call (R5);
 *  - no call from inside a sync transaction ([IllegalStateException]), none after the lease closed
 *    or with less than [QuietRunScheduler.MIN_CALL_MILLIS] left (`closed`), and each call's
 *    deadline is cut to the time left.
 *
 * Nothing here touches a session, a lane or the engine's breakers, pauses or transport faults: a
 * participant's calls cannot change the read lane (T19).
 */
internal class LeasedSession(
    override val kind: ParticipantKind,
    private val lease: TransportLease,
    override val deadlineMonotonicMillis: Long,
    private val clock: SyncClock,
    private val trusted: () -> Boolean,
    private val inTransaction: () -> Boolean,
) : ParticipantSession {

    override val relayRedeem: RelayRedeemAccess? =
        if (kind == ParticipantKind.FOREGROUND || kind == ParticipantKind.BACKGROUND) Redeem() else null

    override val issuer: IssuerAccess? =
        if (kind == ParticipantKind.QUIET || kind == ParticipantKind.USER_ISSUER_CALL) Issuer() else null

    override val closed: Boolean get() = lease.closed || clock.monotonicMillis() >= deadlineMonotonicMillis

    override fun clockTrusted(): Boolean = !closed && trusted()

    /** The deadline of a call asking for [requested] ms: at most what is left of the session. */
    private fun callDeadline(requested: Int): Int {
        check(!inTransaction()) { "a participant call inside a sync transaction" }
        if (lease.closed) throw NetworkException(CLOSED)
        val left = deadlineMonotonicMillis - clock.monotonicMillis()
        if (left < QuietRunScheduler.MIN_CALL_MILLIS) throw NetworkException(CLOSED)
        return minOf(requested.toLong(), left).toInt()
    }

    private inner class Redeem : RelayRedeemAccess {
        override fun redeem(relay: OnionAddress, namespace: NamespaceId, token: ByteArray, requestId: ByteArray, deadlineMillis: Int): TorRelayTransport.RedeemAnswer {
            val deadline = callDeadline(deadlineMillis)
            return lease.use { it.redeem(relay, namespace.toByteArray(), token, requestId, deadline) }
        }

        override fun toString(): String = "RelayRedeemAccess"
    }

    private inner class Issuer : IssuerAccess {
        private val used = AtomicBoolean()

        /** The one call of this access, on its own flow. */
        private fun <T> once(requested: Int, call: (EntitlementCalls, ByteArray, Int) -> T): T {
            if (!used.compareAndSet(false, true)) throw NetworkException(CLOSED)
            val deadline = callDeadline(requested)
            val flow = lease.newFlow()
            try {
                return lease.use { call(it, flow, deadline) }
            } finally {
                lease.endFlow(flow)
            }
        }

        override fun requestInvoice(claimHash: ByteArray, credits: List<ByteArray>, baseWeek: Long, deadlineMillis: Int): TorIssuerTransport.InvoiceAnswer =
            once(deadlineMillis) { c, flow, d -> c.requestInvoice(flow, claimHash, credits, baseWeek, d) }

        override fun blindSign(
            invoiceId: ByteArray,
            claimKey: ByteArray,
            seed: ByteArray,
            product: Int,
            baseWeek: Long,
            layoutDigest: ByteArray,
            positions: Int,
            deadlineMillis: Int,
        ): TorIssuerTransport.SignAnswer =
            once(deadlineMillis) { c, flow, d -> c.blindSign(flow, invoiceId, claimKey, seed, product, baseWeek, layoutDigest, positions, d) }

        override fun invoiceStatus(invoiceId: ByteArray, claimKey: ByteArray, deadlineMillis: Int): TorIssuerTransport.StatusAnswer =
            once(deadlineMillis) { c, flow, d -> c.invoiceStatus(flow, invoiceId, claimKey, d) }

        override fun redeemInvite(
            inviteToken: ByteArray,
            seed: ByteArray,
            baseWeek: Long,
            layoutDigest: ByteArray,
            positions: Int,
            deadlineMillis: Int,
        ): TorIssuerTransport.TrialAnswer =
            once(deadlineMillis) { c, flow, d -> c.redeemInvite(flow, inviteToken, seed, baseWeek, layoutDigest, positions, d) }

        override fun claimPayout(claimId: ByteArray, credits: List<ByteArray>, payoutAddress: String, deadlineMillis: Int): TorIssuerTransport.ClaimAnswer =
            once(deadlineMillis) { c, flow, d -> c.claimPayout(flow, claimId, credits, payoutAddress, d) }

        override fun refreshCredit(receivedCredit: ByteArray, seed: ByteArray, layoutDigest: ByteArray, deadlineMillis: Int): TorIssuerTransport.RefreshAnswer =
            once(deadlineMillis) { c, flow, d -> c.refreshCredit(flow, receivedCredit, seed, layoutDigest, d) }

        override fun toString(): String = "IssuerAccess"
    }

    override fun toString(): String = "ParticipantSession($kind)"

    private companion object {
        const val CLOSED = "closed"
    }
}
