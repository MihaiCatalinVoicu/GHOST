package org.ghost.sync.engine

import org.ghost.network.NetworkException
import org.ghost.network.OnionAddress
import org.ghost.network.TorIssuerTransport
import org.ghost.network.TorRelayTransport
import org.ghost.sync.port.EntitlementCalls
import org.ghost.sync.port.TransportLease
import java.nio.ByteBuffer
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.atomic.AtomicLong

/**
 * Entitlement calls that record every call (name, flow, deadline) and answer at once with a fixed,
 * well-formed answer; [failure] may name a category to fail a call with, [during] runs inside each
 * call before it answers (a test may block there).
 */
internal class RecordingCalls : EntitlementCalls {
    class Call(val name: String, flow: ByteArray?, val deadlineMillis: Int) {
        val flow: ByteArray? = flow?.copyOf()

        override fun toString(): String = "Call($name)"
    }

    val calls = CopyOnWriteArrayList<Call>()
    val ended = CopyOnWriteArrayList<ByteArray>()

    @Volatile
    var failure: (String) -> String? = { null }

    @Volatile
    var during: (String) -> Unit = {}

    private fun <T> call(name: String, flow: ByteArray?, deadlineMillis: Int, answer: () -> T): T {
        calls += Call(name, flow, deadlineMillis)
        during(name)
        failure(name)?.let { throw NetworkException(it) }
        return answer()
    }

    override fun redeem(relay: OnionAddress, namespace: ByteArray, token: ByteArray, requestId: ByteArray, deadlineMillis: Int): TorRelayTransport.RedeemAnswer =
        call("redeem", null, deadlineMillis) {
            TorRelayTransport.RedeemAnswer(TorRelayTransport.REDEEM_OK, 1, 1, 1, ByteArray(TorRelayTransport.CAPABILITY_V2_BYTES))
        }

    override fun requestInvoice(flow: ByteArray, claimHash: ByteArray, credits: List<ByteArray>, baseWeek: Long, deadlineMillis: Int): TorIssuerTransport.InvoiceAnswer =
        call("requestInvoice", flow, deadlineMillis) { TorIssuerTransport.InvoiceAnswer(TorIssuerTransport.INVOICE_WRONG_PERIOD, ByteArray(16), 0, null, 0) }

    override fun blindSign(
        flow: ByteArray,
        invoiceId: ByteArray,
        claimKey: ByteArray,
        seed: ByteArray,
        product: Int,
        baseWeek: Long,
        layoutDigest: ByteArray,
        positions: Int,
        deadlineMillis: Int,
    ): TorIssuerTransport.SignAnswer =
        call("blindSign", flow, deadlineMillis) { TorIssuerTransport.SignAnswer(TorIssuerTransport.STATE_AWAITING_PAYMENT, 0, 0, emptyList()) }

    override fun invoiceStatus(flow: ByteArray, invoiceId: ByteArray, claimKey: ByteArray, deadlineMillis: Int): TorIssuerTransport.StatusAnswer =
        call("invoiceStatus", flow, deadlineMillis) { TorIssuerTransport.StatusAnswer(TorIssuerTransport.STATE_AWAITING_PAYMENT, 0, 0) }

    override fun redeemInvite(
        flow: ByteArray,
        inviteToken: ByteArray,
        seed: ByteArray,
        baseWeek: Long,
        layoutDigest: ByteArray,
        positions: Int,
        deadlineMillis: Int,
    ): TorIssuerTransport.TrialAnswer = call("redeemInvite", flow, deadlineMillis) { TorIssuerTransport.TrialAnswer(TorIssuerTransport.TRIAL_REPLAYED, emptyList()) }

    override fun claimPayout(flow: ByteArray, claimId: ByteArray, credits: List<ByteArray>, payoutAddress: String, deadlineMillis: Int): TorIssuerTransport.ClaimAnswer =
        call("claimPayout", flow, deadlineMillis) { TorIssuerTransport.ClaimAnswer(TorIssuerTransport.CLAIM_CONFLICT, 0, 0) }

    override fun refreshCredit(flow: ByteArray, receivedCredit: ByteArray, seed: ByteArray, layoutDigest: ByteArray, deadlineMillis: Int): TorIssuerTransport.RefreshAnswer =
        call("refreshCredit", flow, deadlineMillis) { TorIssuerTransport.RefreshAnswer(TorIssuerTransport.REFRESH_REPLAYED, null) }

    override fun endFlow(flow: ByteArray) {
        ended += flow.copyOf()
    }

    override fun toString(): String = "RecordingCalls"
}

/** A lease over [calls] that is READY while [ready]; flows are distinct 16-byte counters. */
internal class RecordingLease(val calls: RecordingCalls = RecordingCalls()) : TransportLease {
    @Volatile
    private var open = true

    @Volatile
    var ready: Boolean = true

    override val closed: Boolean get() = !open

    override fun awaitReady(deadlineMonotonicMillis: Long): Boolean = open && ready

    override fun close() {
        open = false
    }

    override fun <T> use(block: (EntitlementCalls) -> T): T {
        if (!open || !ready) throw NetworkException("closed")
        return block(calls)
    }

    override fun newFlow(): ByteArray = ByteBuffer.allocate(16).putLong(FLOWS.incrementAndGet()).putLong(0x5eed).array()

    override fun endFlow(flow: ByteArray) {
        if (open && ready) calls.endFlow(flow)
    }

    override fun toString(): String = "RecordingLease"

    companion object {
        private val FLOWS = AtomicLong()
    }
}

/** The category of the NetworkException [block] threw, or null when it returned. */
internal fun category(block: () -> Unit): String? = try {
    block()
    null
} catch (e: NetworkException) {
    e.category
}
