package org.ghost.sync.port

import org.ghost.network.OnionAddress
import org.ghost.network.TorIssuerTransport
import org.ghost.network.TorRelayTransport

/**
 * Leases on the one transport for the session participant (Phase 8 design §11.6). Production:
 * `org.ghost.sync.android.TorTransportHolder`. The runtime opens one lease per session, quiet run or
 * user issuer call and closes it before the transport is aborted at that activity's end.
 */
interface LeasePort {
    fun openLease(): TransportLease
}

/**
 * One lease. While it is open, [use] reaches the transport that is READY now; a call can never
 * reach a transport created after the lease closed, so a lease of one activity never carries a call
 * into the next one. Every method may be called from any thread.
 */
interface TransportLease {
    /** True once [close] ran; every [use] then fails with `NetworkException("closed")`. */
    val closed: Boolean

    /**
     * Waits until the transport is READY while the lease is open, at most until
     * [deadlineMonotonicMillis]; true when it is READY. Never creates or bootstraps a transport.
     */
    fun awaitReady(deadlineMonotonicMillis: Long): Boolean

    /** Idempotent; wakes [awaitReady]. Calls in flight end when the transport is aborted. */
    fun close()

    /** Runs one call on the READY transport; `NetworkException("closed")` when closed or not READY. */
    fun <T> use(block: (EntitlementCalls) -> T): T

    /** A fresh 16-byte issuer flow id from a CSPRNG (one per call, never reused). */
    fun newFlow(): ByteArray

    /** Ends [flow] (its circuits are never used again); never throws for a closed lease or transport. */
    fun endFlow(flow: ByteArray)
}

/**
 * The redemption and issuer calls of one native transport (Phase 8 design §10.9, §11.7), with the
 * flow of every issuer call named by the caller. Production: `TorRelayTransport.redeem` and
 * [TorIssuerTransport] on the same handle. Failures as [TorIssuerTransport] documents.
 */
interface EntitlementCalls {
    fun redeem(relay: OnionAddress, namespace: ByteArray, token: ByteArray, requestId: ByteArray, deadlineMillis: Int): TorRelayTransport.RedeemAnswer

    fun requestInvoice(flow: ByteArray, claimHash: ByteArray, credits: List<ByteArray>, baseWeek: Long, deadlineMillis: Int): TorIssuerTransport.InvoiceAnswer

    fun blindSign(
        flow: ByteArray,
        invoiceId: ByteArray,
        claimKey: ByteArray,
        seed: ByteArray,
        product: Int,
        baseWeek: Long,
        layoutDigest: ByteArray,
        positions: Int,
        deadlineMillis: Int,
    ): TorIssuerTransport.SignAnswer

    fun invoiceStatus(flow: ByteArray, invoiceId: ByteArray, claimKey: ByteArray, deadlineMillis: Int): TorIssuerTransport.StatusAnswer

    fun redeemInvite(
        flow: ByteArray,
        inviteToken: ByteArray,
        seed: ByteArray,
        baseWeek: Long,
        layoutDigest: ByteArray,
        positions: Int,
        deadlineMillis: Int,
    ): TorIssuerTransport.TrialAnswer

    fun claimPayout(flow: ByteArray, claimId: ByteArray, credits: List<ByteArray>, payoutAddress: String, deadlineMillis: Int): TorIssuerTransport.ClaimAnswer

    fun refreshCredit(flow: ByteArray, receivedCredit: ByteArray, seed: ByteArray, layoutDigest: ByteArray, deadlineMillis: Int): TorIssuerTransport.RefreshAnswer

    /** Idempotent; a no-op on a closed transport. */
    fun endFlow(flow: ByteArray)
}
