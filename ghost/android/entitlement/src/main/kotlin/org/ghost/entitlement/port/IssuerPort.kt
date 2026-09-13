package org.ghost.entitlement.port

import org.ghost.network.TorIssuerTransport

/**
 * The issuer calls of one session (Phase 8 design §5.3, §8.3, §9.4, §19.8), each on a fresh issuer
 * flow. Production: `android.TorIssuerPort` over the session's `IssuerAccess`, which exists only in
 * quiet runs and user issuer calls and allows one call (design §11.6, J9). The native side recomputes
 * every request from the stored seed and layout digest (identical bytes on every retry) and validates
 * every answer against the schedule; protocol outcomes are results, failures are
 * `NetworkException(category)` or [IllegalArgumentException] (refused before any I/O).
 */
interface IssuerPort {
    fun requestInvoice(claimHash: ByteArray, credits: List<ByteArray>, baseWeek: Long): TorIssuerTransport.InvoiceAnswer

    fun blindSign(
        invoiceId: ByteArray,
        claimKey: ByteArray,
        seed: ByteArray,
        product: Int,
        baseWeek: Long,
        layoutDigest: ByteArray,
        positions: Int,
    ): TorIssuerTransport.SignAnswer

    fun invoiceStatus(invoiceId: ByteArray, claimKey: ByteArray): TorIssuerTransport.StatusAnswer

    fun redeemInvite(inviteToken: ByteArray, seed: ByteArray, baseWeek: Long, layoutDigest: ByteArray, positions: Int): TorIssuerTransport.TrialAnswer

    fun claimPayout(claimId: ByteArray, credits: List<ByteArray>, payoutAddress: String): TorIssuerTransport.ClaimAnswer

    fun refreshCredit(receivedCredit: ByteArray, seed: ByteArray, layoutDigest: ByteArray): TorIssuerTransport.RefreshAnswer
}
