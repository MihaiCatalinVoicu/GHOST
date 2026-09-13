package org.ghost.entitlement.android

import org.ghost.entitlement.port.IssuerPort
import org.ghost.network.TorIssuerTransport
import org.ghost.sync.api.IssuerAccess

/**
 * [IssuerPort] over the `IssuerAccess` of a quiet run or user issuer call (design §11.6, §11.7): one
 * call per session on a fresh issuer flow of the process's one Tor transport, ended after the call.
 * It adds no protocol logic; the Rust core checks every request and answer (ADR-19).
 */
class TorIssuerPort(private val access: IssuerAccess) : IssuerPort {
    override fun requestInvoice(claimHash: ByteArray, credits: List<ByteArray>, baseWeek: Long): TorIssuerTransport.InvoiceAnswer =
        access.requestInvoice(claimHash, credits, baseWeek)

    override fun blindSign(
        invoiceId: ByteArray,
        claimKey: ByteArray,
        seed: ByteArray,
        product: Int,
        baseWeek: Long,
        layoutDigest: ByteArray,
        positions: Int,
    ): TorIssuerTransport.SignAnswer = access.blindSign(invoiceId, claimKey, seed, product, baseWeek, layoutDigest, positions)

    override fun invoiceStatus(invoiceId: ByteArray, claimKey: ByteArray): TorIssuerTransport.StatusAnswer =
        access.invoiceStatus(invoiceId, claimKey)

    override fun redeemInvite(inviteToken: ByteArray, seed: ByteArray, baseWeek: Long, layoutDigest: ByteArray, positions: Int): TorIssuerTransport.TrialAnswer =
        access.redeemInvite(inviteToken, seed, baseWeek, layoutDigest, positions)

    override fun claimPayout(claimId: ByteArray, credits: List<ByteArray>, payoutAddress: String): TorIssuerTransport.ClaimAnswer =
        access.claimPayout(claimId, credits, payoutAddress)

    override fun refreshCredit(receivedCredit: ByteArray, seed: ByteArray, layoutDigest: ByteArray): TorIssuerTransport.RefreshAnswer =
        access.refreshCredit(receivedCredit, seed, layoutDigest)

    override fun toString(): String = "TorIssuerPort"
}
