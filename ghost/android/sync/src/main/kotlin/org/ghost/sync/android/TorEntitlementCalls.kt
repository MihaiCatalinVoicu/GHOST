package org.ghost.sync.android

import org.ghost.network.NetworkException
import org.ghost.network.OnionAddress
import org.ghost.network.RelayTransport
import org.ghost.network.TorIssuerTransport
import org.ghost.network.TorRelayTransport
import org.ghost.sync.port.EntitlementCalls

/** The entitlement calls of one native transport (the holder keeps one per transport). */
internal fun interface EntitlementCallsFactory {
    fun of(transport: RelayTransport): EntitlementCalls

    companion object {
        /** Production: the redemption and issuer calls of the Rust core on a [TorRelayTransport]. */
        val TOR: EntitlementCallsFactory = EntitlementCallsFactory { TorEntitlementCalls(it) }
    }
}

/**
 * [EntitlementCalls] on the handle of one [TorRelayTransport] (Phase 8 design §11.7): redemption on
 * the namespace's circuits, issuer calls on their flow's own circuits, both through the one Tor
 * client of the process. It adds no protocol logic (ADR-19): the Rust core checks every request
 * and every answer. Nothing is caught here, and no message carries an identifier (T3).
 *
 * The holder only ever creates [TorRelayTransport]s in production ([TorTransportHolder.forApp]); a
 * transport of another kind has no entitlement calls, and a call on it fails `internal` before any
 * I/O.
 */
internal class TorEntitlementCalls(private val transport: RelayTransport) : EntitlementCalls {
    private val tor: TorRelayTransport? = transport as? TorRelayTransport
    private val issuer: TorIssuerTransport? = tor?.let(::TorIssuerTransport)

    private fun tor(): TorRelayTransport = tor ?: throw NetworkException(INTERNAL)

    private fun issuer(): TorIssuerTransport = issuer ?: throw NetworkException(INTERNAL)

    override fun redeem(relay: OnionAddress, namespace: ByteArray, token: ByteArray, requestId: ByteArray, deadlineMillis: Int): TorRelayTransport.RedeemAnswer =
        tor().redeem(relay, namespace, token, requestId, deadlineMillis)

    override fun requestInvoice(flow: ByteArray, claimHash: ByteArray, credits: List<ByteArray>, baseWeek: Long, deadlineMillis: Int): TorIssuerTransport.InvoiceAnswer =
        issuer().requestInvoice(flow, claimHash, credits, baseWeek, deadlineMillis)

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
    ): TorIssuerTransport.SignAnswer = issuer().blindSign(flow, invoiceId, claimKey, seed, product, baseWeek, layoutDigest, positions, deadlineMillis)

    override fun invoiceStatus(flow: ByteArray, invoiceId: ByteArray, claimKey: ByteArray, deadlineMillis: Int): TorIssuerTransport.StatusAnswer =
        issuer().invoiceStatus(flow, invoiceId, claimKey, deadlineMillis)

    override fun redeemInvite(
        flow: ByteArray,
        inviteToken: ByteArray,
        seed: ByteArray,
        baseWeek: Long,
        layoutDigest: ByteArray,
        positions: Int,
        deadlineMillis: Int,
    ): TorIssuerTransport.TrialAnswer = issuer().redeemInvite(flow, inviteToken, seed, baseWeek, layoutDigest, positions, deadlineMillis)

    override fun claimPayout(flow: ByteArray, claimId: ByteArray, credits: List<ByteArray>, payoutAddress: String, deadlineMillis: Int): TorIssuerTransport.ClaimAnswer =
        issuer().claimPayout(flow, claimId, credits, payoutAddress, deadlineMillis)

    override fun refreshCredit(flow: ByteArray, receivedCredit: ByteArray, seed: ByteArray, layoutDigest: ByteArray, deadlineMillis: Int): TorIssuerTransport.RefreshAnswer =
        issuer().refreshCredit(flow, receivedCredit, seed, layoutDigest, deadlineMillis)

    /** A no-op on a closed transport ([TorIssuerTransport.endFlow]) and on a transport without issuer calls. */
    override fun endFlow(flow: ByteArray) {
        issuer?.endFlow(flow)
    }

    override fun toString(): String = "TorEntitlementCalls"

    private companion object {
        const val INTERNAL = "internal"
    }
}
