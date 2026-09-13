package org.ghost.entitlement.android

import org.ghost.entitlement.port.TokenCryptoPort
import org.ghost.network.EntitlementCrypto

/**
 * [TokenCryptoPort] over the JNI [EntitlementCrypto] (design §11.7): the schedule built into
 * `libghost_client_net.so`, verified natively under the pinned schedule key. The summary is read once
 * per process (a failed read, e.g. a missing library, is retried at the next use). Together with
 * `port.InviteTokenCheck` this is the `Invite.TokenCheck` over `nativeVerifyToken` (§19.20 point 6).
 */
class NativeTokenCrypto : TokenCryptoPort {
    private val summary: EntitlementCrypto.ScheduleSummary by lazy { EntitlementCrypto.scheduleSummary() }

    override fun scheduleSummary(): EntitlementCrypto.ScheduleSummary = summary

    override fun layout(product: Int, index: Long): EntitlementCrypto.Layout = EntitlementCrypto.layout(product, index)

    override fun verifyToken(token: ByteArray, kind: Int): EntitlementCrypto.VerifiedToken? = EntitlementCrypto.verifyToken(token, kind)

    override fun validateAddress(address: String, purpose: Int): EntitlementCrypto.AddressInfo? = EntitlementCrypto.validateAddress(address, purpose)

    override fun paymentUri(subaddress: String, amountAtomic: Long): String = EntitlementCrypto.paymentUri(subaddress, amountAtomic)

    override fun toString(): String = "NativeTokenCrypto"
}
