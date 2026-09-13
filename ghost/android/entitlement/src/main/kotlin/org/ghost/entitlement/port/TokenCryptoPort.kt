package org.ghost.entitlement.port

import org.ghost.identity.Invite
import org.ghost.network.EntitlementCrypto

/**
 * The stateless entitlement functions of the Rust core (Phase 8 design §11.7) over the Entitlement
 * Schedule built into the native library. Production: `android.NativeTokenCrypto` over
 * [EntitlementCrypto]; JVM tests: a test schedule. Kotlin gets summaries, layout digests, offline
 * token verdicts, validated addresses and payment URIs, never keys, blinded messages, blind
 * signatures, salts, nonces or r. Failures: `NetworkException(category)` (`internal` when the
 * embedded schedule does not verify, `native_missing` without the library).
 */
interface TokenCryptoPort {
    /** The verified summary of the embedded schedule. */
    fun scheduleSummary(): EntitlementCrypto.ScheduleSummary

    /** The frozen layout of [product] at [index] (base week, or the credit epoch of a refresh). */
    fun layout(product: Int, index: Long): EntitlementCrypto.Layout

    /** The offline check of [token] as [kind], or null when the schedule refuses it. */
    fun verifyToken(token: ByteArray, kind: Int): EntitlementCrypto.VerifiedToken?

    /** A Monero address of the schedule's network for [purpose], or null when refused. */
    fun validateAddress(address: String, purpose: Int): EntitlementCrypto.AddressInfo?

    /** `monero:<subaddress>?tx_amount=<12 decimals>`, built natively from validated values. */
    fun paymentUri(subaddress: String, amountAtomic: Long): String
}

/**
 * [Invite.TokenCheck] over the offline token check of the schedule (design §8.2, §19.20 point 6): the
 * INVITE epoch of a token the schedule accepts as an invite token, else null. In production this is
 * `nativeVerifyToken(token, INVITE)` through [TokenCryptoPort].
 */
class InviteTokenCheck(private val crypto: TokenCryptoPort) : Invite.TokenCheck {
    override fun inviteEpoch(token: ByteArray): Long? = crypto.verifyToken(token, EntitlementCrypto.KIND_INVITE)?.epoch

    override fun toString(): String = "InviteTokenCheck"
}
