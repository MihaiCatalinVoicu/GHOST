package org.ghost.entitlement.api

/**
 * The entitlement facade for Phase 13 (design §11.2): UI-less, counts and enums only. Every method is
 * local unless stated otherwise, never blocks on the network and may be called from any thread except
 * from inside a sync transaction. Issuer calls happen only in quiet runs, or for the user actions that
 * say so (declared L3 samples, STANDARD mode only).
 */
interface Entitlement {
    /** Coverage, counts and flags. */
    fun status(): EntitlementStatus

    /**
     * Records a purchase intent (local only); its `RequestInvoice` runs in a later quiet run. Null when
     * the schedule ends within 5 weeks, or (credits) when own fresh credits do not cover the price.
     */
    fun startPurchase(payWith: PayWith): PurchaseId?

    fun requiredDisclosures(id: PurchaseId): Set<Disclosure>

    fun acknowledge(id: PurchaseId, disclosures: Set<Disclosure>)

    /** Null until the pack is invoiced and every required disclosure was acknowledged, and after the deadline. */
    fun paymentInstructions(id: PurchaseId): PaymentInstructions?

    /** Optional "get invoice now": the purchase's `RequestInvoice` as a user call (STANDARD mode only). */
    fun requestInvoiceNow(id: PurchaseId)

    /** Optional "check now": `InvoiceStatus` as a user call (STANDARD mode only); never signs. */
    fun checkNow(id: PurchaseId)

    /** Only while no payment instructions were ever shown. */
    fun cancel(id: PurchaseId): Boolean

    /** Onboarding (§8.3): verifies the invite, records the trial, creates the identity and starts `RedeemInvite`. */
    fun activate(inviteText: String): ActivationResult

    fun activationState(): ActivationState

    /** A signed `ghost://invite/…` link, or null without a fresh invite token or usable drop relays. */
    fun createInvite(expiryDay: Int): String?

    /** Revokes invite [index] by redeeming it in a later quiet run (§8.6, §19.14). */
    fun revokeInvite(index: Int): Boolean

    /** A claim of own fresh credits to [address] (validated locally), run in a later quiet run. */
    fun claimPayout(address: String): ClaimId?

    fun setAutoRenewWithCredits(enabled: Boolean)

    /** The payment screen of [id] is shown (§19.11): relay sessions are closed and held off. */
    fun paymentScreenShown(id: PurchaseId)

    /** The payment screen of [id] was hidden: relay sessions stay held for U[20 min, 60 min]. */
    fun paymentScreenHidden(id: PurchaseId)
}
