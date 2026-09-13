package org.ghost.entitlement.engine

import org.ghost.entitlement.api.PayWith
import org.ghost.entitlement.port.IssuerPort
import org.ghost.entitlement.store.PurchaseRow
import org.ghost.entitlement.store.PurchaseStore
import org.ghost.sync.api.SyncTransaction

/**
 * Quiet-run work (design §11.6, §12.2, §19.14): **at most one issuer call per quiet run** (J9), the
 * most overdue of a purchase step (`RequestInvoice` or a planned `BlindSign`), an auto-renewal (if
 * enabled, coverage ends within 2 weeks and own fresh credits cover the price), a due claim, a due
 * `RefreshCredit` and an invite revocation. Which runs are quiet is not decided here: the sync
 * runtime's `QuietRunScheduler` draws it from client randomness alone, with no entitlement input.
 * The renewal trigger reads the last week held against the device clock; relays cannot move it, since
 * the redeem lane never spends a token of a week after `week(wall) + 1` (the bounded relay-facing
 * clock, [ClockEstimate]) and renewal is due anyway once coverage ends by then.
 */
internal class QuietRunWork(private val c: EngineContext) {

    sealed class Item(val due: Long) {
        class Request(val id: ByteArray, due: Long) : Item(due)
        class Sign(val id: ByteArray, due: Long) : Item(due)
        class Refresh(val id: ByteArray, due: Long) : Item(due)
        class Revocation(val id: ByteArray, due: Long) : Item(due)
        class Claim(val id: ByteArray, due: Long) : Item(due)
        class Renewal(due: Long) : Item(due)

        override fun toString(): String = javaClass.simpleName
    }

    /** The items due at [now], most overdue first. */
    fun due(now: Long): List<Item> = c.tx { tx -> collect(tx, now) }.filter { it.due <= now }.sortedBy { it.due }

    /** Runs the most overdue item (one issuer call at most); returns it, or null when nothing was due. */
    fun run(issuer: IssuerPort, now: Long): Item? {
        val item = pick(c.tx { tx -> collect(tx, now) }, now) ?: return null
        when (item) {
            is Item.Request -> c.purchaseSteps.requestInvoice(issuer, item.id, now)
            is Item.Sign -> c.purchaseSteps.blindSign(issuer, item.id, now)
            is Item.Refresh -> c.purchaseSteps.refresh(issuer, item.id, now)
            is Item.Revocation -> c.trialSteps.redeem(issuer, item.id, now, trusted = true)
            is Item.Claim -> c.claimSteps.step(issuer, item.id, now)
            is Item.Renewal -> c.purchaseSteps.start(PayWith.CREDITS, now, delayed = false)?.let {
                c.purchaseSteps.requestInvoice(issuer, it.toByteArray(), now)
            }
        }
        return item
    }

    private fun collect(tx: SyncTransaction, now: Long): List<Item> {
        val items = ArrayList<Item>()
        val live = c.purchases.live(tx)
        for (p in live) {
            if (c.memory.inFlight(p.id())) continue
            when {
                p.kind == PurchaseStore.PACK && p.state == PurchaseStore.PREPARED -> items += Item.Request(p.id(), p.nextDueMinute ?: (p.createdHour ?: 0L))
                p.kind == PurchaseStore.PACK && p.state == PurchaseStore.INVOICED && p.attempt < RetryPolicy.BLIND_SIGN_ATTEMPTS ->
                    items += Item.Sign(p.id(), p.nextDueMinute ?: 0L)
                p.kind == PurchaseStore.REFRESH && p.state == PurchaseStore.PREPARED -> items += Item.Refresh(p.id(), p.nextDueMinute ?: 0L)
                p.kind == PurchaseStore.TRIAL && p.state == PurchaseStore.PREPARED && p.nextDueMinute != null -> items += Item.Revocation(p.id(), p.nextDueMinute)
            }
        }
        c.claims.open(tx)?.let { claim -> if (!c.memory.inFlight(claim.claimId())) items += Item.Claim(claim.claimId(), checkNotNull(claim.nextDueMinute)) }
        if (renewalDue(tx, now, live)) items += Item.Renewal(now)
        return items
    }

    private fun renewalDue(tx: SyncTransaction, now: Long, live: List<PurchaseRow>): Boolean {
        val st = c.state.read(tx) ?: return false
        if (!st.autoRenewCredits || live.any { it.kind == PurchaseStore.PACK } || !c.purchasable(now)) return false
        val week = Grid.week(now)
        val last = c.tokens.lastAccessWeek(tx)
        if (last != null && last - week >= RENEW_WITHIN_WEEKS) return false
        return Pricing.coveringSet(c.summary, c.tokens.freshCredits(tx), week, week) != null
    }

    override fun toString(): String = "QuietRunWork"

    companion object {
        private const val RENEW_WITHIN_WEEKS = 2L

        /**
         * The one item a quiet run serves (J9): the most overdue of the items due at [now], ties in the
         * order of [items] (purchases by id, then the claim, then the renewal). Pinned by
         * `entitlement_policy.txt` (`work`).
         */
        fun pick(items: List<Item>, now: Long): Item? = items.filter { it.due <= now }.minByOrNull { it.due }
    }
}
