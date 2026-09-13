package org.ghost.entitlement.engine

import org.ghost.entitlement.store.TokenRow
import org.ghost.network.EntitlementCrypto
import org.ghost.network.EntitlementCrypto.ScheduleSummary

/**
 * The grid of design §4.1: ISO weeks from Monday 1970-01-05 00:00 UTC (345 600 s), invite epochs of
 * 4 weeks, credit and price epochs of 13 weeks. Times are unix seconds.
 */
internal object Grid {
    const val WEEK_ORIGIN: Long = 345_600L
    const val WEEK: Long = 604_800L
    const val DAY: Long = 86_400L
    const val HOUR: Long = 3_600L
    const val MINUTE: Long = 60L
    private const val WEEKS_PER_INVITE_EPOCH = 4L
    private const val WEEKS_PER_CREDIT_EPOCH = 13L

    fun week(t: Long): Long = Math.floorDiv(t - WEEK_ORIGIN, WEEK)

    fun start(week: Long): Long = WEEK_ORIGIN + WEEK * week

    fun inviteEpoch(week: Long): Long = Math.floorDiv(week, WEEKS_PER_INVITE_EPOCH)

    fun creditEpoch(week: Long): Long = Math.floorDiv(week, WEEKS_PER_CREDIT_EPOCH)

    fun priceEpoch(week: Long): Long = creditEpoch(week)

    /** UTC day (days since 1970-01-01). */
    fun day(t: Long): Long = Math.floorDiv(t, DAY)
}

/** One position of a layout: the kind and epoch of its key and, for ACCESS, its ES slot. */
internal class Position(val kind: Int, val epoch: Long, val slot: Int?) {
    override fun toString(): String = "Position($kind, $epoch, $slot)"
}

/**
 * Layout order (design §4.2, §4.3): the (kind, epoch, slot) stored next to each issued token comes
 * from this order, which the Rust core uses for the same (base week, product) (§11.7). The layout
 * digest itself is native; the engine checks the count against the native answer.
 */
internal object Layouts {
    const val PACK_WEEKS = 5
    const val TRIAL_WEEKS = 2

    fun packProduct(xmr: Boolean): Int = if (xmr) EntitlementCrypto.PRODUCT_PACK_XMR else EntitlementCrypto.PRODUCT_PACK_CREDITS

    /** Weeks base..base+4 × slots × access_per_slot, then invites_per_pack INVITE positions, then one CREDIT if paid in XMR. */
    fun pack(s: ScheduleSummary, base: Long, xmr: Boolean): List<Position> {
        val out = ArrayList<Position>()
        for (w in base until base + PACK_WEEKS) {
            for (slot in s.slotsInWeek(w)) repeat(s.constants.accessPerSlot) { out += Position(EntitlementCrypto.KIND_ACCESS, w, slot) }
        }
        repeat(s.constants.invitesPerPack) { out += Position(EntitlementCrypto.KIND_INVITE, Grid.inviteEpoch(base), null) }
        if (xmr) out += Position(EntitlementCrypto.KIND_CREDIT, Grid.creditEpoch(base), null)
        return out
    }

    /** Weeks base..base+1 × slots × trial_per_slot ACCESS positions; no invite, no credit. */
    fun trial(s: ScheduleSummary, base: Long): List<Position> {
        val out = ArrayList<Position>()
        for (w in base until base + TRIAL_WEEKS) {
            for (slot in s.slotsInWeek(w)) repeat(s.constants.trialPerSlot) { out += Position(EntitlementCrypto.KIND_ACCESS, w, slot) }
        }
        return out
    }
}

/**
 * Prices and credit values from the schedule (design §4.6, §19.8): a credit is worth a tenth of the
 * price of its own epoch and is accepted in its epoch and the four following.
 */
internal object Pricing {
    const val MAX_DISCOUNT_CREDITS = 20
    private const val CREDIT_EPOCHS_ACCEPTED = 4L
    private const val CREDIT_SHARE = 10L

    fun price(s: ScheduleSummary, priceEpoch: Long): Long? = s.prices.firstOrNull { it.priceEpoch == priceEpoch }?.packPriceAtomic

    fun creditValue(s: ScheduleSummary, creditEpoch: Long): Long? = price(s, creditEpoch)?.let { it / CREDIT_SHARE }

    /** Credit epochs `c_now − 4 … c_now` of [nowWeek]. */
    fun accepted(creditEpoch: Long, nowWeek: Long): Boolean {
        val now = Grid.creditEpoch(nowWeek)
        return creditEpoch in (now - CREDIT_EPOCHS_ACCEPTED)..now
    }

    /**
     * The smallest set (at least `credits_per_free_pack`, at most 20) of accepted [credits] whose values
     * cover the price of [base]'s price epoch (§4.6, §19.8), highest values first and the older epoch
     * first among equal values, or null when none covers it.
     */
    fun coveringSet(s: ScheduleSummary, credits: List<TokenRow>, base: Long, nowWeek: Long): List<TokenRow>? {
        val target = price(s, Grid.priceEpoch(base)) ?: return null
        val usable = credits.filter { accepted(it.epoch, nowWeek) && creditValue(s, it.epoch) != null }
            .sortedWith(compareByDescending<TokenRow> { creditValue(s, it.epoch) }.thenBy { it.epoch })
        val chosen = ArrayList<TokenRow>()
        var sum = 0L
        for (credit in usable) {
            if (chosen.size >= s.constants.creditsPerFreePack && sum >= target) break
            chosen += credit
            sum += checkNotNull(creditValue(s, credit.epoch))
        }
        return chosen.takeIf { sum >= target && it.size >= s.constants.creditsPerFreePack && it.size <= MAX_DISCOUNT_CREDITS }
    }
}
