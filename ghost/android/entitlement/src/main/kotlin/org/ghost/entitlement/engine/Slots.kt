package org.ghost.entitlement.engine

import org.ghost.entitlement.port.EntitlementRandom
import org.ghost.sync.api.PrivacyMode
import org.ghost.sync.store.Time

/**
 * Activation slots (design §12.3, R4): a pack's tokens become eligible at
 * `floor_minute(first UTC-day boundary ≥ t_f + 4 h) + U[0, 6 h)`, plus Geometric(1/2) whole days in
 * HIGH mode; trial tokens at once in STANDARD mode and by the pack rule in HIGH mode, with the extra
 * days capped at the trial's last week (Q30, §19.23 point 5). The draws are client randomness only
 * and are persisted in `eligible_minute` (R1).
 */
internal object Slots {
    private const val SLOT_DELAY: Long = 4 * Grid.HOUR
    private const val SPREAD: Long = 6 * Grid.HOUR
    private const val MAX_EXTRA_DAYS = 16

    fun packEligibleMinute(finalizedAt: Long, random: EntitlementRandom, mode: PrivacyMode): Long =
        slot(finalizedAt, random, mode, lastDay = null)

    /**
     * An onboarding trial of base week [baseWeek]: at once in STANDARD mode; in HIGH mode by the pack
     * rule, its extra days cut so that they reach at most the last day of the trial's last week
     * (`start(base + TRIAL_WEEKS) − 1 day`) and never fewer than none, so a HIGH-mode trial is always
     * usable (Q30). The draws are exactly the pack rule's; the cap applies after them, so it changes
     * no other draw. A trial finalized so late that its slot itself falls after that day keeps the
     * slot: the cap never moves eligibility earlier than the slot.
     */
    fun trialEligibleMinute(finalizedAt: Long, baseWeek: Long, random: EntitlementRandom, mode: PrivacyMode): Long =
        if (mode == PrivacyMode.STANDARD) {
            Time.floorMinute(finalizedAt)
        } else {
            slot(finalizedAt, random, mode, lastDay = Grid.start(baseWeek + Layouts.TRIAL_WEEKS) - Grid.DAY)
        }

    /** The pack rule; with [lastDay] the extra days reach at most the day starting then. */
    private fun slot(finalizedAt: Long, random: EntitlementRandom, mode: PrivacyMode, lastDay: Long?): Long {
        val shifted = finalizedAt + SLOT_DELAY
        val boundary = -Math.floorDiv(-shifted, Grid.DAY) * Grid.DAY
        var extraDays = 0L
        if (mode == PrivacyMode.HIGH) while (extraDays < MAX_EXTRA_DAYS && random.uniform() < 0.5) extraDays++
        val offset = minOf(SPREAD - 1, (random.uniform() * SPREAD).toLong())
        val days = if (lastDay == null) extraDays else extraDays.coerceAtMost(maxOf(0L, Math.floorDiv(lastDay - boundary, Grid.DAY)))
        return Time.floorMinute(boundary + offset + days * Grid.DAY)
    }
}
