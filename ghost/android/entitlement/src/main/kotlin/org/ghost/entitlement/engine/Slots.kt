package org.ghost.entitlement.engine

import org.ghost.entitlement.port.EntitlementRandom
import org.ghost.sync.api.PrivacyMode
import org.ghost.sync.store.Time

/**
 * Activation slots (design §12.3, R4): a pack's tokens become eligible at
 * `floor_minute(first UTC-day boundary ≥ t_f + 4 h) + U[0, 6 h)`, plus Geometric(1/2) whole days in
 * HIGH mode; trial tokens at once in STANDARD mode and by the pack rule in HIGH mode. The draws are
 * client randomness only and are persisted in `eligible_minute` (R1).
 */
internal object Slots {
    private const val SLOT_DELAY: Long = 4 * Grid.HOUR
    private const val SPREAD: Long = 6 * Grid.HOUR
    private const val MAX_EXTRA_DAYS = 16

    fun packEligibleMinute(finalizedAt: Long, random: EntitlementRandom, mode: PrivacyMode): Long {
        val shifted = finalizedAt + SLOT_DELAY
        val boundary = -Math.floorDiv(-shifted, Grid.DAY) * Grid.DAY
        var extraDays = 0
        if (mode == PrivacyMode.HIGH) while (extraDays < MAX_EXTRA_DAYS && random.uniform() < 0.5) extraDays++
        val offset = minOf(SPREAD - 1, (random.uniform() * SPREAD).toLong())
        return Time.floorMinute(boundary + offset + extraDays * Grid.DAY)
    }

    fun trialEligibleMinute(finalizedAt: Long, random: EntitlementRandom, mode: PrivacyMode): Long =
        if (mode == PrivacyMode.STANDARD) Time.floorMinute(finalizedAt) else packEligibleMinute(finalizedAt, random, mode)
}
