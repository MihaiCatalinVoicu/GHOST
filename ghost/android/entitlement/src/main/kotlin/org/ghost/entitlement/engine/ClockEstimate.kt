package org.ghost.entitlement.engine

import org.ghost.sync.api.RelayId

/**
 * The relay-facing clock (design §12.5, §19.4): `now_est = wall + δ`, δ the median of
 * `relay_minute − local_minute` over the latest answer of each of at least two distinct relays in
 * this process; before two relays answered, `now_est = wall`. A `WRONG_PERIOD` answer's
 * `relay_period_id` is adopted for that relay at once. In memory only, and never an input to an
 * issuer-facing decision (base week, issuer due times), which use the device wall clock under
 * `clockTrusted()` only.
 *
 * Both are bounded by the early window of a week (24 h): each offset is clipped to ±24 h and a
 * period is adopted only when it is the week of a moment within 24 h of the wall clock. Relays that
 * lie about the time then move the redeem lane's week by at most one, so a token of a week after
 * `week(wall) + 1` is never spent: they cannot empty future weeks and so move the coverage end, which
 * drives the auto-renewal's `RequestInvoice` (a relay → issuer channel, §19.4).
 */
internal class ClockEstimate {
    private val offsetMinutes = HashMap<RelayId, Long>()
    private val adoptedPeriods = HashMap<RelayId, Long>()

    @Synchronized
    fun record(relay: RelayId, relayMinute: Long, relayPeriod: Long, localSeconds: Long, wrongPeriod: Boolean) {
        val local = Math.floorDiv(localSeconds, Grid.MINUTE)
        offsetMinutes[relay] = when {
            relayMinute >= local + MAX_SKEW_MINUTES -> MAX_SKEW_MINUTES
            relayMinute <= local - MAX_SKEW_MINUTES -> -MAX_SKEW_MINUTES
            else -> relayMinute - local
        }
        if (wrongPeriod) adoptedPeriods[relay] = relayPeriod else adoptedPeriods.remove(relay)
    }

    @Synchronized
    fun now(wall: Long): Long {
        if (offsetMinutes.size < MIN_RELAYS) return wall
        val sorted = offsetMinutes.values.sorted()
        val mid = sorted.size / 2
        val median = if (sorted.size % 2 == 1) sorted[mid] else Math.floorDiv(sorted[mid - 1] + sorted[mid], 2L)
        return wall + median * Grid.MINUTE
    }

    /** The week of [relay]'s decisions: its adopted period if within a day of [wall], else the week of the estimate. */
    @Synchronized
    fun week(relay: RelayId, wall: Long): Long {
        val adopted = adoptedPeriods[relay]
        return if (adopted != null && adopted in Grid.week(wall - MAX_SKEW)..Grid.week(wall + MAX_SKEW)) adopted else Grid.week(now(wall))
    }

    override fun toString(): String = "ClockEstimate"

    private companion object {
        const val MIN_RELAYS = 2

        /** The early window (design §3.4): an honest relay accepts a week's tokens from 24 h before it starts. */
        const val MAX_SKEW: Long = 24 * Grid.HOUR
        const val MAX_SKEW_MINUTES: Long = MAX_SKEW / Grid.MINUTE
    }
}
