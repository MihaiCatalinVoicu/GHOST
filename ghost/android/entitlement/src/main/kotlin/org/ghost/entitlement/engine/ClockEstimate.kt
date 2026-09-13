package org.ghost.entitlement.engine

import org.ghost.sync.api.RelayId

/**
 * The relay-facing clock (design §12.5, §19.4): `now_est = wall + δ`, δ the median of
 * `relay_minute − local_minute` over the latest answer of each of at least two distinct relays in
 * this process; before two relays answered, `now_est = wall`. A `WRONG_PERIOD` answer's
 * `relay_period_id` is adopted for that relay at once. In memory only, and never an input to an
 * issuer-facing decision (base week, issuer due times), which use the device wall clock under
 * `clockTrusted()` only.
 */
internal class ClockEstimate {
    private val offsetMinutes = HashMap<RelayId, Long>()
    private val adoptedPeriods = HashMap<RelayId, Long>()

    @Synchronized
    fun record(relay: RelayId, relayMinute: Long, relayPeriod: Long, localSeconds: Long, wrongPeriod: Boolean) {
        offsetMinutes[relay] = relayMinute - Math.floorDiv(localSeconds, Grid.MINUTE)
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

    /** The week of [relay]'s decisions: its adopted period, else the week of the estimate. */
    @Synchronized
    fun week(relay: RelayId, wall: Long): Long = adoptedPeriods[relay] ?: Grid.week(now(wall))

    override fun toString(): String = "ClockEstimate"

    private companion object {
        const val MIN_RELAYS = 2
    }
}
