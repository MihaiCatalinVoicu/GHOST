package org.ghost.entitlement.engine

import org.ghost.sync.api.RelayId

/**
 * The relay-facing clock (design §12.5, §19.4, §19.24 point 1): `now_est = wall + δ`, δ the median of
 * `relay_minute − local_minute` over the latest answer of each of at least two distinct relays in
 * this process; before two relays answered, `now_est = wall`. A `WRONG_PERIOD` answer's
 * `relay_period_id` is adopted for that relay at once. In memory only, and never an input to an
 * issuer-facing decision (base week, issuer due times), which use the device wall clock under
 * `clockTrusted()` only.
 *
 * The decisions about one relay (the redeem lane's week, the ±1 h guard, the renewal lead, the retry
 * of a kept reservation) run on that relay's own time, `wall + δ_relay`, once it answered in this
 * process ([relayNow]): an adopted period is then always read on the clock of the relay that set it,
 * so a device running up to a day off meets each relay at most once with a refused period. A relay's
 * answer moves the decisions about that relay only; the others keep the median.
 *
 * Both are bounded by the early window of a week (24 h): each offset is clipped to ±24 h and a
 * period is adopted only when it is the week of a moment within 24 h of the wall clock. Relays that
 * lie about the time then move the redeem lane's week by at most one, so a token of a week after
 * `week(wall) + 1` is never spent: they cannot empty future weeks and so move the coverage end, which
 * drives the auto-renewal's `RequestInvoice` (a relay → issuer channel, §19.4).
 *
 * Offsets are taken against the device wall clock, so a device clock change makes them stale:
 * [observe] forgets every offset and adoption once `wall − monotonic` moved by [CLOCK_JUMP_MILLIS] or
 * more since the last observation (the device clock was set), and the process starts over from the
 * wall clock.
 */
internal class ClockEstimate {
    private val offsetMinutes = HashMap<RelayId, Long>()
    private val adoptedPeriods = HashMap<RelayId, Long>()

    /** `wall − monotonic` in milliseconds at the last [observe]. */
    private var basisMillis: Long? = null

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

    /** Forgets the estimate when the device clock was set since the last observation. */
    @Synchronized
    fun observe(wall: Long, monotonicMillis: Long) {
        val basis = wall * 1000 - monotonicMillis
        val last = basisMillis
        if (last != null && Math.abs(basis - last) >= CLOCK_JUMP_MILLIS) {
            offsetMinutes.clear()
            adoptedPeriods.clear()
        }
        basisMillis = basis
    }

    @Synchronized
    fun now(wall: Long): Long {
        if (offsetMinutes.size < MIN_RELAYS) return wall
        val sorted = offsetMinutes.values.sorted()
        val mid = sorted.size / 2
        val median = if (sorted.size % 2 == 1) sorted[mid] else Math.floorDiv(sorted[mid - 1] + sorted[mid], 2L)
        return wall + median * Grid.MINUTE
    }

    /** The time of [relay]'s decisions: its own clock once it answered in this process, else [now]. */
    @Synchronized
    fun relayNow(relay: RelayId, wall: Long): Long {
        val own = offsetMinutes[relay] ?: return now(wall)
        return wall + own * Grid.MINUTE
    }

    /**
     * The week of [relay]'s decisions: its adopted period while that is within a day of [wall] (never
     * behind the relay's own clock), else the week of [relayNow].
     */
    @Synchronized
    fun week(relay: RelayId, wall: Long): Long {
        val own = Grid.week(relayNow(relay, wall))
        val adopted = adoptedPeriods[relay]
        return if (adopted != null && adopted in Grid.week(wall - MAX_SKEW)..Grid.week(wall + MAX_SKEW)) maxOf(adopted, own) else own
    }

    override fun toString(): String = "ClockEstimate"

    companion object {
        private const val MIN_RELAYS = 2

        /** The early window (design §3.4): an honest relay accepts a week's tokens from 24 h before it starts. */
        private const val MAX_SKEW: Long = 24 * Grid.HOUR
        private const val MAX_SKEW_MINUTES: Long = MAX_SKEW / Grid.MINUTE

        /** A move of `wall − monotonic` this large is a device clock change, not jitter or slewing. */
        const val CLOCK_JUMP_MILLIS: Long = 120_000L
    }
}
