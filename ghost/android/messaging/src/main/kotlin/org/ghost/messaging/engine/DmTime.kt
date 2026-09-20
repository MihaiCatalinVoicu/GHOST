package org.ghost.messaging.engine

/**
 * The time grid the DM tables are written on (Phase 9 design §13.6 "Step 5", R-M3).
 *
 * Every time column of the `dm_*` and `olm_*` tables is one of three shapes, each with a `typeof`
 * CHECK the schema enforces: `*_minute` (unix seconds, `% 60 = 0`), `*_hour` (`% 3600 = 0`) and
 * `*_day` (a day index). Period indices — `bundle_week`, `period_id` — are ISO weeks on the same
 * origin Phase 8 uses, Monday 1970-01-05 00:00 UTC, because a registration's period and a
 * capability's week are compared against each other at the relay (§4.4 point 3) and a second
 * origin would put them one week apart forever.
 *
 * Rounding is **floor** for a stored instant and **ceil** for a deadline, which is the rule the
 * schema's CHECKs and §10.3's "expiry times only move earlier" assume. `Math.floorDiv` is used
 * throughout so a negative instant (a clock set before 1970 in a test world) rounds down rather
 * than towards zero.
 */
internal object DmTime {

    /** Monday 1970-01-05 00:00 UTC: ISO week 0, the Phase 8 grid origin (`Grid.WEEK_ORIGIN`). */
    const val WEEK_ORIGIN: Long = 345_600L

    const val MINUTE: Long = 60L
    const val HOUR: Long = 3_600L
    const val DAY: Long = 86_400L
    const val WEEK: Long = 604_800L

    /** The ISO week index of an instant. */
    fun week(seconds: Long): Long = Math.floorDiv(seconds - WEEK_ORIGIN, WEEK)

    /** The first instant of an ISO week. */
    fun weekStart(week: Long): Long = WEEK_ORIGIN + WEEK * week

    /** The UTC day index of an instant (days since 1970-01-01). */
    fun day(seconds: Long): Long = Math.floorDiv(seconds, DAY)

    fun floorMinute(seconds: Long): Long = Math.floorDiv(seconds, MINUTE) * MINUTE

    fun ceilMinute(seconds: Long): Long = -Math.floorDiv(-seconds, MINUTE) * MINUTE

    fun floorHour(seconds: Long): Long = Math.floorDiv(seconds, HOUR) * HOUR

    fun ceilHour(seconds: Long): Long = -Math.floorDiv(-seconds, HOUR) * HOUR
}
