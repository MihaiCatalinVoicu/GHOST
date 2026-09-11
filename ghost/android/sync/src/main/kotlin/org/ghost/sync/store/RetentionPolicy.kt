package org.ghost.sync.store

/**
 * Retention constants and derivations (design §2.3, §11.2 #6 and #8). Every `retain_until_day`
 * written by the stores comes from this object and is rounded up to a 7-day boundary ([ceil7]); the
 * schema refuses any other value.
 *
 * Derivation summary: all copies of one op are stored within the store window H after its first
 * possible copy (W-rule), so every membership of a received hash expires before `E + H + 5σ + 2 h`
 * (E = the relay expiry returned by `get`), about E + 22.1 d; TAIL = 24 d. A hash listed at t but
 * never fetched expires before `t + H + TTL_max + 4σ + 2 h`, about t + 109.1 d; LISTED_RETAIN = 111 d.
 * An own blob can no longer be stored once its op row is gone, so its tombstone needs TTL + 8 d.
 */
object RetentionPolicy {
    /** H: stores of one op happen within 7 days of its first possible copy. */
    const val STORE_WINDOW_SECONDS: Long = 7 * Time.DAY

    /** σ: tolerated clock skew of the device and honest relays while the transport is READY. */
    const val SKEW_SECONDS: Long = 3 * Time.DAY

    const val TAIL_DAYS: Long = 24
    const val LISTED_RETAIN_DAYS: Long = 111
    const val OWN_EXTRA_DAYS: Long = 8

    /** Retired relay rows are deleted after this many days once nothing refers to them. */
    const val RETIRED_RELAY_DAYS: Long = LISTED_RETAIN_DAYS

    /** Capabilities are deleted one day after their (floored) expiry hour. */
    const val CAPABILITY_GRACE_SECONDS: Long = Time.DAY

    /** At most this many inbox rows are deleted per GC pass. */
    const val GC_BATCH: Int = 500

    /** Rounds an epoch day up to the next multiple of 7 (the schema CHECK). */
    fun ceil7(day: Long): Long = -Math.floorDiv(-day, 7L) * 7L

    /** Own blob, while its op exists and when the op row is deleted: `ceil7(today + TTL days + 8)`. */
    fun ownRetainDay(nowEpochSeconds: Long, ttlSeconds: Long): Long =
        ceil7(Time.day(nowEpochSeconds) + ttlSeconds / Time.DAY + OWN_EXTRA_DAYS)

    /** Listed or unavailable row: `ceil7(last listing day + 111)`. */
    fun listedRetainDay(nowEpochSeconds: Long): Long = ceil7(Time.day(nowEpochSeconds) + LISTED_RETAIN_DAYS)

    /** Fetched blob, and own blob on every receipt: `ceil7(day(relay expiry) + 24)`. */
    fun expiryRetainDay(expiryEpochSeconds: Long): Long = ceil7(Time.day(expiryEpochSeconds) + TAIL_DAYS)

    /**
     * Identical bytes whose own tombstone retains until [retainUntilDay] may be enqueued again only
     * while `now < retain_until_day − TAIL` (§11.2 #6): recipients still hold their tombstones for
     * every copy the new op can make.
     */
    fun resendAllowed(retainUntilDay: Long, nowEpochSeconds: Long): Boolean =
        nowEpochSeconds < (retainUntilDay - TAIL_DAYS) * Time.DAY

    /** Latest time identical bytes of an INDETERMINATE op may be resent: earliest copy hour + TTL − σ. */
    fun resendNotAfter(earliestCopyHour: Long, ttlSeconds: Long): Long = earliestCopyHour + ttlSeconds - SKEW_SECONDS

    /** Rows whose retention day is strictly before today may be deleted. */
    fun expired(retainUntilDay: Long, nowEpochSeconds: Long): Boolean = retainUntilDay < Time.day(nowEpochSeconds)
}
