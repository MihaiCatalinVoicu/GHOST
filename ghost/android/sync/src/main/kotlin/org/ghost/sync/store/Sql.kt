package org.ghost.sync.store

import org.ghost.storage.SqlExecutor
import org.ghost.sync.api.BlobHash
import java.security.MessageDigest

/**
 * Time granularity helpers. Persisted times are minute (`*_minute`, multiple of 60), hour
 * (`*_hour`, multiple of 3600) or day (`*_day`) values only (design §2.1, T20). All inputs are unix
 * seconds.
 */
object Time {
    const val MINUTE: Long = 60
    const val HOUR: Long = 3_600
    const val DAY: Long = 86_400

    fun floorMinute(seconds: Long): Long = Math.floorDiv(seconds, MINUTE) * MINUTE

    fun ceilMinute(seconds: Long): Long = -Math.floorDiv(-seconds, MINUTE) * MINUTE

    fun floorHour(seconds: Long): Long = Math.floorDiv(seconds, HOUR) * HOUR

    fun ceilHour(seconds: Long): Long = -Math.floorDiv(-seconds, HOUR) * HOUR

    /** Epoch day of a unix time. */
    fun day(seconds: Long): Long = Math.floorDiv(seconds, DAY)

    /**
     * A due time `delaySeconds` from now at minute granularity: the current minute plus the delay
     * rounded up to whole minutes. It never exceeds `now + delaySeconds` rounded up to a minute and,
     * for delays that are whole minutes, never exceeds `now + delaySeconds` (clock clamp, §11.2 #4).
     */
    fun dueMinute(now: Long, delaySeconds: Long): Long = floorMinute(now) + ceilMinute(delaySeconds)
}

/** Shared SQL fragments and helpers of the stores (constants only; data is always bound). */
internal object Sql {
    /** A delivery that may still store or become verified: its op's payload must be kept (W, trigger). */
    const val LIVE_DELIVERY_D = "(d.state IN ('pending', 'wait_capability', 'acked') OR d.inflight = 1)"

    /** Clock clamp (§3.7, §11.2 #4): a retry time further than 61 minutes ahead is treated as due. */
    const val DUE_CLAMP_SECONDS: Long = 61 * 60

    /** Claim backoff clamp: a backoff further than 24 h ahead is treated as due (§11.2 #4). */
    const val OFFER_BACKOFF_CLAMP_SECONDS: Long = 24 * 3600

    /** Defer clamp: a deferral further than 7 days ahead is treated as due (§11.2 #4). */
    const val DEFER_CLAMP_SECONDS: Long = 7 * 86_400
}

/** Collects every row before returning, so no write ever runs while a device cursor is open. */
internal fun <T> SqlExecutor.rows(sql: String, args: List<Any?> = emptyList(), map: (SqlExecutor.Row) -> T): List<T> {
    val out = ArrayList<T>()
    query(sql, args) { out += map(it) }
    return out
}

/** One row or null; throws if the query returns more than one row. */
internal fun <T> SqlExecutor.single(sql: String, args: List<Any?> = emptyList(), map: (SqlExecutor.Row) -> T): T? {
    val all = rows(sql, args, map)
    check(all.size <= 1) { "expected at most one row" }
    return all.firstOrNull()
}

/** Runs a guarded statement that must change exactly [expected] rows. */
internal fun SqlExecutor.updateExactly(expected: Int, sql: String, args: List<Any?>) {
    val changed = execUpdate(sql, args)
    check(changed == expected) { "guarded sync update changed an unexpected number of rows" }
}

internal fun sha256(bytes: ByteArray): BlobHash = BlobHash(MessageDigest.getInstance("SHA-256").digest(bytes))

internal fun SqlExecutor.Row.int(index: Int): Int = Math.toIntExact(long(index))

internal fun SqlExecutor.Row.longOrNull(index: Int): Long? = if (isNull(index)) null else long(index)
