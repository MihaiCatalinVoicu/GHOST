package org.ghost.messaging.channel.store

/**
 * What the channel stores refuse, as a typed error (Phase 10 design §10.1: "typed errors"): a value the schema
 * would refuse (a size, a grid, a range), a transition the state machine does not have, a row that is not
 * there, a row that is, and a bound the schema keeps.
 *
 * The exception carries the error and the table (or table and column) and **never a value**: a row of the
 * channel tables holds keys, pseudonyms and user text, and an exception message reaches a crash report
 * (T3). Nothing here is caught anywhere in `:messaging` (gate `sync-no-catch-all.sh`): a typed error is a
 * defect of the caller, and it reaches the top level like any other.
 */
internal class ChannelStoreException(val error: ChannelStoreError, val where: String) :
    IllegalStateException("${error.name} at $where")

internal enum class ChannelStoreError {
    /** A size, a grid or a range the schema's CHECK would refuse; refused before the statement runs. */
    BAD_VALUE,

    /** A state change the machine of §6.11 does not have; the trigger would abort it too. */
    ILLEGAL_TRANSITION,

    /** A write that needs a row (a counter to bump, an epoch to finalize) and found none. */
    MISSING_ROW,

    /** An insert of a key that exists; the `*_no_replace` guard would abort it too. */
    ROW_EXISTS,

    /** A bound of §6.3.5 or §9 (the schema's trigger would abort the insert). */
    LIMIT,
}

/**
 * The input checks every store applies before it writes. Each mirrors a CHECK of migration 7, so a caller's
 * defect is a [ChannelStoreException] naming the column, not a bare "CHECK constraint failed" from the
 * executor; the CHECK stays as the backstop (a value that passes here and fails there is a defect of this
 * file, and `ChannelStateMachinesTest` compares the two on the boundaries).
 */
internal object Fields {
    const val MINUTE: Long = 60L
    const val HOUR: Long = 3_600L
    const val WEEK_DAYS: Long = 7L
    const val U32_MAX: Long = 4_294_967_295L

    private fun bad(where: String): Nothing = throw ChannelStoreException(ChannelStoreError.BAD_VALUE, where)

    /** [value] must be exactly [size] bytes. */
    fun bytes(where: String, value: ByteArray, size: Int): ByteArray {
        if (value.size != size) bad(where)
        return value
    }

    /** [value] must be [min] to [max] bytes. */
    fun bytesBetween(where: String, value: ByteArray, min: Int, max: Int): ByteArray {
        if (value.size < min || value.size > max) bad(where)
        return value
    }

    /** A floor-sized bucket of §5.6: exactly one of 4 KiB, 16 KiB or 64 KiB (the schema's CHECK is the backstop). */
    fun bucket(where: String, value: ByteArray): ByteArray {
        if (value.size != 4_096 && value.size != 16_384 && value.size != 65_536) bad(where)
        return value
    }

    fun bytesOrNull(where: String, value: ByteArray?, size: Int): ByteArray? = value?.let { bytes(where, it, size) }

    fun bytesBetweenOrNull(where: String, value: ByteArray?, min: Int, max: Int): ByteArray? =
        value?.let { bytesBetween(where, it, min, max) }

    /** A `*_minute` column: Unix seconds on a minute boundary. */
    fun minute(where: String, value: Long): Long {
        if (value % MINUTE != 0L) bad(where)
        return value
    }

    /** A `*_hour` column: Unix seconds on an hour boundary. */
    fun hour(where: String, value: Long): Long {
        if (value % HOUR != 0L) bad(where)
        return value
    }

    /** A `*_day` column, or an epoch or another counter that is `>= 0`. */
    fun nonNegative(where: String, value: Long): Long {
        if (value < 0L) bad(where)
        return value
    }

    /**
     * A weekly `*_day` column, `until_day % 7 = 0` and `>= 0` (`ch_seen.until_day`, the `ceil7` of F9 §7.6 D3): a
     * seizer learns the week and not the day.
     */
    fun week(where: String, value: Long): Long {
        if (value < 0L || value % WEEK_DAYS != 0L) bad(where)
        return value
    }

    fun minuteOrNull(where: String, value: Long?): Long? = value?.let { minute(where, it) }
    fun hourOrNull(where: String, value: Long?): Long? = value?.let { hour(where, it) }
    fun nonNegativeOrNull(where: String, value: Long?): Long? = value?.let { nonNegative(where, it) }

    /** A `u32`: a generation, a sequence number. */
    fun u32(where: String, value: Long): Long {
        if (value < 0L || value > U32_MAX) bad(where)
        return value
    }

    fun range(where: String, value: Long, min: Long, max: Long): Long {
        if (value < min || value > max) bad(where)
        return value
    }

    fun rangeInt(where: String, value: Int, min: Int, max: Int): Int {
        if (value < min || value > max) bad(where)
        return value
    }

    fun flag(value: Boolean): Long = if (value) 1L else 0L
}
