package org.ghost.media.store

/**
 * What the media stores refuse, as a typed error (Phase 11 design §13.1: "typed catches"; the Phase 10 precedent
 * `ChannelStoreException`): a value the schema would refuse (a size, a grid, a range), a transition the state machine of
 * §7.6 does not have, a row that is not there, a row that is, and a bound the schema keeps.
 *
 * The exception carries the error and the table (or table and column) and **never a value**: a row of the media tables
 * holds wrapped keys, object ids and hashes, and an exception message reaches a crash report (T3). Nothing here is caught
 * anywhere in `:media` (gate `sync-no-catch-all.sh`): a typed error is a defect of the caller, and it reaches the top
 * level like any other.
 */
class MediaStoreException(val error: MediaStoreError, val where: String) :
    IllegalStateException("${error.name} at $where")

enum class MediaStoreError {
    /** A size, a grid or a range the schema's CHECK would refuse; refused before the statement runs. */
    BAD_VALUE,

    /** A state change the machine of §7.6 does not have; the trigger would abort it too. */
    ILLEGAL_TRANSITION,

    /** A write that needs a row (an object to move, a fragment to settle) and found none. */
    MISSING_ROW,

    /** An insert of a key that exists; the `*_no_replace` guard would abort it too. */
    ROW_EXISTS,

    /** A bound of §6.4 or §13.6 (the retry generations, the resends, the decode failures). */
    LIMIT,
}

/**
 * The constants of the media object that the store needs (Phase 11 design §3.1, §3.6, §5.4, §6.4, §7.5, §13.6). The store
 * needs only these numbers, not the Rust crate that owns the format (slice S1): a class code is an index into [CLASSES],
 * a fragment is [FRAGMENT_BYTES] long, and the limits are the ones the schema's CHECKs carry.
 */
object MediaLimits {
    /** The relay blob size of every media blob and the size of every ciphertext file (the 64 KiB bucket, §3.1). */
    const val FRAGMENT_BYTES: Int = 65_536

    /** The fragment counts `F` of the eleven size classes; `class_code` is the index (§3.1). An object has `F + 1` blobs. */
    val CLASSES: IntArray = intArrayOf(16, 24, 36, 56, 84, 128, 192, 288, 432, 648, 804)

    /** The ordinal of the manifest blob (§13.6: "-1 = the manifest"); the fragments are `0 until F`. */
    const val MANIFEST_ORDINAL: Int = -1

    /** The last ordinal of the largest class (`F = 804`). */
    const val MAX_ORDINAL: Int = 803

    /** The TTL buckets in seconds (§5.4 R-MT1): 1 hour, 1 day, 7 days, 30 days. */
    val TTL_BUCKETS: Set<Long> = setOf(3_600L, 86_400L, 604_800L, 2_592_000L)

    /** User retries of a failed object (§6.4): `media_upload.retry_gen` is 0 to this. */
    const val MAX_RETRIES: Int = 3

    /** Phase 7 identical-bytes resends of one ordinal (§6.4): `media_outbound_op.resend_count` is 0 to this. */
    const val MAX_RESENDS: Int = 2

    /** Sandbox failures after which an object is undecodable (CS-M8). */
    const val MAX_DECODE_FAILURES: Int = 2

    /** Open ordinals per object and per device (§6.4 `MEDIA-FEED`). */
    const val OPEN_PER_OBJECT: Int = 32
    const val OPEN_PER_DEVICE: Int = 64

    /** Pooled (unmatched) bytes above which the pool evicts, by local deletion and never by fetching less (§7.5). */
    const val POOL_CAP_BYTES: Long = 512L * 1024 * 1024

    /** Free device storage below which ingest consumes a blob without writing a file (§7.5). */
    const val FREE_FLOOR_BYTES: Long = 256L * 1024 * 1024

    /** An unmatched blob lives at most this many days (§7.5: "at most eight days"). */
    const val POOL_MAX_DAYS: Long = 8L

    const val SECONDS_PER_HOUR: Long = 3_600L
    const val SECONDS_PER_DAY: Long = 86_400L

    /** The number of blobs of an object of class [classCode]: `F + 1` (the fragments and the manifest). */
    fun blobsOf(classCode: Int): Int {
        if (classCode !in CLASSES.indices) throw MediaStoreException(MediaStoreError.BAD_VALUE, "class_code")
        return CLASSES[classCode] + 1
    }

    /** The UTC day index of an instant, as the DM tables write `*_day` (`DmTime.day`). */
    fun day(seconds: Long): Long = Math.floorDiv(seconds, SECONDS_PER_DAY)
}

/**
 * The input checks every store applies before it writes. Each mirrors a CHECK of migration 8, so a caller's defect is a
 * [MediaStoreException] naming the column, not a bare "CHECK constraint failed" from the executor; the CHECK stays as the
 * backstop (a value that passes here and fails there is a defect of this file, and the constraint tests of `:media` compare
 * the two on the boundaries).
 */
internal object Fields {
    private fun bad(where: String): Nothing = throw MediaStoreException(MediaStoreError.BAD_VALUE, where)

    /** [value] must be exactly [size] bytes. */
    fun bytes(where: String, value: ByteArray, size: Int): ByteArray {
        if (value.size != size) bad(where)
        return value
    }

    fun bytesOrNull(where: String, value: ByteArray?, size: Int): ByteArray? = value?.let { bytes(where, it, size) }

    fun objectId(value: ByteArray): ByteArray = bytes("media_object.object_id", value, 16)

    fun hash(where: String, value: ByteArray): ByteArray = bytes(where, value, 32)

    /** A `*_hour` column: Unix seconds on an hour boundary (and `typeof` integer, which a `Long` is). */
    fun hour(where: String, value: Long): Long {
        if (value % MediaLimits.SECONDS_PER_HOUR != 0L) bad(where)
        return value
    }

    /** A `*_day` column: a day index, `>= 0`. */
    fun day(where: String, value: Long): Long {
        if (value < 0L) bad(where)
        return value
    }

    fun range(where: String, value: Long, min: Long, max: Long): Long {
        if (value < min || value > max) bad(where)
        return value
    }

    fun flag(value: Boolean): Long = if (value) 1L else 0L

    /** An ordinal: -1 for the manifest, 0 to 803 for a fragment. */
    fun ordinal(value: Int): Int {
        if (value < MediaLimits.MANIFEST_ORDINAL || value > MediaLimits.MAX_ORDINAL) bad("media_fragment.ordinal")
        return value
    }

    /** `?, ?, ?` for [n] bound values. */
    fun marks(n: Int): String = List(n) { "?" }.joinToString(", ")
}

/** Lower-case hex of [bytes]: the name of a ciphertext file on disk is the hex of the 16 random bytes of `media_blob.file_name`. */
internal fun hex(bytes: ByteArray): String {
    val digits = "0123456789abcdef"
    val out = StringBuilder(bytes.size * 2)
    for (b in bytes) {
        out.append(digits[(b.toInt() shr 4) and 0xF]).append(digits[b.toInt() and 0xF])
    }
    return out.toString()
}
