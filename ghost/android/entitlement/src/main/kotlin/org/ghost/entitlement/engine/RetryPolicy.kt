package org.ghost.entitlement.engine

import org.ghost.identity.Hkdf
import org.ghost.sync.store.Time
import java.nio.ByteBuffer

/** What a failed call means to its flow (design §5.7; categories of `client-core/README.md`). */
internal enum class Failure {
    /** `transport`, `timeout`, `relay_unavailable`, `closed`, `quota`, `tor_*` and anything unknown: an identical retry later. */
    TRANSIENT,

    /** `unauthorized` (`PERMISSION_DENIED`). */
    UNAUTHORIZED,

    /** `rejected`, `invalid_argument` (refused before any I/O), or an argument refused in Kotlin. */
    REJECTED,

    /** `malformed_response`: one identical retry, then `failed` + `ISSUER_MISMATCH`. */
    MALFORMED,
}

/**
 * Attempt caps and the fixed `BlindSign` plan (design §19.11, Q22). Per invoice at most 5 attempts:
 * three planned at receipt + U[3 h, 5 h], U[44 h, 52 h], U[100 h, 112 h], then two slow ones at
 * U[7 d, 8 d] and U[20 d, 22 d]; then `lost`. The draw of attempt k is
 * `HKDF-SHA256(ikm = seed, salt = none, info = "ghost/v1/attempt" ‖ u8(k), L = 8)`, its top 53 bits a
 * fraction of the window, so no column is needed and a restart keeps the times; the due minute is
 * rounded up (never earlier than the draw). No issuer answer changes a due time.
 */
internal object RetryPolicy {
    const val BLIND_SIGN_ATTEMPTS = 5
    const val REQUEST_ATTEMPTS = 40
    const val FLOW_ATTEMPTS = 40
    const val CLAIM_ATTEMPTS = 20

    private const val H = Grid.HOUR
    private const val D = Grid.DAY
    private val WINDOWS: List<Pair<Long, Long>> = listOf(3 * H to 5 * H, 44 * H to 52 * H, 100 * H to 112 * H, 7 * D to 8 * D, 20 * D to 22 * D)
    private val ATTEMPT_LABEL = "ghost/v1/attempt".toByteArray(Charsets.US_ASCII)
    private const val TWO_POW_MINUS_53: Double = 1.0 / (1L shl 53)

    /** The due minute of `BlindSign` attempt [k] (0-based) of the invoice received at [receiptMinute]. */
    fun blindSignDueMinute(seed: ByteArray, receiptMinute: Long, k: Int): Long {
        require(k in 0 until BLIND_SIGN_ATTEMPTS) { "attempt out of range" }
        val (lo, hi) = WINDOWS[k]
        val okm = Hkdf.derive(ikm = seed, salt = null, info = ATTEMPT_LABEL + byteArrayOf(k.toByte()), length = 8)
        val u = (ByteBuffer.wrap(okm).long ushr 11) * TWO_POW_MINUS_53
        return Time.ceilMinute(receiptMinute + lo + (u * (hi - lo)).toLong())
    }

    fun classify(category: String): Failure = when (category) {
        "unauthorized" -> Failure.UNAUTHORIZED
        "rejected", "invalid_argument", "not_onion" -> Failure.REJECTED
        "malformed_response" -> Failure.MALFORMED
        else -> Failure.TRANSIENT
    }
}
