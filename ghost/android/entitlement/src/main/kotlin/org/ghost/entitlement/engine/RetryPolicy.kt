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
 * Attempt caps and pre-drawn due times (design §19.11, Q22, E5, E8, E17). No issuer answer ever adds
 * an attempt or moves a due time, so a stalling or lying issuer gets no more linked samples than the
 * caps below:
 *  - `BlindSign`: per invoice at most 5 attempts, three planned at receipt + U[3 h, 5 h],
 *    U[44 h, 52 h], U[100 h, 112 h], then two slow ones at U[7 d, 8 d] and U[20 d, 22 d]; then `lost`.
 *    The draw of attempt k is `HKDF-SHA256(ikm = seed, salt = none, info = "ghost/v1/attempt" ‖ u8(k),
 *    L = 8)`, its top 53 bits a fraction of the window, so no column is needed and a restart keeps the
 *    times; the due minute is rounded up (never earlier than the draw).
 *  - `RequestInvoice`, `RefreshCredit`, `ClaimPayout` and a revocation: the planned attempt and at most
 *    one identical retry (the retry an ambiguous send needs, §11.5), due U[20 h, 28 h] after the first
 *    attempt left, drawn and written ahead with it; then the flow fails. A pack whose invoice came on
 *    the retry starts its `BlindSign` plan at the second window, so a purchase makes at most 6 linked
 *    issuer calls whatever the issuer answers (E5).
 *  - An onboarding trial: retried at each foreground, the user present (§8.3, a declared L3 sample),
 *    at most [ONBOARDING_ATTEMPTS] times.
 * A `WRONG_PERIOD` re-prepare (§5.3, §8.3) is the flow's retry, not a new flow: the new row keeps the
 * invite token or presents the same credits, so it inherits the attempt count and the pre-drawn retry
 * time (`PurchaseSteps.rePrepare`), and a flow whose cap is spent fails instead.
 */
internal object RetryPolicy {
    const val BLIND_SIGN_ATTEMPTS = 5
    const val CALL_ATTEMPTS = 2
    const val ONBOARDING_ATTEMPTS = 40

    private const val H = Grid.HOUR
    private const val D = Grid.DAY
    private val WINDOWS: List<Pair<Long, Long>> = listOf(3 * H to 5 * H, 44 * H to 52 * H, 100 * H to 112 * H, 7 * D to 8 * D, 20 * D to 22 * D)
    private val ATTEMPT_LABEL = "ghost/v1/attempt".toByteArray(Charsets.US_ASCII)
    private const val TWO_POW_MINUS_53: Double = 1.0 / (1L shl 53)
    private const val RETRY_MIN: Long = 20 * H
    private const val RETRY_SPAN: Long = 8 * H

    /**
     * The due minute written ahead of attempt [attempt] (0-based) of a capped call sent at [now]: at the
     * first send the one retry's time, U[20 h, 28 h] later from [uniform]; afterwards [current], unchanged.
     */
    fun nextDueAfterSend(attempt: Int, current: Long?, now: Long, uniform: () -> Double): Long? =
        if (attempt == 0) Time.ceilMinute(now + RETRY_MIN + (uniform() * RETRY_SPAN).toLong()) else current

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
