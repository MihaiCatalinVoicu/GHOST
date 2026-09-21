package org.ghost.messaging.engine

import org.ghost.sync.api.TtlBucket

/**
 * The timer, TTL and freshness arithmetic of Phase 9 design §10.1 and §21.10, as far as **sending
 * and receiving** need it.
 *
 * **Scope, declared.** §17.1 gives the ephemeral slice (S9) the countdowns, the SWEEP cascade, the
 * checkpoint, the alarm and the T25 suites. What S7 cannot defer is the part every store and every
 * accepted message already depends on: a DM op cannot be enqueued without a TTL bucket and a
 * deadline (R-T1 … R-T4), an outgoing row cannot be inserted without `expire_at_minute` and an
 * incoming one without `unread_deadline_minute` (the `dm_message` CHECKs make both mandatory when
 * the timer is not off), and `RECV` R9 cannot decide freshness without `FRESH(bucket)`. This
 * object is that part and no more: it computes, it never deletes.
 *
 * Every value is a **minute** or an **hour** on the grid of [DmTime]; nothing here carries
 * seconds (T13).
 */
internal object DmTimers {

    /** The timer codes of §7.1: 0 off, 1 = 5 min, 2 = 1 h, 3 = 1 d, 4 = 7 d, 5 = 30 d. */
    const val TIMER_OFF: Int = 0

    /** The default conversation timer, which the schema also defaults `timer_code` to. */
    const val TIMER_DEFAULT: Int = 4

    /** The largest timer code §7.1 defines. */
    const val TIMER_MAX: Int = 5

    /** σ, the Phase 7 per-device clock tolerance (§7.6). */
    const val SIGMA_SECONDS: Long = 3 * DmTime.DAY

    /** The store window every DM op's deadline is capped at (§10.1 R-T4). */
    const val DEADLINE_CAP_SECONDS: Long = 7 * DmTime.DAY

    /** `FRESH` for the two longest buckets, and the horizon every other window is derived from. */
    const val FRESH_SECONDS: Long = 45 * DmTime.DAY

    /**
     * The relay TTL of a timer code — ADR-27 point 11 exactly (§10.1 R-T1): the smallest bucket at
     * or above the timer, and 30 days when the timer is off, which is the DM store-and-forward
     * horizon. 5 minutes shares the 1-hour bucket, which is the one case "TTL ≤ timer" cannot
     * hold and which erratum X-16 reads as ADR-27.
     */
    fun bucketOf(timerCode: Int): TtlBucket = when (timerCode) {
        TIMER_OFF -> TtlBucket.DAYS_30
        1, 2 -> TtlBucket.HOUR_1
        3 -> TtlBucket.DAY_1
        4 -> TtlBucket.DAYS_7
        5 -> TtlBucket.DAYS_30
        else -> throw IllegalArgumentException("timer code out of range")
    }

    /**
     * R-T3: a TIMER_SET uses the **larger** of the old and the new bucket, so a change from 7 days
     * to 1 hour still reaches a recipient who was offline for more than an hour.
     */
    fun timerSetBucket(oldCode: Int, newCode: Int): TtlBucket {
        val old = bucketOf(oldCode)
        val new = bucketOf(newCode)
        return if (old.seconds >= new.seconds) old else new
    }

    /**
     * R-T4 (§10.1, SC-3): `deadline = author + min(bucket, 7 d)`.
     *
     * The 7-day cap is the Phase 7 store window, and it is what makes `FRESH = 45 d` hold for a
     * parked op as well as a prompt one (§7.6's derivation). A 5-minute message gets the 1-hour
     * deadline, so NI-DM4 compares equal inputs and a HIGH send delay of up to 10 minutes cannot
     * outlive it (§21.10 point 1).
     */
    fun deadlineSeconds(authorMinute: Long, bucket: TtlBucket): Long =
        authorMinute + minOf(bucket.seconds.toLong(), DEADLINE_CAP_SECONDS)

    /**
     * `FRESH(b) = min(b, 7 d) + b + 2 h + 2σ` (§21.10 point 3), which R-C9's table gives as
     * 1 h → 6 d 4 h, 1 d → 8 d 2 h, 7 d → 20 d 2 h, and 30 d (and off) → 43 d 2 h, kept at 45 d.
     *
     * A per-bucket freshness is what keeps a replay of a one-hour message from being accepted for
     * six weeks; the 45-day horizon stays for the pair-key window, the generation retention and
     * binding v3, which are not per-message.
     */
    fun freshSeconds(bucket: TtlBucket): Long {
        val b = bucket.seconds.toLong()
        val derived = minOf(b, DEADLINE_CAP_SECONDS) + b + 2 * DmTime.HOUR + 2 * SIGMA_SECONDS
        return minOf(derived, FRESH_SECONDS)
    }

    /**
     * D3's tag lifetime (§7.6, §21.10 point 3):
     * `until_day = ceil7(day(author_minute) + ceil_days(FRESH(b)) + 1)`.
     *
     * The `ceil7` is the schema's: `dm_seen.until_day` carries `% 7 = 0`, which is how a tag's day
     * says nothing finer than a week about when the message was authored (T33).
     */
    fun seenUntilDay(authorMinute: Long, bucket: TtlBucket): Long {
        val freshDays = ceilDiv(freshSeconds(bucket), DmTime.DAY)
        val day = DmTime.day(authorMinute) + freshDays + 1
        return ceil7(day)
    }

    /**
     * §10.3: the sender's countdown starts at the SEND commit —
     * `expire_at_minute = ceil_minute(commit + timer)` — and is null when the timer is off.
     */
    fun senderExpireMinute(commitSeconds: Long, timerCode: Int): Long? =
        if (timerCode == TIMER_OFF) null else DmTime.ceilMinute(commitSeconds + timerSeconds(timerCode))

    /**
     * §10.3 and C-11: an unread incoming message is deleted at
     * `min(relay expiry E, consume + bucket + 1 h)`.
     *
     * `E` is what the serving relay returned at `get` (`InboundBlob.relayExpiryHour`), already
     * validated in Rust. A relay lying **short** can only make deletion earlier, which is a denial
     * of service it could cause by withholding anyway; a relay lying **long** is clamped by the
     * second term. A content-derived deadline (`author + bucket`) is refused outright: a sender
     * whose clock runs ahead would extend it (mutant ME-19).
     */
    fun unreadDeadlineMinute(
        consumeSeconds: Long,
        relayExpiryHour: Long,
        timerCode: Int,
    ): Long? {
        if (timerCode == TIMER_OFF) return null
        val cap = consumeSeconds + bucketOf(timerCode).seconds.toLong() + DmTime.HOUR
        return DmTime.ceilMinute(minOf(relayExpiryHour, cap))
    }

    /**
     * §8.3: how long a held ciphertext lives —
     * `hold_until_minute = ceil_minute(min(relayExpiryHour, consume + 30 d + 1 h))`.
     *
     * The message's own timer is **unknown until it decrypts**, so the longest DM bucket bounds
     * the hold; the relay expiry caps it, for the reason it caps an unread message's deadline
     * (C-11, [unreadDeadlineMinute]). A `changed` state never resolves itself — the held rows go at
     * this minute and the state stays until the user acts (declared, L7-D17).
     */
    fun holdUntilMinute(consumeSeconds: Long, relayExpiryHour: Long): Long {
        val cap = consumeSeconds + TtlBucket.DAYS_30.seconds.toLong() + DmTime.HOUR
        return DmTime.ceilMinute(minOf(relayExpiryHour, cap))
    }

    /** The timer's own length in seconds (§7.1: 0 off, 5 min, 1 h, 1 d, 7 d, 30 d). */
    fun timerSeconds(timerCode: Int): Long = when (timerCode) {
        TIMER_OFF -> 0
        1 -> 5 * DmTime.MINUTE
        2 -> DmTime.HOUR
        3 -> DmTime.DAY
        4 -> 7 * DmTime.DAY
        5 -> 30 * DmTime.DAY
        else -> throw IllegalArgumentException("timer code out of range")
    }

    private fun ceilDiv(value: Long, by: Long): Long = -Math.floorDiv(-value, by)

    private fun ceil7(day: Long): Long = -Math.floorDiv(-day, 7L) * 7L
}
