package org.ghost.messaging.channel.engine

import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * CO-9's self-update schedule (Phase 10 design §6.4 CO-9, §6.8): a member of rank 255 commits an empty self-update
 * once every [PERIOD_DAYS]-day period, at the first session after its PRF slot. The slot of a period is
 * `period × 28 + (HMAC(K, channel_id ‖ u32_be(period)) mod 28)`: one day of the period per member, spread by the
 * MAC, recomputed by the member alone — nothing about the slot is agreed with anyone (the retry after a lost
 * tie-break reuses [java.time] days through `ch_schedule.next_selfupdate_day`, the only state).
 *
 * **The key (finding F-S5-6, §19.39).** CO-9 names `K_sched` "from the MESSAGING branch" but §5.2 defines no
 * derivation for it and no label, and the closed JNI list (§10.2, gate G-M6) exposes no MESSAGING-branch HKDF the
 * Kotlin side could call — the one literal the design gives is the MAC's input, `channel_id ‖ u32(period)`, with no
 * label at all. This engine therefore keys the PRF by `dm_self`'s random seen key, a random seed, which §5.2
 * rule (1) admits as a key input; the MAC is computed in Kotlin like `ChannelTags`' (G-M3 rule 4's exception
 * shape: a MAC keyed by a secret, not a derivation from public material; no `ghost/v1/ch…` literal appears). The
 * slot is scheduling metadata, never on the wire; the one relay-visible consequence — the self-update's store
 * time — is the declared LC-6. The cost of the deviation: a seed restore regenerates `dm_self`'s seen key, so the
 * member draws a new slot from the restored day onward, where the MESSAGING branch would have kept the old one.
 */
internal object ChannelSchedule {

    /** The self-update period of CO-9 (and Q9's 28-day cadence): 28 days. */
    const val PERIOD_DAYS: Long = 28

    /** The period [day] belongs to. */
    fun period(day: Long): Long = Math.floorDiv(day, PERIOD_DAYS)

    /**
     * The day of [period]'s slot for [channelId]:
     * `period × 28 + floorMod(HMAC(K, channel_id ‖ u32_be(period)) as int64, 28)`. [key] is `dm_self`'s random
     * seen key (the KDoc above); the caller zeroes nothing — the seen key is the caller's copy to zero, as
     * everywhere. The offset is `floorMod`, never `%`: a signed int64's truncated remainder is negative for
     * about half of all digests and would land the slot before its period's start (§19.40, the S5 review).
     */
    fun slotDay(channelId: ByteArray, period: Long, key: ByteArray): Long {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(key, "HmacSHA256"))
        val msg = channelId + ByteArray(4) { i -> (period ushr (24 - 8 * i)).toByte() }
        val digest = mac.doFinal(msg)
        var head = 0L
        for (i in 0 until 8) head = (head shl 8) or (digest[i].toLong() and 0xff)
        return period * PERIOD_DAYS + Math.floorMod(head, PERIOD_DAYS)
    }

    /** The day of the slot that follows [day]'s period (what a committed or skipped self-update schedules next). */
    fun nextSlotDay(channelId: ByteArray, day: Long, key: ByteArray): Long = slotDay(channelId, period(day) + 1, key)
}
