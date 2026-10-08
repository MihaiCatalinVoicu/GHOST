package org.ghost.messaging.channel

import org.ghost.messaging.channel.engine.ChannelSchedule
import java.security.MessageDigest
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * **CO-9's slot PRF pinned against an independent reference** (the review of S5, §19.40): the slot
 * day must lie **inside its period** for every (period, key) pair. The first version assembled a
 * signed int64 `head` from the HMAC digest and took Kotlin's `%`, whose truncated remainder is
 * negative for about half of all digests: those slots landed up to 27 days **before** their
 * period's start, the cadence slipped to 33–81 day gaps and a past `next_selfupdate_day`
 * double-fired. This test computes the HMAC itself (javax.crypto, like the engine but by its own
 * hand) and floors the modulo by hand — it pins the slot's range, which the engine's
 * self-comparing world tests cannot see.
 */
class ChannelScheduleTest {

    @Test
    fun theSlotDayLiesInsideItsPeriodForEveryPeriodAndKey() {
        var checked = 0
        for (i in 0 until 300) {
            val period = (i % 17).toLong() + i / 17
            val key = sha256("sched-key:$i")
            val channelId = sha256("sched-channel:${i / 3}")
            val slot = ChannelSchedule.slotDay(channelId, period, key)
            assertEquals("period $period, pair $i: the engine and the independent reference agree",
                referenceSlotDay(channelId, period, key), slot)
            assertTrue(
                "the slot is inside its period: $slot in [$period*28, ${period + 1}*28)",
                slot >= period * ChannelSchedule.PERIOD_DAYS && slot < (period + 1) * ChannelSchedule.PERIOD_DAYS,
            )
            checked++
        }
        assertTrue("at least 256 (period, key) pairs were checked", checked >= 256)
    }

    /**
     * The independent reference: the same MAC input the design names (`channel_id ‖ u32_be(period)`),
     * the digest's first eight bytes as a big-endian signed int64, the modulo **floored by hand**
     * (`((head % 28) + 28) % 28`) — no engine code on the path.
     */
    private fun referenceSlotDay(channelId: ByteArray, period: Long, key: ByteArray): Long {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(key, "HmacSHA256"))
        val msg = channelId + ByteArray(4) { i -> (period ushr (24 - 8 * i)).toByte() }
        val digest = mac.doFinal(msg)
        var head = 0L
        for (b in 0 until 8) head = (head shl 8) or (digest[b].toLong() and 0xff)
        val mod = ((head % ChannelSchedule.PERIOD_DAYS) + ChannelSchedule.PERIOD_DAYS) % ChannelSchedule.PERIOD_DAYS
        return period * ChannelSchedule.PERIOD_DAYS + mod
    }

    private fun sha256(text: String): ByteArray = MessageDigest.getInstance("SHA-256").digest(text.toByteArray(Charsets.UTF_8))
}
