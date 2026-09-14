package org.ghost.entitlement.engine

import org.ghost.entitlement.port.EntitlementRandom
import org.ghost.sync.store.Time

/**
 * The refresh time of a received credit (design §19.8, §19.26; Q31): drawn from client randomness
 * when the inviter creates the invite and starts listening on its drop, never from the moment a
 * credit is read from the drop, which the relays see.
 *
 *  - [Times.first]: 1–14 days after the end of the latest drop window an invitee of the invite can
 *    draw (it activates before the expiry day, and `t_drop < start(base + 8)`, §19.12), so an
 *    invitee's credit is normally read before it and waits for it;
 *  - [Times.second]: 1–14 days after the drop's listening ends, so after every read (nothing is
 *    taken from the drop once its listening ended).
 *
 * A credit read at or before the first time is refreshed then, one read after it at the second: the
 * read decides only which of the two pre-drawn times applies. Either is cut at two days before
 * credit epoch `epoch + 2` starts, from when the issuer refuses the refresh (it refreshes `c_now` and
 * `c_now − 1` only, §19.8), so a cut refresh is due at a time set by the credit's epoch alone; a
 * credit whose due time would lie before its read is dropped, never refreshed at the read. Pinned
 * by `entitlement_policy.txt` (`refresh`, `refreshdue`), which the T2 reference policy replays too.
 */
internal object RefreshPlan {
    private const val DELAY_MIN: Long = Grid.DAY
    private const val DELAY_MAX: Long = 14 * Grid.DAY
    private const val CUT_MARGIN: Long = 2 * Grid.DAY

    /** The two refresh times of one invite (minutes, device time). */
    class Times(val first: Long, val second: Long) {
        override fun toString(): String = "RefreshPlan.Times"
    }

    /**
     * The refresh times of an invite usable on the days before UTC day [expiryDay] and listened
     * until UTC day [listenUntilDay]: the first draw sets [Times.first], the second [Times.second].
     */
    fun times(expiryDay: Long, listenUntilDay: Long, random: EntitlementRandom): Times {
        val lastDropEnd = Grid.start(Grid.week(expiryDay * Grid.DAY - 1) + TrialSteps.DROP_END_WEEK)
        val first = draw(lastDropEnd, random.uniform())
        val second = draw(listenUntilDay * Grid.DAY, random.uniform())
        return Times(first, second)
    }

    private fun draw(from: Long, u: Double): Long = Time.ceilMinute(from + DELAY_MIN + (u * (DELAY_MAX - DELAY_MIN)).toLong())

    /**
     * The due time of a received credit of credit epoch [epoch] read from the drop at [readAt]: the
     * first time if read at or before it, else the second, cut at the issuer's refresh window; null
     * when that lies before the read (the credit is dropped).
     */
    fun due(first: Long, second: Long, epoch: Long, readAt: Long): Long? {
        val cut = Grid.start(Grid.creditEpochFirstWeek(epoch + 2)) - CUT_MARGIN
        val due = minOf(if (readAt <= first) first else second, cut)
        return if (due >= readAt) due else null
    }
}
