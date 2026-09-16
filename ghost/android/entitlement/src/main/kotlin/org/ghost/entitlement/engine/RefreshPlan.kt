package org.ghost.entitlement.engine

import org.ghost.entitlement.port.EntitlementRandom
import org.ghost.sync.store.Time

/**
 * The refresh time of a received credit (design §19.8, §19.29; Q31 simplified 2026-09-14): one time,
 * drawn from client randomness when the inviter registers a drop as listened (an invite it creates,
 * or a drop a restore scans, §8.4), 1–14 days after the drop's listening ends. Nothing is taken from
 * a drop from its `listen_until_day` on ([DropSteps]), so every read precedes that time, and the
 * read, which the relays see, decides nothing: the due time is a function of the invite's draw, its
 * listening end and the credit's epoch only.
 *
 * The issuer refreshes a credit of epoch c only until credit epoch c + 2 starts (§19.8); the client
 * keeps two days of margin ([cut]). A time after the cut is replaced by the same draw placed inside
 * [listening end, cut] (its fraction of the 1–14-day window). When the cut precedes the listening's
 * end no time after every read exists, and the credit is dropped (counted), whatever the read: any
 * earlier time could precede a later read of the same blob, and a refresh at the read is what Q31
 * excluded. Pinned by `entitlement_policy.txt` (`refresh`, `refreshdue`), which the T2 reference
 * policy replays too.
 */
internal object RefreshPlan {
    private const val DELAY_MIN: Long = Grid.DAY
    private const val DELAY_MAX: Long = 14 * Grid.DAY
    private const val CUT_MARGIN: Long = 2 * Grid.DAY

    /** The refresh time of a credit received through a drop listened until UTC day [listenUntilDay]: one draw. */
    fun time(listenUntilDay: Long, random: EntitlementRandom): Long =
        Time.ceilMinute(listenUntilDay * Grid.DAY + DELAY_MIN + (random.uniform() * (DELAY_MAX - DELAY_MIN)).toLong())

    /** Two days before credit epoch [epoch] + 2 starts, from when the issuer refuses the refresh (§19.8). */
    fun cut(epoch: Long): Long = Grid.start(Grid.creditEpochFirstWeek(epoch + 2)) - CUT_MARGIN

    /**
     * The due time of a received credit of credit epoch [epoch] from a drop listened until UTC day
     * [listenUntilDay] whose refresh time is [at]: [at] when it lies at or before the cut; otherwise the
     * same draw placed inside [listening end, cut], rounded up to the minute; null when the cut precedes
     * the listening's end (the credit is dropped). No read time enters.
     */
    fun due(at: Long, listenUntilDay: Long, epoch: Long): Long? {
        val end = listenUntilDay * Grid.DAY
        val cut = cut(epoch)
        if (cut < end) return null
        if (at <= cut) return at
        val span = DELAY_MAX - DELAY_MIN
        val drawn = (at - end - DELAY_MIN).coerceIn(0L, span)
        return Time.ceilMinute(end + Math.floorDiv(drawn * (cut - end), span))
    }
}
