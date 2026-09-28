package org.ghost.messaging

import org.ghost.messaging.engine.ContentFreshness
import org.ghost.messaging.engine.DmTime
import org.ghost.messaging.engine.DmTimers
import org.ghost.messaging.harness.DmMutants
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * [ContentFreshness.RULE] is the rule `ReceiveStep` wrote inline before design §22.38 — each bound at
 * its edge, in its order — and it reads the self row only when the inline code did.
 */
class ContentFreshnessTest {
    private val arrival = 1_800_000_000L
    private val fresh = 6 * DmTime.DAY
    private val twoSigma = 2 * DmTimers.SIGMA_SECONDS

    /** `FRESH(b)` of every timer code's bucket (§21.10 point 3). */
    private val everyFreshness = (0..5).map { DmTimers.freshSeconds(DmTimers.bucketOf(it)) }.distinct()

    private fun admits(author: Long, pairWeek: Long? = null, acceptAfter: Long? = null): Boolean =
        ContentFreshness.RULE.admits(author, arrival, fresh, pairWeek) { acceptAfter }

    @Test
    fun theAgeBoundIsInclusiveAtBothEdges() {
        assertTrue(admits(arrival - fresh))
        assertFalse(admits(arrival - fresh - 1))
        assertTrue(admits(arrival + twoSigma))
        assertFalse(admits(arrival + twoSigma + 1))
    }

    @Test
    fun acceptAfterRefusesOnlyWhatWasAuthoredBeforeIt() {
        assertFalse(admits(arrival - 60, acceptAfter = arrival))
        assertTrue(admits(arrival, acceptAfter = arrival))
        assertTrue(admits(arrival - 60, acceptAfter = null))
    }

    @Test
    fun bindingB1WantsTheAuthorsWeekToBeTheKeysWeek() {
        val week = DmTime.week(arrival)
        assertTrue(admits(arrival, pairWeek = week))
        assertFalse(admits(arrival, pairWeek = week + 1))
        assertTrue(admits(arrival, pairWeek = null))
    }

    /**
     * The three comparisons `ReceiveStep.decryptAndApply` made inline before §22.38, copied verbatim
     * — each `return dropped(STALE)` a `return false` — with the self row read where it read it.
     */
    private fun inline(authorSeconds: Long, arrivalSeconds: Long, fresh: Long, pairWeek: Long?, self: () -> Long?): Boolean {
        if (authorSeconds < arrivalSeconds - fresh ||
            authorSeconds > arrivalSeconds + 2 * DmTimers.SIGMA_SECONDS
        ) {
            return false
        }
        val acceptAfter = self()
        if (acceptAfter != null && authorSeconds < acceptAfter) {
            return false
        }
        if (pairWeek != null && DmTime.week(authorSeconds) != pairWeek) {
            return false
        }
        return true
    }

    /** One input of the grid below: an author time, a bucket's freshness, a key week, a self row. */
    private class Input(val author: Long, val fresh: Long, val pairWeek: Long?, val acceptAfter: Long?)

    /**
     * Every bucket's freshness, author times a second and a minute either side of every edge the
     * rule has (both ends of the age bound, `accept_after_minute`, the key week's two boundaries),
     * each with no self row or one at each edge, and each in pair mode (the arrival's week and both
     * neighbours) and not.
     */
    private fun grid(): List<Input> {
        val week = DmTime.week(arrival)
        val out = ArrayList<Input>()
        for (f in everyFreshness) {
            val edges = listOf(
                arrival - f, arrival + twoSigma, arrival, arrival - 3600,
                DmTime.weekStart(week), DmTime.weekStart(week + 1), DmTime.weekStart(week - 1),
            )
            val afters = listOf(null, arrival - f, arrival - 3600, arrival, arrival + twoSigma)
            for (edge in edges) for (d in listOf(-61L, -60L, -1L, 0L, 1L, 60L, 61L)) {
                for (after in afters) for (pw in listOf(null, week - 1, week, week + 1)) {
                    out += Input(edge + d, f, pw, after)
                }
            }
        }
        return out
    }

    @Test
    fun itDecidesAndReadsExactlyAsTheInlineCodeDidOnEveryEdge() {
        var admitted = 0
        var refused = 0
        for (i in grid()) {
            var ruleReads = 0
            var inlineReads = 0
            val rule = ContentFreshness.RULE.admits(i.author, arrival, i.fresh, i.pairWeek) { ruleReads++; i.acceptAfter }
            val old = inline(i.author, arrival, i.fresh, i.pairWeek) { inlineReads++; i.acceptAfter }
            val at = "author ${i.author}, fresh ${i.fresh}, pair week ${i.pairWeek}, accept after ${i.acceptAfter}"
            assertEquals("the decision at $at", old, rule)
            assertEquals("the self-row reads at $at", inlineReads, ruleReads)
            if (rule) admitted++ else refused++
        }
        // Both outcomes are reached, so the comparison is not over one constant.
        assertTrue("the grid admits nothing", admitted > 0)
        assertTrue("the grid refuses nothing", refused > 0)
    }

    @Test
    fun theGridTellsMutantMc9FromTheInlineCode() {
        // The comparison above can fail: MC-9's policy (§22.38) differs from the inline code on it.
        val mc9 = requireNotNull(DmMutants.MC9.freshness)
        val differs = grid().count { i ->
            mc9.admits(i.author, arrival, i.fresh, i.pairWeek) { i.acceptAfter } !=
                inline(i.author, arrival, i.fresh, i.pairWeek) { i.acceptAfter }
        }
        assertTrue("MC-9 decides like the inline code on every point of the grid", differs > 0)
    }

    @Test
    fun theSelfRowIsReadOnlyOnceTheAgeBoundHasPassed() {
        var reads = 0
        val stale = ContentFreshness.RULE.admits(arrival - fresh - 1, arrival, fresh, null) { reads++; null }
        assertFalse(stale)
        assertEquals("a stale author time must not read the self row", 0, reads)
        assertTrue(ContentFreshness.RULE.admits(arrival, arrival, fresh, null) { reads++; null })
        assertEquals(1, reads)
    }
}
