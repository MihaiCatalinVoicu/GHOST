package org.ghost.messaging.channel

import org.ghost.messaging.channel.engine.ChannelSettleStep
import org.junit.Assert.assertEquals
import org.junit.Test
import kotlin.random.Random

/**
 * **EM-3 conformance replay** (Phase 10 design §19.34's `better` semantics vs the engine; slice
 * S5c): a short probe asserting the engine's winner function ([ChannelSettleStep.co3Pick], what
 * `CH-SETTLE` runs) equals the model's rule on scripted candidate sets — the S5b2 comparator fix
 * (F-S5-7) checked against EM-3 without rerunning the exhaustive model (it is green; the PR bound
 * ran 1 474 689 states over 19 scenarios, §19.34). The rule, as the model's `better` runs it
 * (§19.1 rule 2, §19.13): among the **viable** candidates (abandonment already applied), the
 * winner maximises the successor senders, then minimises `(rank, hash)`; a committer's own
 * candidate without a verified copy ranks below every held foreign candidate unless it has
 * strictly more successor senders, and is adopted as the only viable candidate on at least one
 * successor sender (CO-4 (a)).
 *
 * The probe replays scripted sets (the named shapes of §12.3/§12.6: plain ties, successor
 * preferences, demotion, adoption) and a seeded sweep over small random sets, comparing the
 * engine's pick against an independent transcription of the model's rule below.
 */
class ChannelEm3ConformanceTest {

    /** The model's `better`, transcribed from §19.34/§19.1 (the reference the engine must equal). */
    private fun modelBetter(viable: List<ChannelSettleStep.Co3View>, counts: Map<List<Byte>, Int>): ChannelSettleStep.Co3View? {
        fun succ(v: ChannelSettleStep.Co3View): Int = counts[v.hash] ?: 0
        // More successors first, then the ascending `(rank, hash)` — the model's `better`.
        val better = Comparator<ChannelSettleStep.Co3View> { x, y ->
            val d = succ(y) - succ(x)
            if (d != 0) d else {
                val r = x.rank - y.rank
                if (r != 0) r else compareValues(x.hash, y.hash)
            }
        }
        val bestForeign = viable.filter { !it.own }.minWithOrNull(better)
        val own = viable.firstOrNull { it.own }
        return when {
            own == null -> bestForeign
            bestForeign == null -> if (own.verified || succ(own) >= 1) own else null
            !own.verified -> if (succ(own) > succ(bestForeign)) own else bestForeign
            else -> listOf(own, bestForeign).minWithOrNull(better)
        }
    }

    /** Lexicographic order of two hashes (CO-3's tie-break, as the engine's comparator runs it). */
    private fun compareValues(a: List<Byte>, b: List<Byte>): Int {
        for (i in 0 until minOf(a.size, b.size)) {
            val d = a[i] - b[i]
            if (d != 0) return d
        }
        return a.size - b.size
    }

    private fun enginePick(viable: List<ChannelSettleStep.Co3View>, counts: Map<List<Byte>, Int>): ChannelSettleStep.Co3View? =
        ChannelSettleStep.co3Pick(viable, counts)

    private fun view(rank: Int, tag: Int, own: Boolean = false, verified: Boolean = false) =
        ChannelSettleStep.Co3View(rank, listOf(tag.toByte()), own, verified)

    private fun assertSame(viable: List<ChannelSettleStep.Co3View>, counts: Map<List<Byte>, Int>, what: String) {
        assertEquals(what, modelBetter(viable, counts)?.hash, enginePick(viable, counts)?.hash)
    }

    @Test
    fun scriptedCandidateSetsAgreeWithTheModelsBetterRule() {
        val a = view(0, 1)
        val b = view(1, 2)
        val c = view(255, 3)
        // The plain `(rank, hash)` rule: no successors anywhere.
        assertSame(listOf(a, b, c), emptyMap(), "no successors: the lowest rank wins")
        assertSame(listOf(c, b), emptyMap(), "no successors: rank beats rank 255")
        assertSame(listOf(b, view(1, 4)), emptyMap(), "a tie on rank: the lower hash wins")
        // Successor preference (CO-3): the count decides before the rank.
        assertSame(listOf(a, b), mapOf(b.hash to 1), "one successor beats rank 0 (MM-24's rule)")
        assertSame(listOf(a, b), mapOf(a.hash to 1, b.hash to 2), "the larger count wins")
        assertSame(listOf(b, c), mapOf(c.hash to 3), "rank 255 with successors beats rank 1")
        assertSame(listOf(a, b, c), mapOf(c.hash to 1, a.hash to 1), "a tie on counts falls back to (rank, hash)")
        // The own-candidate rules (§19.13, CO-4 (a)).
        val ownVerified = view(0, 9, own = true, verified = true)
        val ownUnverified = view(0, 9, own = true, verified = false)
        assertSame(listOf(ownVerified, b), emptyMap(), "a verified own loses a plain tie on (rank, hash)")
        assertSame(listOf(ownVerified, b), mapOf(b.hash to 1), "a verified own loses to successors")
        assertSame(listOf(ownVerified, b), mapOf(ownVerified.hash to 1), "a verified own wins with successors")
        assertSame(listOf(ownUnverified, b), emptyMap(), "an unverified own is demoted below a foreign one")
        assertSame(listOf(ownUnverified, b), mapOf(ownUnverified.hash to 1), "…unless it has strictly more successors")
        assertSame(listOf(ownUnverified, b), mapOf(ownUnverified.hash to 1, b.hash to 1), "equal successors: the demotion stands")
        assertSame(listOf(ownUnverified), mapOf(ownUnverified.hash to 1), "adoption: a successor sender proves the copy (MM-32)")
        assertSame(listOf(ownUnverified), emptyMap(), "an unverified own alone with no successor evidence is no winner")
        assertSame(listOf(ownVerified), emptyMap(), "a verified own alone wins")
        assertSame(listOf(a, ownUnverified, c), mapOf(ownUnverified.hash to 2, c.hash to 1), "the demotion reads the best foreign only")
    }

    @Test
    fun aSeededSweepOverSmallCandidateSetsAgreesExhaustively() {
        val random = Random(42)
        var cases = 0
        repeat(4_000) {
            val n = 1 + random.nextInt(4)
            val viable = ArrayList<ChannelSettleStep.Co3View>(n)
            val used = HashSet<Int>()
            for (i in 0 until n) {
                val tag = random.nextInt(64)
                if (!used.add(tag)) continue
                viable += view(
                    rank = random.nextInt(256),
                    tag = tag,
                    own = random.nextInt(4) == 0,
                    verified = random.nextInt(2) == 0,
                )
            }
            if (viable.count { it.own } > 1) viable.removeAt(viable.indexOfLast { it.own })
            val counts = HashMap<List<Byte>, Int>()
            for (v in viable) if (random.nextInt(2) == 0) counts[v.hash] = random.nextInt(4)
            assertSame(viable, counts, "sweep case $cases: $viable counts=$counts")
            cases++
        }
        assertEquals(4000, cases)
    }
}
