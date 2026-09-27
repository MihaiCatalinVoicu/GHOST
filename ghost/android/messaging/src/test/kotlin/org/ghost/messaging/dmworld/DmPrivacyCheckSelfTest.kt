package org.ghost.messaging.dmworld

import org.ghost.crypto.bridge.RelaySets
import org.ghost.messaging.DmWorld
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.SplittableRandom

/**
 * The privacy checks' own arithmetic, on inputs whose answer is known — no world and no native
 * library, so it runs everywhere. A join that cannot find a planted match, a relay-set rule that
 * disagrees with the production one, or a binomial interval that does not bracket its mean would make
 * every PASS of the world tests meaningless; this is where that would show.
 */
class DmPrivacyCheckSelfTest {

    @Test
    fun theDictionaryFindsAPlantedWindowAnywhereAndNothingElse() {
        val rnd = SplittableRandom(1)
        val entry = ByteArray(32).also { rnd.nextBytes(it) }
        val dictionary = ByteDictionary()
        dictionary.add("planted", entry)
        repeat(50) { dictionary.add("noise $it", ByteArray(32).also { b -> rnd.nextBytes(b) }) }
        val corpus = ByteArray(4096).also { rnd.nextBytes(it) }
        var hits = 0
        dictionary.scan(corpus) { _, _ -> hits++ }
        assertEquals("uniform bytes matched a dictionary entry", 0, hits)
        // The first 16 bytes of the entry at an odd offset, and its last 16 further on: the window
        // rule of JD1 and JD2 finds either end of an entry.
        System.arraycopy(entry, 0, corpus, 1_001, 16)
        System.arraycopy(entry, 16, corpus, 3_003, 16)
        val found = ArrayList<Pair<String, Int>>()
        dictionary.scan(corpus) { e, at -> found += e.name to at }
        assertEquals(listOf("planted" to 1_001, "planted" to 3_003), found)
        // A middle slice is not an end of the entry, and is not found.
        val middle = ByteArray(4096).also { rnd.nextBytes(it) }
        System.arraycopy(entry, 8, middle, 500, 16)
        var middleHits = 0
        dictionary.scan(middle) { _, _ -> middleHits++ }
        assertEquals(0, middleHits)
    }

    @Test
    fun theDictionaryGrowsAndNamesItsEntriesByFamily() {
        val rnd = SplittableRandom(3)
        val dictionary = ByteDictionary()
        val values = List(5_000) { ByteArray(32).also { b -> rnd.nextBytes(b) } }
        val family = dictionary.family(7) { form -> "value $form" }
        values.forEachIndexed { i, v -> dictionary.add(family, i, v) }
        assertEquals(5_000, dictionary.size)
        val corpus = ByteArray(64)
        System.arraycopy(values[4_321], 0, corpus, 10, 32)
        val found = ArrayList<Triple<String, Int?, Int>>()
        dictionary.scan(corpus) { e, at -> found += Triple(e.name, e.owner, at) }
        assertEquals(listOf(Triple("value 4321", 7, 10), Triple("value 4321", 7, 26)), found)
    }

    @Test
    fun jd9sRelaySetIsTheProductionRuleWrittenOutAgain() {
        val rnd = SplittableRandom(2)
        val slots = (0 until PrivacyWorld.SLOTS).map { i ->
            RelaySets.Slot(i, i.toLong(), byteArrayOf((0x40 + i % PrivacyWorld.OPERATORS).toByte()))
        }
        repeat(500) {
            val ns = ByteArray(32).also { rnd.nextBytes(it) }
            val production = RelaySets.forNamespace(ns, slots).map { it.slot }.toSet()
            assertEquals(production, Joins.relaySet(ns))
        }
    }

    @Test
    fun rb1IsSection66sTable() {
        assertEquals(4096, Joins.rb1(0))
        assertEquals(4096, Joins.rb1(2_220))
        assertEquals(16384, Joins.rb1(2_221))
        assertEquals(16384, Joins.rb1(14_508))
        assertEquals(65536, Joins.rb1(14_509))
        assertEquals(65536, Joins.rb1(61_440))
    }

    @Test
    fun theBinomialIntervalBracketsChanceAndExcludesTheMutant() {
        // S-DM3 at the PR scale: n = 240 namespaces, N = 120 identities.
        val (lo, hi) = Sdm3.interval(240, 1.0 / 120, 0.001)
        assertTrue("[$lo, $hi] does not contain the mean 2", 2 in lo..hi)
        assertTrue("[$lo, $hi] contains PM-3's K = n", 240 !in lo..hi)
        assertTrue(Sdm3.twoSided(2, 240, 1.0 / 120) > 0.5)
        assertTrue(Sdm3.twoSided(240, 240, 1.0 / 120) < 1e-100)
        val pmf = Sdm3.pmf(240, 1.0 / 120)
        assertEquals(1.0, pmf.sum(), 1e-9)
    }

    @Test
    fun theTimerTableIsSection101s() {
        assertEquals(2_592_000L, Joins.table(0))
        assertEquals(3_600L, Joins.table(1))
        assertEquals(3_600L, Joins.table(2))
        assertEquals(86_400L, Joins.table(3))
        assertEquals(604_800L, Joins.table(4))
        assertEquals(2_592_000L, Joins.table(5))
    }

    // ------------------------------------------------------------------ NI-DM2's comparator

    /** One synthetic NI-DM2 message: M reached its variable unless [stores] is empty. */
    private fun m(
        state: NiDm2.State,
        kind: NiDm2.Kind,
        length: Int = 0,
        ttl: Long = 604_800,
        size: Int = 4096,
        slots: List<Int> = listOf(0, 1, 3),
        seconds: Long = 60,
        stores: Boolean = true,
    ): NiDm2.Slot {
        val view = if (stores) slots.map { NiDm2.Store(it, "inbox", size, ttl, "scope$it") } else emptyList()
        val content = GroundTruth.Content(
            kind = kind.wire,
            bodyLength = length,
            quoted = kind.quoted,
            sealRoot = state.offer == true,
            sealRootPq = false,
            pqKey = false,
        )
        return NiDm2.Slot(
            variant = NiDm2.Variant(state, kind),
            length = length,
            view = view,
            seconds = view.map { seconds },
            blobs = if (stores) 1 else 0,
            mode = if (stores) state.mode else null,
            content = if (stores) content else null,
            action = "synthetic",
        )
    }

    /** The gating twins at length 0: two that need no establishment (their seconds gate) and a reset. */
    private fun gating(ttl: Long = 604_800, seconds: Long = 60): List<NiDm2.Slot> = listOf(
        m(NiDm2.State.PROVISIONAL, NiDm2.Kind.QUOTED, ttl = ttl, seconds = seconds),
        m(NiDm2.State.PAIR, NiDm2.Kind.TIMER_SET, ttl = ttl),
        m(NiDm2.State.RESET, NiDm2.Kind.CONTROL, ttl = ttl, seconds = 400),
    )

    private val intro = NiDm2.State.INTRO
    private val timerSet = NiDm2.Kind.TIMER_SET

    @Test
    fun niDm2PassesADeclaredDefectOnlyWhenItReproducesExactlyAsDeclared() {
        val exact = NiDm2.Result(gating() + m(intro, timerSet, ttl = 86_400, seconds = 700))
        assertTrue(exact.line(), exact.passed)
        assertTrue(
            exact.line(),
            exact.line().contains(
                "; 1 declared open defect, not gated, reproduced exactly as declared: INTRO/TIMER_SET at 0 stores " +
                    "ttl=86400 where the other twins store ttl=604800, every other field equal, at 3 relays — ",
            ),
        )
        // 3 of 4 messages gate; 2 comparisons of views, 1 of seconds (the reset's are not compared).
        assertTrue(exact.line(), exact.line().contains("; 3 of their 4 messages gate: "))
        assertEquals(2, exact.comparisons)
        assertEquals(1, exact.timedComparisons)

        val fixed = NiDm2.Result(gating() + m(intro, timerSet))
        assertFalse(fixed.line(), fixed.passed)
        assertTrue(fixed.line(), fixed.line().contains("no longer reproduces"))

        val partial = NiDm2.Result(gating() + m(intro, timerSet, ttl = 2_592_000))
        assertFalse(partial.line(), partial.passed)
        assertTrue(partial.line(), partial.line().contains("otherwise than declared"))

        val size = NiDm2.Result(gating() + m(intro, timerSet, ttl = 86_400, size = 16_384))
        assertFalse(size.line(), size.passed)
        assertTrue(size.line(), size.line().contains("otherwise than declared"))

        val relays = NiDm2.Result(gating() + m(intro, timerSet, ttl = 86_400, slots = listOf(0, 1, 2)))
        assertFalse(relays.line(), relays.passed)
        assertTrue(relays.line(), relays.line().contains("otherwise than declared"))

        val extra = NiDm2.Result(gating() + m(intro, timerSet, ttl = 86_400, slots = listOf(0, 1, 2, 3)))
        assertFalse(extra.line(), extra.passed)

        // The other twins no longer store the declared TTL: the declaration describes another world.
        val moved = NiDm2.Result(gating(ttl = 2_592_000) + m(intro, timerSet, ttl = 86_400))
        assertFalse(moved.line(), moved.passed)
        assertTrue(moved.line(), moved.line().contains("not the declared ttl=604800"))

        val missing = NiDm2.Result(gating())
        assertFalse(missing.line(), missing.passed)
        assertTrue(missing.line(), missing.line().contains("declared, but no such twin ran"))

        val unreached = NiDm2.Result(gating() + m(intro, timerSet, stores = false))
        assertFalse(unreached.line(), unreached.passed)
        assertTrue(unreached.line(), unreached.line().contains("so nothing was reproduced"))
    }

    @Test
    fun niDm2FailsOnAGatingDifferenceAndNeverComparesATwinThatDidNotReachItsState() {
        val split = gating().toMutableList().also { it[1] = m(NiDm2.State.PAIR, NiDm2.Kind.TIMER_SET, ttl = 86_400) }
        val differs = NiDm2.Result(split + m(intro, timerSet, ttl = 86_400))
        assertFalse(differs.line(), differs.passed)
        assertTrue(differs.line(), differs.line().contains("differ at body length 0: "))
        assertTrue(differs.line(), differs.line().contains("no single view of the other twins"))

        val empty = gating().toMutableList().also { it[0] = m(NiDm2.State.PROVISIONAL, NiDm2.Kind.QUOTED, stores = false) }
        val notReached = NiDm2.Result(empty + m(intro, timerSet, ttl = 86_400))
        assertFalse(notReached.line(), notReached.passed)
        assertTrue(notReached.line(), notReached.line().contains("did not reach their variable"))
        // The empty twin is not compared: no "no store" view can pass for a difference a mutant made.
        assertFalse(notReached.line(), notReached.line().contains("differ at body length"))
    }

    @Test
    fun niDm2ComparesTheSecondOnlyWhereNoEstablishmentDecidesIt() {
        // The provisional twin stored a minute later than the pair twin: a state-dependent delay.
        val late = NiDm2.Result(gating(seconds = 120) + m(intro, timerSet, ttl = 86_400))
        assertFalse(late.line(), late.passed)
        assertTrue(late.line(), late.line().contains("store seconds after t0 differ at body length 0"))
        // The reset's and the intro's seconds (400 and 700 above) never gate.
        val establishing = NiDm2.Result(gating() + m(intro, timerSet, ttl = 86_400, seconds = 5))
        assertTrue(establishing.line(), establishing.passed)
    }

    // ------------------------------------------------------------------ JD7's attempt windows

    private val hour = DmWorld.HOUR

    /** A reader whose relay sessions start every hour for [hours] hours. */
    private fun wakes(hours: Int): java.util.TreeSet<Long> = java.util.TreeSet((0..hours).map { it * hour })

    /** Reads in three windows, six hours apart, after an establishment at 0 (see §21.7 points 2, 5). */
    private val threeWindows = listOf(10L, 7 * hour + 10, 14 * hour + 10)

    @Test
    fun jd7sWindowsBoundTheAttemptsAndSayWhenAFourthCouldHaveFallen() {
        val establishment = PrivacyWorld.Establishment(0, 1, 0)
        val w = Joins.Windows(listOf(establishment), wakes(72))
        for (t in threeWindows) assertTrue("read at $t refused", w.accept(t))
        assertEquals(3, w.total)
        assertEquals(1, w.exhausted)
        // The third window closed at its end, 14 h 15 min; a session starts at 21 h and no new
        // establishment came: an unbounded engine's fourth attempt had somewhere to fall.
        assertEquals(1, w.binding())
        assertFalse("a fourth attempt was accepted", w.accept(21 * hour + 10))
    }

    /**
     * The production triggers' windows (§22.36): a window closes at its end — the alarm and the actor
     * timer wake for the fetch deadline — not at the reader's next relay round, and a later attempt
     * opens only at a relay session **start** (`Due.START`, phase review MD-2), whose read lane lists
     * in the second it started.
     */
    @Test
    fun jd7sWindowsCloseAtTheirEndAndReopenOnlyAtASessionStart() {
        val establishment = PrivacyWorld.Establishment(0, 1, 0)
        val w = Joins.Windows(listOf(establishment), wakes(72))
        // The first window's last second is in it; a read a minute later is not (the first version
        // closed the window at the next relay session, an hour on here, and accepted it).
        assertTrue(w.accept(15 * 60))
        assertFalse("a read after the first window's end was accepted", w.accept(16 * 60))
        // Six hours after that end, a session starts at 7 h: its read in that second opens the
        // second window, and a read of the same session past the window's end is outside it.
        assertTrue(w.accept(7 * hour))
        assertTrue(w.accept(7 * hour + 15 * 60))
        assertFalse("a read after the second window's end was accepted", w.accept(7 * hour + 20 * 60))
        // A reader with no session start six hours after the end gets no second window, however
        // many relay rounds it makes: the rounds of a foreground session are no session starts.
        val quiet = Joins.Windows(listOf(establishment), java.util.TreeSet(listOf(0L, hour)))
        assertTrue(quiet.accept(60))
        assertFalse("a later attempt without a session start was accepted", quiet.accept(8 * hour))
        assertEquals(1, quiet.total)
    }

    @Test
    fun jd7sBindingCountRefusesAnExhaustionWithNoRoomForAFourthAttempt() {
        val establishment = PrivacyWorld.Establishment(0, 1, 0)
        // The world ends before six hours pass after the third window.
        val short = Joins.Windows(listOf(establishment), wakes(20))
        for (t in threeWindows) assertTrue(short.accept(t))
        assertEquals(1, short.exhausted)
        assertEquals(0, short.binding())
        // A new send to the peer (a new establishment) comes before the fourth attempt would.
        val renewed = Joins.Windows(listOf(establishment, PrivacyWorld.Establishment(0, 1, 18 * hour)), wakes(72))
        for (t in threeWindows) assertTrue(renewed.accept(t))
        assertEquals(1, renewed.exhausted)
        assertEquals(0, renewed.binding())
        // Two windows only: nothing was exhausted, nothing binds.
        val two = Joins.Windows(listOf(establishment), wakes(72))
        for (t in threeWindows.take(2)) assertTrue(two.accept(t))
        assertEquals(0, two.exhausted)
        assertEquals(0, two.binding())
    }
}
