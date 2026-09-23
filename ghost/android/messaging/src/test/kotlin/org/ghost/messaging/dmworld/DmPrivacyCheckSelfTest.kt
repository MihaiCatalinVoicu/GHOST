package org.ghost.messaging.dmworld

import org.ghost.crypto.bridge.RelaySets
import org.junit.Assert.assertEquals
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
}
