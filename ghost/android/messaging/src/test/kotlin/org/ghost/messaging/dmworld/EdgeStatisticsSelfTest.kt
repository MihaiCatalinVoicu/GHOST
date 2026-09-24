package org.ghost.messaging.dmworld

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.SplittableRandom

/**
 * The arithmetic of S-DM1, S-DM2 and S-DM4 held to known answers, with no native library and no
 * world ([EdgeMath]), and the view projection and features of the edge attackers held to hand-built
 * views ([EdgeViews], [EdgeFeatures]). The permutation test is shown to **reject** a planted
 * difference — also a small one among rows tied at zero, as the edge attack's are — **not** to
 * reject equal scorers, and to hold its level on continuous and on zero-heavy null worlds; its
 * smallest p is α itself, so a check that reads `p ≤ α` can fail. The exact half is shown to see an
 * 8-byte run at every offset of either blob (§22.30).
 */
class EdgeStatisticsSelfTest {

    @Test
    fun aucKnownAnswers() {
        val labels = booleanArrayOf(false, false, true, true)
        assertEquals(1.0, EdgeMath.auc(doubleArrayOf(0.1, 0.2, 0.8, 0.9), labels), 1e-12)
        assertEquals(0.0, EdgeMath.auc(doubleArrayOf(0.9, 0.8, 0.2, 0.1), labels), 1e-12)
        assertEquals(0.5, EdgeMath.auc(doubleArrayOf(1.0, 1.0, 1.0, 1.0), labels), 1e-12)
        // Positives 0.35 and 0.8 against negatives 0.1 and 0.4: 3 of 4 comparisons won.
        assertEquals(0.75, EdgeMath.auc(doubleArrayOf(0.1, 0.4, 0.35, 0.8), labels), 1e-12)
        // A tie between a positive and a negative counts one half.
        assertEquals(0.875, EdgeMath.auc(doubleArrayOf(0.1, 0.4, 0.4, 0.8), labels), 1e-12)
        assertTrue(EdgeMath.auc(doubleArrayOf(1.0, 2.0), booleanArrayOf(false, false)).isNaN())
    }

    @Test
    fun midRanksAreTwiceTheAverageRank() {
        assertArrayEquals(intArrayOf(5, 2, 5), EdgeMath.midRanks2(doubleArrayOf(3.0, 1.0, 3.0)))
        assertArrayEquals(intArrayOf(2, 4, 6), EdgeMath.midRanks2(doubleArrayOf(-1.0, 0.0, 7.0)))
        assertArrayEquals(intArrayOf(4, 4, 4), EdgeMath.midRanks2(doubleArrayOf(0.0, 0.0, 0.0)))
    }

    @Test
    fun theStratifiedAucComparesRowsOnlyWithinTheirStratum() {
        // Stratum 0: all scores high, positive above negative; stratum 1: all low, positive above
        // negative. Pooled, stratum 0's negative outranks stratum 1's positive; stratified, it never
        // meets it.
        val scores = doubleArrayOf(10.0, 11.0, 0.0, 1.0)
        val labels = booleanArrayOf(false, true, false, true)
        val strata = intArrayOf(0, 0, 1, 1)
        assertEquals(1.0, EdgeMath.stratifiedAuc(scores, labels, strata), 1e-12)
        assertEquals(0.75, EdgeMath.auc(scores, labels), 1e-12)
        // A stratum with only negatives compares nothing and changes nothing.
        assertEquals(
            1.0,
            EdgeMath.stratifiedAuc(scores + doubleArrayOf(99.0), labels + booleanArrayOf(false), strata + intArrayOf(2)),
            1e-12,
        )
    }

    /** Synthetic (window, pair) rows: [groups] pairs over [strata] windows, 20 % positive pairs. */
    private class Synthetic(groups: Int, strata: Int, seed: Long, fullSignal: Double, ldSignal: Double) {
        val n = groups * strata
        val labels = BooleanArray(n)
        val stratum = IntArray(n)
        val group = IntArray(n)
        val full = DoubleArray(n)
        val ld = DoubleArray(n)

        init {
            val rnd = SplittableRandom(seed)
            val positive = BooleanArray(groups) { rnd.nextInt(5) == 0 }
            var i = 0
            for (s in 0 until strata) for (g in 0 until groups) {
                labels[i] = positive[g]
                stratum[i] = s
                group[i] = g
                val y = if (positive[g]) 1.0 else 0.0
                full[i] = fullSignal * y + gaussian(rnd)
                ld[i] = ldSignal * y + gaussian(rnd)
                i++
            }
        }

        private fun gaussian(rnd: SplittableRandom): Double =
            Math.sqrt(-2 * Math.log(1 - rnd.nextDouble())) * Math.cos(2 * Math.PI * rnd.nextDouble())
    }

    /**
     * Synthetic (window, pair) rows shaped like the edge attack's: [groups] pairs over [strata]
     * windows, 20 % positive pairs, and a count score that is **zero in most rows** — a positive pair
     * is active in a window with probability 0.15, a negative one with 0.03, at 1–3 — so most rows of
     * both views tie at 0. The full view adds 1 to an active-or-not positive row with probability
     * [leak]; [noise] adds, independently in each view, 1 to any row with that probability (two
     * equally informative views that are not identical); [extra] adds 1–2 to any row of the full view
     * alone with that probability, whatever its label (events that link nothing).
     */
    private class ZeroHeavy(groups: Int, strata: Int, seed: Long, leak: Double, noise: Double = 0.0, extra: Double = 0.0) {
        val n = groups * strata
        val labels = BooleanArray(n)
        val stratum = IntArray(n)
        val group = IntArray(n)
        val full = DoubleArray(n)
        val ld = DoubleArray(n)

        init {
            val rnd = SplittableRandom(seed)
            val positive = BooleanArray(groups) { rnd.nextInt(5) == 0 }
            var i = 0
            for (s in 0 until strata) for (g in 0 until groups) {
                labels[i] = positive[g]
                stratum[i] = s
                group[i] = g
                val base = if (rnd.nextDouble() < (if (positive[g]) 0.15 else 0.03)) 1.0 + rnd.nextInt(3) else 0.0
                ld[i] = base + (if (rnd.nextDouble() < noise) 1.0 else 0.0)
                full[i] = base + (if (rnd.nextDouble() < noise) 1.0 else 0.0) + (if (positive[g] && rnd.nextDouble() < leak) 1.0 else 0.0) +
                    (if (rnd.nextDouble() < extra) 1.0 + rnd.nextInt(2) else 0.0)
                i++
            }
        }
    }

    @Test
    fun thePermutationTestRejectsAPlantedDifference() {
        val d = Synthetic(groups = 300, strata = 4, seed = 1, fullSignal = 2.0, ldSignal = 0.5)
        val t = EdgeMath.pairedPermutationTest(d.full, d.ld, d.labels, d.stratum, d.group, seed = 7)
        assertTrue("the planted difference is positive: ${t.difference}", t.difference > 0.2)
        assertEquals("no permuted difference reaches a planted one", 0, t.exceeded)
        assertEquals(EdgeMath.ALPHA, t.p, 1e-15)
        assertTrue("p = α must reject (p ≤ α, not p < α)", t.rejects)
    }

    @Test
    fun thePermutationTestDoesNotRejectEqualScorers() {
        val d = Synthetic(groups = 300, strata = 4, seed = 2, fullSignal = 1.0, ldSignal = 1.0)
        // Identical scores: every component is 0, so every permuted difference is the observed 0.
        val same = EdgeMath.pairedPermutationTest(d.ld, d.ld.copyOf(), d.labels, d.stratum, d.group, seed = 7)
        assertEquals(0.0, same.difference, 1e-12)
        assertEquals(1.0, same.p, 1e-12)
        assertFalse(same.rejects)
        // Worse full scores never reject (one-sided).
        val worse = Synthetic(groups = 300, strata = 4, seed = 3, fullSignal = 0.0, ldSignal = 2.0)
        assertFalse(EdgeMath.pairedPermutationTest(worse.full, worse.ld, worse.labels, worse.stratum, worse.group, seed = 7).rejects)
        // A monotone map of either view's scores changes nothing: each view is compared with itself
        // (so two fitted models on different scales are compared as they rank, not as they score).
        val shifted = DoubleArray(d.full.size) { 3 * d.full[it] + 100 }
        val a = EdgeMath.pairedPermutationTest(d.full, d.ld, d.labels, d.stratum, d.group, seed = 7)
        val b = EdgeMath.pairedPermutationTest(shifted, d.ld, d.labels, d.stratum, d.group, seed = 7)
        assertEquals(a.difference, b.difference, 1e-12)
        assertEquals(a.exceeded, b.exceeded)
    }

    @Test
    fun thePermutationTestHoldsItsLevelUnderTheNull() {
        // Two equally informative, independently noisy scorers, 200 worlds, 99 permutations each —
        // continuous scores, scores tied at zero in most rows as the edge attack's are, and a full
        // view with extra events on rows of both labels: the share of p ≤ 0.05 must be near 0.05 (at
        // most 0.10 here, 20 of 200). The zero-heavy case is the one the first version was never held
        // to (§22.30 item 12): a port of its per-view ranks rejected none of 200 such worlds, measured
        // while this was written, so it was far below its level.
        var gaussian = 0
        var zeros = 0
        var unlabelled = 0
        for (seed in 0 until 200) {
            val d = Synthetic(groups = 120, strata = 3, seed = 1_000L + seed, fullSignal = 1.0, ldSignal = 1.0)
            val t = EdgeMath.pairedPermutationTest(d.full, d.ld, d.labels, d.stratum, d.group, seed = seed.toLong(), permutations = 99)
            if (t.difference > 0 && t.p <= 0.05) gaussian++
            val z = ZeroHeavy(groups = 300, strata = 4, seed = 5_000L + seed, leak = 0.0, noise = 0.02)
            val u = EdgeMath.pairedPermutationTest(z.full, z.ld, z.labels, z.stratum, z.group, seed = seed.toLong(), permutations = 99)
            if (u.difference > 0 && u.p <= 0.05) zeros++
            val e = ZeroHeavy(groups = 300, strata = 4, seed = 9_000L + seed, leak = 0.0, extra = 0.3)
            val v = EdgeMath.pairedPermutationTest(e.full, e.ld, e.labels, e.stratum, e.group, seed = seed.toLong(), permutations = 99)
            if (v.difference > 0 && v.p <= 0.05) unlabelled++
        }
        assertTrue("$gaussian of 200 continuous null worlds rejected at 0.05", gaussian in 1..20)
        assertTrue("$zeros of 200 zero-heavy null worlds rejected at 0.05", zeros in 1..20)
        assertTrue("$unlabelled of 200 worlds with label-blind extra events rejected at 0.05", unlabelled <= 20)
    }

    @Test
    fun thePermutationTestRejectsALeakAmongRowsTiedAtZero() {
        // 1 540 pairs over 8 windows, as the MEDIUM controls: the full view adds one event to a
        // positive pair's window with probability 0.1, about +0.04 of AUC. It is rejected at α; a
        // port of the first version, which ranked each view on its own, gave p ≈ 0.035 on three such
        // worlds while this was written (§22.30 item 12).
        val d = ZeroHeavy(groups = 1_540, strata = 8, seed = 42, leak = 0.1)
        val t = EdgeMath.pairedPermutationTest(d.full, d.ld, d.labels, d.stratum, d.group, seed = 7)
        assertTrue("the leak is small: ${t.difference}", t.difference in 0.01..0.06)
        assertTrue("a leak among tied rows must reject: diff ${t.difference}, p ${t.p}", t.rejects)
        // The same leak with extra events on rows of both labels in the full view as well (the open
        // fetch window adds co-occurrence to most non-conversations too): still rejected.
        val e = ZeroHeavy(groups = 1_540, strata = 8, seed = 43, leak = 0.5, extra = 0.2)
        val u = EdgeMath.pairedPermutationTest(e.full, e.ld, e.labels, e.stratum, e.group, seed = 7)
        assertTrue("a leak beside label-blind events must reject: diff ${u.difference}, p ${u.p}", u.difference > 0 && u.rejects)
    }

    @Test
    fun theLogisticRegressionLearnsAPlantedFeatureAndNothingFromNoise() {
        val rnd = SplittableRandom(11)
        val n = 3_000
        val y = BooleanArray(n) { rnd.nextInt(4) == 0 }
        val group = IntArray(n) { it / 3 }
        val signal = Array(n) { i -> doubleArrayOf(rnd.nextDouble(), (if (y[i]) 1.5 else 0.0) + rnd.nextDouble(), rnd.nextDouble()) }
        val noise = Array(n) { doubleArrayOf(rnd.nextDouble(), rnd.nextDouble(), rnd.nextDouble()) }
        assertTrue(EdgeMath.auc(EdgeMath.crossFittedLogistic(signal, y, group), y) > 0.9)
        val chance = EdgeMath.auc(EdgeMath.crossFittedLogistic(noise, y, group), y)
        assertTrue("noise features gave AUC $chance", chance in 0.4..0.6)
        // A constant column (every row equal, as a full-view-only feature is in LD) is ignored.
        val withConstant = Array(n) { signal[it] + doubleArrayOf(0.0) }
        assertArrayEquals(
            EdgeMath.crossFittedLogistic(signal, y, group), EdgeMath.crossFittedLogistic(withConstant, y, group), 1e-9,
        )
    }

    // ------------------------------------------------------- the views and features, by hand

    /** Three clients (0, 1, 2), each with an inbox X and a bundle namespace P. */
    private fun ns(client: Int, role: Char): ByteArray = ByteArray(32) { (client * 16 + if (role == 'X') 1 else 2).toByte() }

    private val clusters: Map<String, Pair<Int, Char>> = (0..2).flatMap { c ->
        listOf(EdgeViews.hex(ns(c, 'X')) to (c to 'X'), EdgeViews.hex(ns(c, 'P')) to (c to 'P'))
    }.toMap()

    private fun bytes(seed: Long, prefix: ByteArray? = null): ByteArray {
        val rnd = SplittableRandom(seed)
        val b = ByteArray(4_096) { rnd.nextInt(256).toByte() }
        prefix?.copyInto(b)
        return b
    }

    private fun ev(
        op: ViewOp, client: Int, target: Int, role: Char, second: Long, bytes: ByteArray? = null,
        credential: ByteArray? = null, verifier: ByteArray? = null, period: Long? = null, ttl: Long? = null,
    ) = ViewEvent(
        op = op, relaySlot = 0, client = client, circuit = "c$client/${target}$role/s$second",
        namespace = ns(target, role), second = second, bytes = bytes,
        blobHash = bytes?.let { ViewRelay.sha256(it) }, ttlSeconds = ttl ?: if (op == ViewOp.STORE) 604_800L else null,
        credential = credential, period = period, keyKind = if (op == ViewOp.REGISTER) "deposit" else null, verifier = verifier,
    )

    /**
     * A conversation between 0 and 1 (0 writes at 1 000, 1 fetches and answers at 1 100), an
     * establishment of 1 with 0's bundle at 900 (a read inside its window), a registration and a
     * publication of 0, and 2 alone; [extra] is appended.
     */
    private fun honest(reply: ByteArray = bytes(2), extra: List<ViewEvent> = emptyList()): List<ViewEvent> {
        val first = bytes(1)
        return listOf(
            ev(ViewOp.LIST, 1, 1, 'X', 900),
            ev(ViewOp.LIST, 1, 0, 'P', 900),
            ev(ViewOp.LIST, 0, 0, 'X', 1_000),
            ev(ViewOp.REGISTER, 0, 0, 'X', 1_000, verifier = byteArrayOf(1, 2, 3), period = 2_870),
            ev(ViewOp.STORE, 0, 0, 'P', 1_000, bytes = bytes(9), ttl = 2_592_000L),
            ev(ViewOp.STORE, 0, 1, 'X', 1_000, bytes = first, credential = byteArrayOf(7)),
            ev(ViewOp.LIST, 1, 1, 'X', 1_100),
            ev(ViewOp.GET, 1, 1, 'X', 1_100, bytes = first),
            ev(ViewOp.STORE, 1, 0, 'X', 1_100, bytes = reply, credential = byteArrayOf(8)),
            ev(ViewOp.LIST, 1, 1, 'X', 2_000),
            ev(ViewOp.LIST, 2, 2, 'X', 5_000),
        ) + extra
    }

    private val pairs = listOf(intArrayOf(0, 1), intArrayOf(0, 2), intArrayOf(1, 2))
    private val edges = setOf(EdgeFeatures.key(0, 1))
    private val establishments = listOf(PrivacyWorld.Establishment(reader = 1, owner = 0, at = 900))

    private fun features(views: List<EdgeEvent>): EdgeFeatures.Sample =
        EdgeFeatures.extract(views, pairs, edges, start = 0, end = 30_000, window = 30_000)

    @Test
    fun theLdProjectionKeepsLdsCategoriesAndDropsEveryFullViewOnlyField() {
        val outside = listOf(
            ev(ViewOp.LIST, 1, 1, 'X', 20_000),
            ev(ViewOp.LIST, 1, 0, 'P', 20_000),
            ev(ViewOp.LIST, 2, 0, 'X', 21_000),
            ev(ViewOp.STORE, 0, 0, 'X', 22_000, bytes = bytes(5)),
            ViewEvent(ViewOp.LIST, 0, 2, "c2/unknown", ByteArray(32) { 99 }, 23_000),
        )
        val v = EdgeViews(honest(extra = outside), clusters, establishments)
        assertEquals(16, v.full.size)
        assertEquals(12, v.ld.size)
        assertEquals(
            mapOf(
                "a bundle read outside every attempt window" to 1,
                "a read of a namespace no card names" to 1,
                "a read of another card's inbox" to 1,
                "a store into the storer's own inbox" to 1,
            ),
            v.outsideLd,
        )
        for (e in v.ld) {
            assertTrue(e.bytes == null && e.credential == null && e.verifier == null)
            assertTrue(e.size == 0 || e.size in listOf(4_096, 16_384, 65_536))
        }
        assertTrue(v.full.any { it.bytes != null } && v.full.any { it.credential != null } && v.full.any { it.verifier != null })
        // The registration keeps its period and kind in LD (the owner's register events are LD).
        assertEquals(2_870L, v.ld.single { it.op == ViewOp.REGISTER }.period)
    }

    @Test
    fun theTwoViewsGiveEqualFeaturesWhenTheFullViewAddsNothing() {
        val v = EdgeViews(honest(), clusters, establishments)
        assertTrue(v.outsideLd.isEmpty())
        val full = features(v.full)
        val ld = features(v.ld)
        for (r in 0 until full.rows) assertArrayEquals(full.x[r], ld.x[r], 0.0)
        assertTrue(full.structure.values.all { it == 0 })
        // The conversation is seen: its pair co-occurs (0's list with its store into 1's inbox, 1's
        // list and get with its reply, and 1's in-window bundle read beside its own list).
        assertEquals(Math.log1p(3.0), full.x[0][EdgeFeatures.CO0], 1e-12)
        assertEquals(Math.log1p(1.0), full.x[0][EdgeFeatures.LAG], 1e-12)
        assertEquals(0.0, full.x[1][EdgeFeatures.CO0], 0.0)
    }

    @Test
    fun aReadOutsideLdMovesOnlyTheFullViewsFeatures() {
        val v = EdgeViews(honest(extra = listOf(ev(ViewOp.LIST, 1, 1, 'X', 20_000), ev(ViewOp.LIST, 1, 0, 'P', 20_000))), clusters, establishments)
        assertEquals(mapOf("a bundle read outside every attempt window" to 1), v.outsideLd)
        assertEquals(Math.log1p(4.0), features(v.full).x[0][EdgeFeatures.CO0], 1e-12)
        assertEquals(Math.log1p(3.0), features(v.ld).x[0][EdgeFeatures.CO0], 1e-12)
    }

    @Test
    fun bytesSharedByTwoClientsNamespacesAreCountedInTheFullViewOnly() {
        val tagged = bytes(2, prefix = bytes(1).copyOf(16))
        val v = EdgeViews(honest(reply = tagged), clusters, establishments)
        val full = features(v.full)
        // A 16-byte run holds nine 8-byte windows.
        assertEquals(9, full.structure["byte windows"])
        assertTrue(full.x[0][EdgeFeatures.BYTES] > 0)
        val ld = features(v.ld)
        assertEquals(0, ld.structure["byte windows"])
        assertEquals(0.0, ld.x[0][EdgeFeatures.BYTES], 0.0)
    }

    /** The reply of [honest] with [length] bytes of the first message, from offset [from], written at offset [to]. */
    private fun sharedRun(length: Int, from: Int, to: Int): Int {
        val reply = bytes(2)
        val first = bytes(1)
        first.copyInto(reply, destinationOffset = to, startIndex = from, endIndex = from + length)
        // The bytes around the run differ, so the shared run is exactly [length] long (by chance
        // one in 128 would be longer).
        reply[to - 1] = (first[from - 1].toInt() xor 0xff).toByte()
        reply[to + length] = (first[from + length].toInt() xor 0xff).toByte()
        return features(EdgeViews(honest(reply = reply), clusters, establishments).full).structure.getValue("byte windows")
    }

    @Test
    fun theExactHalfSeesAnEightByteRunAtAnyOffsetInEitherBlob() {
        // The first version read 8 bytes at every 16th offset, so a 16-byte tag at offset 4 in both
        // blobs passed it, and an 8-byte one was seen at 1 offset in 16 (§22.30 item 12). Every offset
        // of the run in each blob, independently, for runs of 8 and 16 bytes: seen, as its windows.
        for (length in listOf(8, 16)) for (from in 0 until 16) for (to in 0 until 16) {
            assertEquals("a run of $length bytes from offset $from at offset $to", length - 7, sharedRun(length, from + 100, to + 200))
        }
        // Declared blind spot: a run shorter than a window is not seen.
        assertEquals(0, sharedRun(7, 105, 213))
    }

    @Test
    fun ldCarriesEveryTtlBucketOfSection10() {
        // §10.1's five buckets map to themselves — the first version folded 90 d into 30 d — and
        // anything between rounds up.
        for (bucket in listOf(3_600L, 86_400L, 604_800L, 2_592_000L, 7_776_000L)) assertEquals(bucket, EdgeViews.ttlBucket(bucket))
        assertEquals(3_600L, EdgeViews.ttlBucket(300L))
        assertEquals(7_776_000L, EdgeViews.ttlBucket(2_592_001L))
    }

    @Test
    fun mutualInformationKnownAnswers() {
        val x = IntArray(400) { it % 4 }
        assertEquals(2.0, EdgeMath.mutualInformationBits(x, x), 1e-12)
        assertEquals(0.0, EdgeMath.mutualInformationBits(x, IntArray(400) { (it / 4) % 2 }), 1e-12)
        assertEquals(1.0, EdgeMath.mutualInformationBits(IntArray(400) { it % 2 }, IntArray(400) { it % 2 * 7 }), 1e-12)
        // Conditional: inside each group X determines Y, and groups weigh by size.
        val g = IntArray(400) { if (it < 100) 0 else 1 }
        val y = IntArray(400) { if (it < 100) 0 else it % 4 }
        assertEquals(0.75 * 2.0, EdgeMath.conditionalMutualInformationBits(x, y, g), 1e-12)
        val (nullMean, exceeded) = EdgeMath.conditionalMiNull(x, y, g, 1.5, seed = 3, permutations = 99)
        assertTrue(nullMean < 0.1)
        assertEquals(0, exceeded)
    }
}
