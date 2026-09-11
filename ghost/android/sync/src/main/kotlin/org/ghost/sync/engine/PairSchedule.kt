package org.ghost.sync.engine

import org.ghost.sync.port.PairKey
import org.ghost.sync.port.RandomSources
import org.ghost.sync.port.SchedulePurpose

/**
 * Per-(relay, namespace) event times (design §6.1, §11.2 #12). All times are monotonic milliseconds.
 *
 * Foreground: `t₀ = anchor + T·u(p, START, 0)` and `t_{k+1} = t_k + T·(0.5 + u(p, STEP, k))`, where
 * `u` is the keyed PRF of [RandomSources.schedule] and the anchor is the time the pair joined the
 * session. A pair's times depend only on the key, the pair and its anchor: not on other pairs, on
 * activity, or on how long events take (T19). Background: one event at
 * `jobStart + W·u(p, BACKGROUND_OFFSET, job)`, so the order of pairs within a job is a keyed random
 * permutation.
 *
 * Beyond [TrafficPolicy.maxReadPairs] read pairs, pairs are ranked by `u(p, ROUND_ROBIN, 0)` and
 * split into `m = ceil(n / cap)` groups by rank; a pair acts only at the events whose index is its
 * group modulo m, which gives each pair one event per `T × m` on average and at most `cap` pairs
 * per group. A pair's underlying times never change with m; only which indices act does.
 *
 * Open so the exit-gate harness can substitute a shared-tick mutant (design §8.8 M13).
 */
internal open class PairSchedule(private val random: RandomSources, private val policy: TrafficPolicy) {

    open fun firstTime(pair: PairKey, anchor: Long): Long =
        anchor + scaled(policy.intervalMillis, random.schedule(pair, SchedulePurpose.FOREGROUND_START, 0))

    /** Time of event [index] + 1, given event [index] at [time]. */
    open fun nextTime(pair: PairKey, index: Long, time: Long): Long =
        time + scaled(policy.intervalMillis, 0.5 + random.schedule(pair, SchedulePurpose.FOREGROUND_STEP, index))

    open fun backgroundTime(pair: PairKey, jobStart: Long, job: Long): Long =
        jobStart + scaled(policy.backgroundWindowMillis, random.schedule(pair, SchedulePurpose.BACKGROUND_OFFSET, job))

    open fun rank(pair: PairKey): Double = random.schedule(pair, SchedulePurpose.ROUND_ROBIN, 0)

    /** Foreground time of event [index] (for tests): iterates from the first event. */
    fun time(pair: PairKey, anchor: Long, index: Long): Long {
        require(index >= 0) { "index out of range" }
        var t = firstTime(pair, anchor)
        for (k in 0 until index) t = nextTime(pair, k, t)
        return t
    }

    /** Number of round-robin groups for [pairCount] read pairs (1 up to the cap). */
    fun groupCount(pairCount: Int): Int = maxOf(1, (pairCount + policy.maxReadPairs - 1) / policy.maxReadPairs)

    /**
     * Group of every pair: its rank (by [rank], ties by relay id then namespace bytes) modulo the
     * group count, so groups differ in size by at most one.
     */
    fun groups(pairs: Collection<PairKey>): Map<PairKey, Int> {
        val m = groupCount(pairs.size)
        if (m == 1) return pairs.associateWith { 0 }
        val ordered = pairs.map { Ranked(it, rank(it)) }.sortedWith(RANKED_ORDER)
        return ordered.withIndex().associate { (i, r) -> r.pair to i % m }
    }

    private class Ranked(val pair: PairKey, val rank: Double)

    override fun toString(): String = "PairSchedule"

    companion object {
        /** `span × u` in whole milliseconds, u in [0, 1.5). */
        fun scaled(span: Long, u: Double): Long = Math.floor(span * u).toLong()

        /** Deterministic order of pairs: relay id, then namespace bytes (unsigned). */
        val PAIR_ORDER: Comparator<PairKey> = Comparator { a, b ->
            val byRelay = a.relayId.value.compareTo(b.relayId.value)
            if (byRelay != 0) byRelay else compareUnsigned(a.namespace.raw, b.namespace.raw)
        }

        private val RANKED_ORDER: Comparator<Ranked> = Comparator { a, b ->
            val byRank = a.rank.compareTo(b.rank)
            if (byRank != 0) byRank else PAIR_ORDER.compare(a.pair, b.pair)
        }

        private fun compareUnsigned(a: ByteArray, b: ByteArray): Int {
            for (i in 0 until minOf(a.size, b.size)) {
                val c = (a[i].toInt() and 0xff).compareTo(b[i].toInt() and 0xff)
                if (c != 0) return c
            }
            return a.size.compareTo(b.size)
        }
    }
}
