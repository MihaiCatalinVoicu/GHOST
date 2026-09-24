package org.ghost.messaging.dmworld

import java.util.SplittableRandom

/**
 * The arithmetic of S-DM1, S-DM2 and S-DM4 (Phase 9 design §15.6 "Statistics"), with no world in
 * it: the rank AUC, its stratified form, the paired permutation test of an AUC difference, a
 * cross-fitted logistic regression and plug-in mutual information. `EdgeStatisticsSelfTest` holds
 * each of them to known answers — including a permutation test that **must reject** a planted
 * difference and must not reject a null one — without a native library.
 */
internal object EdgeMath {

    /** §15.6: 999 permutations. */
    const val PERMUTATIONS: Int = 999

    /**
     * §15.6: α = 0.001. With 999 permutations the smallest attainable p is 1/1000 = α, so the test
     * rejects when **no** permuted statistic reaches the observed one — `p ≤ α`, never `p < α`,
     * which with this B could never reject (the class of defect R-17 exists for).
     */
    const val ALPHA: Double = 0.001

    // ------------------------------------------------------------------------------------ AUC

    /**
     * The rank AUC of [scores] against [labels] inside each stratum, pooled over strata by the
     * number of (positive, negative) comparisons each holds: `Σ_s P_s N_s AUC_s / Σ_s P_s N_s`, the
     * probability that a positive outranks a negative **of its own stratum** (ties count one half).
     * A stratum with no positive or no negative compares nothing and adds nothing. Returns NaN when
     * no stratum compares anything.
     */
    fun stratifiedAuc(scores: DoubleArray, labels: BooleanArray, strata: IntArray): Double {
        val index = Strata(strata)
        var num = 0.0
        var den = 0.0
        for (s in 0 until index.count) {
            val rows = index.rows(s)
            val ranks = midRanks2(DoubleArray(rows.size) { scores[rows[it]] })
            val (n, d) = aucCounts(ranks, BooleanArray(rows.size) { labels[rows[it]] })
            num += n
            den += d
        }
        return if (den == 0.0) Double.NaN else num / den
    }

    /** The plain rank AUC (one stratum). */
    fun auc(scores: DoubleArray, labels: BooleanArray): Double = stratifiedAuc(scores, labels, IntArray(scores.size))

    /**
     * Twice the mid-rank of each value (1-based), so ties stay integers: `[3.0, 1.0, 3.0]` gives
     * `[5, 2, 5]` (ranks 2.5, 1, 2.5).
     */
    fun midRanks2(values: DoubleArray): IntArray {
        val n = values.size
        val order = (0 until n).sortedBy { values[it] }
        val out = IntArray(n)
        var i = 0
        while (i < n) {
            var j = i
            while (j + 1 < n && values[order[j + 1]] == values[order[i]]) j++
            // ranks i+1 … j+1 share (i + j + 2) / 2; twice that is i + j + 2.
            for (k in i..j) out[order[k]] = i + j + 2
            i = j + 1
        }
        return out
    }

    /**
     * `(Σ over positives of (negatives below + ½ negatives tied), P·N)` for integer scores, by a
     * counting pass — the form the permutation loop runs 999 times.
     */
    private fun aucCounts(ranks2: IntArray, labels: BooleanArray): Pair<Double, Double> {
        var max = 0
        for (r in ranks2) if (r > max) max = r
        val pos = IntArray(max + 1)
        val neg = IntArray(max + 1)
        var p = 0L
        var q = 0L
        for (i in ranks2.indices) {
            if (labels[i]) { pos[ranks2[i]]++; p++ } else { neg[ranks2[i]]++; q++ }
        }
        if (p == 0L || q == 0L) return 0.0 to 0.0
        var below = 0L
        var num = 0.0
        for (v in 0..max) {
            if (pos[v] != 0) num += pos[v] * (below + 0.5 * neg[v])
            below += neg[v]
        }
        return num to (p.toDouble() * q)
    }

    /** Row indices grouped by stratum, strata numbered densely in order of first appearance. */
    class Strata(strata: IntArray) {
        private val lists: List<IntArray>
        val count: Int get() = lists.size

        init {
            val byId = LinkedHashMap<Int, ArrayList<Int>>()
            for (i in strata.indices) byId.getOrPut(strata[i]) { ArrayList() } += i
            lists = byId.values.map { it.toIntArray() }
        }

        fun rows(s: Int): IntArray = lists[s]
    }

    // ------------------------------------------------------------------- the permutation test

    /**
     * The outcome of [pairedPermutationTest]: the observed stratified AUCs and their difference,
     * how many permuted differences reached it, and `p = (1 + exceeded) / (1 + B)` (the T2 rule,
     * `stats.rs`).
     */
    class Permutation(
        val aucFull: Double,
        val aucLd: Double,
        val exceeded: Int,
        val permutations: Int,
    ) {
        val difference: Double get() = aucFull - aucLd
        val p: Double get() = (1.0 + exceeded) / (1.0 + permutations)

        /** Significantly greater than 0 at [ALPHA]: the full view gave the attacker more than LD. */
        val rejects: Boolean get() = difference > 0 && p <= ALPHA
    }

    /**
     * The stratified, paired permutation test of §15.6 for `AUC(full) − AUC(LD)` (one-sided: is the
     * full view's attacker better?). Each scorer's values are replaced by their mid-ranks **within
     * each stratum**, so the two are on one scale and exchangeable under H0 (the full view carries no
     * edge information LD does not); a permutation then swaps the two rank vectors of a **group** —
     * every row of one candidate pair, over all strata at once, so a pair's rows, which are not
     * independent, move together — with probability ½, and recomputes the stratified difference.
     * The rows of one stratum are compared only with each other (the "stratified" of §15.6: in the
     * edge attack a stratum is one observation window). Deterministic in [seed].
     */
    fun pairedPermutationTest(
        full: DoubleArray,
        ld: DoubleArray,
        labels: BooleanArray,
        strata: IntArray,
        groups: IntArray,
        seed: Long,
        permutations: Int = PERMUTATIONS,
    ): Permutation {
        require(full.size == ld.size && full.size == labels.size && full.size == strata.size && full.size == groups.size)
        val index = Strata(strata)
        val rf = IntArray(full.size)
        val rl = IntArray(full.size)
        for (s in 0 until index.count) {
            val rows = index.rows(s)
            val a = midRanks2(DoubleArray(rows.size) { full[rows[it]] })
            val b = midRanks2(DoubleArray(rows.size) { ld[rows[it]] })
            for (k in rows.indices) {
                rf[rows[k]] = a[k]
                rl[rows[k]] = b[k]
            }
        }
        val groupCount = (groups.maxOrNull() ?: -1) + 1
        // The loop below runs B times over every row: its buffers are allocated once.
        var largest = 0
        for (s in 0 until index.count) largest = maxOf(largest, index.rows(s).size)
        val posF = LongArray(2 * largest + 2)
        val negF = LongArray(2 * largest + 2)
        val posL = LongArray(2 * largest + 2)
        val negL = LongArray(2 * largest + 2)
        fun statistic(swap: BooleanArray?): Double {
            var nf = 0.0
            var nl = 0.0
            var den = 0.0
            for (s in 0 until index.count) {
                val rows = index.rows(s)
                val top = 2 * rows.size + 1
                java.util.Arrays.fill(posF, 0, top + 1, 0L)
                java.util.Arrays.fill(negF, 0, top + 1, 0L)
                java.util.Arrays.fill(posL, 0, top + 1, 0L)
                java.util.Arrays.fill(negL, 0, top + 1, 0L)
                var p = 0L
                var q = 0L
                for (r in rows) {
                    val swapped = swap != null && swap[groups[r]]
                    val a = if (swapped) rl[r] else rf[r]
                    val b = if (swapped) rf[r] else rl[r]
                    if (labels[r]) { posF[a]++; posL[b]++; p++ } else { negF[a]++; negL[b]++; q++ }
                }
                if (p == 0L || q == 0L) continue
                var belowF = 0L
                var belowL = 0L
                for (v in 0..top) {
                    if (posF[v] != 0L) nf += posF[v] * (belowF + 0.5 * negF[v])
                    if (posL[v] != 0L) nl += posL[v] * (belowL + 0.5 * negL[v])
                    belowF += negF[v]
                    belowL += negL[v]
                }
                den += p.toDouble() * q
            }
            return if (den == 0.0) Double.NaN else (nf - nl) / den
        }
        val observed = statistic(null)
        val rnd = SplittableRandom(seed)
        var exceeded = 0
        val swap = BooleanArray(groupCount)
        repeat(permutations) {
            for (g in 0 until groupCount) swap[g] = rnd.nextBoolean()
            if (statistic(swap) >= observed - 1e-12) exceeded++
        }
        return Permutation(
            aucFull = stratifiedAuc(full, labels, strata),
            aucLd = stratifiedAuc(ld, labels, strata),
            exceeded = exceeded,
            permutations = permutations,
        )
    }

    // ------------------------------------------------------------------ logistic regression

    /**
     * Out-of-fold scores of an L2-regularised logistic regression (Newton's method on standardised
     * features, the intercept unpenalised): rows are assigned to [folds] folds **by their group**
     * (every row of one candidate pair in one fold, over every window), each fold is scored by a
     * model fitted on the others, and nothing about a scored row — not its label, not its features'
     * mean or spread — enters the model that scores it. Identical training rows are fitted once
     * with their count as a weight (most (window, pair) rows are all zeros).
     */
    fun crossFittedLogistic(x: Array<DoubleArray>, y: BooleanArray, groups: IntArray, folds: Int = 5, lambda: Double = 1.0): DoubleArray {
        val n = x.size
        val out = DoubleArray(n)
        if (n == 0) return out
        val d = x[0].size
        val foldOf = IntArray(n) { Math.floorMod(mix(groups[it].toLong()), folds) }
        for (fold in 0 until folds) {
            val mean = DoubleArray(d)
            val sd = DoubleArray(d)
            var nt = 0
            for (i in 0 until n) if (foldOf[i] != fold) {
                nt++
                for (k in 0 until d) mean[k] += x[i][k]
            }
            if (nt == 0) continue
            for (k in 0 until d) mean[k] /= nt
            for (i in 0 until n) if (foldOf[i] != fold) for (k in 0 until d) sd[k] += (x[i][k] - mean[k]).let { it * it }
            for (k in 0 until d) sd[k] = Math.sqrt(sd[k] / nt)
            // Distinct training rows with their weights.
            val weights = LinkedHashMap<Row, DoubleArray>()
            for (i in 0 until n) if (foldOf[i] != fold) {
                val w = weights.getOrPut(Row(x[i], y[i])) { DoubleArray(1) }
                w[0] += 1.0
            }
            val rows = weights.keys.toList()
            val z = Array(rows.size) { r -> standardise(rows[r].x, mean, sd) }
            val t = DoubleArray(rows.size) { if (rows[it].y) 1.0 else 0.0 }
            val w = DoubleArray(rows.size) { weights.getValue(rows[it])[0] }
            val beta = newton(z, t, w, lambda)
            for (i in 0 until n) if (foldOf[i] == fold) {
                val s = standardise(x[i], mean, sd)
                var eta = beta[0]
                for (k in 0 until d) eta += beta[k + 1] * s[k]
                out[i] = eta
            }
        }
        return out
    }

    private class Row(val x: DoubleArray, val y: Boolean) {
        private val hash = 31 * x.contentHashCode() + y.hashCode()
        override fun equals(other: Any?): Boolean = other is Row && other.y == y && other.x.contentEquals(x)
        override fun hashCode(): Int = hash
    }

    private fun standardise(x: DoubleArray, mean: DoubleArray, sd: DoubleArray): DoubleArray =
        DoubleArray(x.size) { k -> if (sd[k] > 1e-12) (x[k] - mean[k]) / sd[k] else 0.0 }

    /** Weighted L2 logistic regression by Newton's method; returns (intercept, coefficients…). */
    fun newton(z: Array<DoubleArray>, t: DoubleArray, w: DoubleArray, lambda: Double, iterations: Int = 50): DoubleArray {
        val d = if (z.isEmpty()) 0 else z[0].size
        val beta = DoubleArray(d + 1)
        repeat(iterations) {
            val g = DoubleArray(d + 1)
            val h = Array(d + 1) { DoubleArray(d + 1) }
            val v = DoubleArray(d + 1)
            for (i in z.indices) {
                v[0] = 1.0
                for (k in 0 until d) v[k + 1] = z[i][k]
                var eta = 0.0
                for (k in 0..d) eta += beta[k] * v[k]
                val p = 1.0 / (1.0 + Math.exp(-eta))
                val c = w[i] * p * (1 - p)
                val r = w[i] * (t[i] - p)
                for (k in 0..d) {
                    g[k] += r * v[k]
                    if (v[k] != 0.0) for (l in 0..d) h[k][l] += c * v[k] * v[l]
                }
            }
            for (k in 1..d) {
                g[k] -= lambda * beta[k]
                h[k][k] += lambda
            }
            h[0][0] += 1e-9
            val step = solve(h, g)
            var largest = 0.0
            for (k in 0..d) {
                beta[k] += step[k]
                largest = maxOf(largest, Math.abs(step[k]))
            }
            if (largest < 1e-9) return beta
        }
        return beta
    }

    private fun solve(a0: Array<DoubleArray>, b0: DoubleArray): DoubleArray {
        val n = b0.size
        val a = Array(n) { a0[it].copyOf() }
        val b = b0.copyOf()
        for (c in 0 until n) {
            var pivot = c
            for (r in c + 1 until n) if (Math.abs(a[r][c]) > Math.abs(a[pivot][c])) pivot = r
            val tmp = a[c]; a[c] = a[pivot]; a[pivot] = tmp
            val tb = b[c]; b[c] = b[pivot]; b[pivot] = tb
            if (Math.abs(a[c][c]) < 1e-15) continue
            for (r in c + 1 until n) {
                val m = a[r][c] / a[c][c]
                if (m == 0.0) continue
                for (k in c until n) a[r][k] -= m * a[c][k]
                b[r] -= m * b[c]
            }
        }
        val x = DoubleArray(n)
        for (r in n - 1 downTo 0) {
            if (Math.abs(a[r][r]) < 1e-15) continue
            var s = b[r]
            for (k in r + 1 until n) s -= a[r][k] * x[k]
            x[r] = s / a[r][r]
        }
        return x
    }

    /** A fixed 64-bit mix (SplitMix64's finaliser), so fold assignment does not follow pair order. */
    fun mix(v: Long): Int {
        var z = v + -0x61c8864680b583ebL
        z = (z xor (z ushr 30)) * -0x40a7b892e31b1a47L
        z = (z xor (z ushr 27)) * -0x6b2fb644ecceee15L
        z = z xor (z ushr 31)
        return (z ushr 33).toInt()
    }

    // ---------------------------------------------------------------- mutual information

    /** Plug-in mutual information of two discrete samples, in bits. */
    fun mutualInformationBits(x: IntArray, y: IntArray): Double {
        require(x.size == y.size)
        val n = x.size.toDouble()
        if (n == 0.0) return 0.0
        val joint = HashMap<Long, Int>()
        val px = HashMap<Int, Int>()
        val py = HashMap<Int, Int>()
        for (i in x.indices) {
            joint.merge((x[i].toLong() shl 32) or (y[i].toLong() and 0xffffffffL), 1, Int::plus)
            px.merge(x[i], 1, Int::plus)
            py.merge(y[i], 1, Int::plus)
        }
        var mi = 0.0
        for ((k, c) in joint.toSortedMap()) {
            val a = (k shr 32).toInt()
            val b = k.toInt()
            mi += (c / n) * Math.log(c * n / (px.getValue(a).toDouble() * py.getValue(b))) / Math.log(2.0)
        }
        return maxOf(0.0, mi)
    }

    /** `I(X; Y | G) = Σ_g (n_g / n) · I_g(X; Y)`, in bits. */
    fun conditionalMutualInformationBits(x: IntArray, y: IntArray, group: IntArray): Double {
        val index = Strata(group)
        var total = 0.0
        for (s in 0 until index.count) {
            val rows = index.rows(s)
            total += rows.size * mutualInformationBits(IntArray(rows.size) { x[rows[it]] }, IntArray(rows.size) { y[rows[it]] })
        }
        return if (x.isEmpty()) 0.0 else total / x.size
    }

    /**
     * A permutation null for [conditionalMutualInformationBits]: X shuffled **within each group**
     * (an inbox's TTL buckets over its own stores), B times; returns (the mean null value, how many
     * reached the observed one).
     */
    fun conditionalMiNull(x: IntArray, y: IntArray, group: IntArray, observed: Double, seed: Long, permutations: Int = PERMUTATIONS): Pair<Double, Int> {
        val index = Strata(group)
        val rnd = SplittableRandom(seed)
        val shuffled = x.copyOf()
        var sum = 0.0
        var exceeded = 0
        repeat(permutations) {
            for (s in 0 until index.count) {
                val rows = index.rows(s)
                for (k in rows.size - 1 downTo 1) {
                    val j = rnd.nextInt(k + 1)
                    val a = shuffled[rows[k]]; shuffled[rows[k]] = shuffled[rows[j]]; shuffled[rows[j]] = a
                }
            }
            val v = conditionalMutualInformationBits(shuffled, y, group)
            sum += v
            if (v >= observed - 1e-12) exceeded++
        }
        return sum / permutations to exceeded
    }
}
