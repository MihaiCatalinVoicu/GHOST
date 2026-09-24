package org.ghost.messaging.dmworld

import java.util.SplittableRandom

/**
 * The arithmetic of S-DM1, S-DM2 and S-DM4 (Phase 9 design §15.6 "Statistics"), with no world in
 * it: the rank AUC, its stratified form, the paired permutation test of an AUC difference (a sign
 * flip of each candidate pair's DeLong placement difference), a cross-fitted logistic regression and
 * plug-in mutual information. `EdgeStatisticsSelfTest` holds each of them to known answers —
 * including a test that **must reject** a planted difference, also among rows that are mostly tied
 * at zero, and must hold its level on null ones — without a native library.
 */
internal object EdgeMath {

    /** §15.6: 999 permutations. */
    const val PERMUTATIONS: Int = 999

    /**
     * §15.6: α = 0.001. With 999 permutations the smallest attainable p is 1/1000 = α, so the test
     * rejects when **no** permuted statistic reaches the observed one — `p ≤ α`, never `p < α`,
     * which with this B could never reject (the class of defect R-17 exists for; §16.1's "p ≥ 0.001"
     * is read as "passes when p > α", §22.30 item 12). What that costs: a leak whose exact p is α is
     * rejected with probability about 0.999^999 ≈ 0.37, so the verdict on a leak near the threshold
     * depends on the permutation stream; a leak far beyond it (every permuted statistic far below
     * the observed one) does not.
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
     * The outcome of [pairedPermutationTest]: the observed stratified AUCs and their difference, how
     * many permuted statistics reached it, and `p = (1 + exceeded) / (1 + B)` (the T2 rule,
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
     * full view's attacker better?), H0 being that it is not: the two AUCs are equal. The rows of one
     * stratum are compared only with each other (the "stratified" of §15.6: in the edge attack a
     * stratum is one observation window), and a **group** — every row of one candidate pair, over all
     * strata — is the unit that is permuted, since a pair's rows are not independent.
     *
     * **How.** Each view's scores are compared only with that view's own, through DeLong's
     * **placement counts** within each stratum — a positive row's count of the stratum's negatives it
     * outranks, a negative row's count of the positives that outrank it, ties one half — and a pair's
     * rows are summed into one component `ψ_g = Σ (full count − LD count)`. The observed statistic is
     * the stratified difference itself, `Σ_g ψ_g / (2 Σ_s P_s N_s)` (each comparison is counted once
     * from each side). A permutation flips the sign of each pair's component with probability ½ and
     * takes `Σ_g ±ψ_g / Σ_s P_s N_s`, whose spread is the pair-clustered DeLong variance of the
     * difference: the placements of the positives and those of the negatives each carry the whole
     * difference, so the flipped sum is not halved (halved, the null is half as wide and a port
     * rejected about a fifth of null worlds at 0.05, measured while this was written). Where the two
     * views give the same scores every component is 0 and p = 1 exactly. Deterministic in [seed].
     *
     * **Why this form** (§22.30 item 12). The first version replaced each view's scores by their
     * mid-ranks within the stratum **separately** and swapped a pair's two rank vectors. Where most
     * rows are all zero and a leak changes how many are not, the zero rows then carry different
     * mid-ranks in the two views, every swap turns zero-against-zero ties into strict comparisons, and
     * the null spreads far beyond anything the observed difference reaches: a port rejected none of
     * 200 zero-heavy null worlds at 0.05 and missed leaks at z ≈ 7. Ranking both views **together**
     * (a swap of raw scores) repairs that for a scorer that is one function of either view, but its
     * null is "the two views' scores are exchangeable", not "the AUCs are equal": a leak that also
     * adds events to non-conversations — the open fetch window adds co-occurrence to 1 352 of the
     * MEDIUM control's 1 402 negative pairs — widens its null to twice this test's (z 3.4 against 7.1
     * for the co-occurrence attacker on that world, one permuted statistic in 999 at the observed).
     * And it does not apply to the logistic attacker at all, whose two fits share no scale. This test
     * needs neither: it compares each view's ranking with itself, for fixed and fitted scorers alike.
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
        val cf = DoubleArray(full.size)
        val cl = DoubleArray(full.size)
        val den = placementCounts(full, labels, index, cf)
        placementCounts(ld, labels, index, cl)
        val groupCount = (groups.maxOrNull() ?: -1) + 1
        val psi = DoubleArray(groupCount)
        for (r in full.indices) psi[groups[r]] += cf[r] - cl[r]
        val aucFull = stratifiedAuc(full, labels, strata)
        val aucLd = stratifiedAuc(ld, labels, strata)
        if (den == 0.0) return Permutation(aucFull, aucLd, permutations, permutations)
        var total = 0.0
        for (v in psi) total += v
        val observed = total / (2 * den)
        check(Math.abs(observed - (aucFull - aucLd)) < 1e-9) { "placement sum $observed is not the AUC difference ${aucFull - aucLd}" }
        val rnd = SplittableRandom(seed)
        var exceeded = 0
        repeat(permutations) {
            var s = 0.0
            for (g in 0 until groupCount) if (rnd.nextBoolean()) s += psi[g] else s -= psi[g]
            if (s / den >= observed - 1e-12) exceeded++
        }
        return Permutation(aucFull, aucLd, exceeded, permutations)
    }

    /**
     * DeLong's placement counts of [x] within each stratum of [index], into [out]: for a positive
     * row the stratum's negatives below it plus half those tied, for a negative row the positives
     * above it plus half those tied (0 in a stratum with no positive or no negative). Returns
     * `Σ_s P_s N_s`.
     */
    private fun placementCounts(x: DoubleArray, labels: BooleanArray, index: Strata, out: DoubleArray): Double {
        var den = 0.0
        for (s in 0 until index.count) {
            val rows = index.rows(s)
            var p = 0
            var q = 0
            for (r in rows) if (labels[r]) p++ else q++
            if (p == 0 || q == 0) {
                for (r in rows) out[r] = 0.0
                continue
            }
            den += p.toDouble() * q
            val order = rows.sortedBy { x[it] }
            var negBelow = 0
            var posBelow = 0
            var i = 0
            while (i < order.size) {
                var j = i
                while (j + 1 < order.size && x[order[j + 1]] == x[order[i]]) j++
                var tiePos = 0
                var tieNeg = 0
                for (k in i..j) if (labels[order[k]]) tiePos++ else tieNeg++
                for (k in i..j) {
                    val r = order[k]
                    out[r] = if (labels[r]) negBelow + 0.5 * tieNeg else (p - posBelow - tiePos) + 0.5 * tiePos
                }
                negBelow += tieNeg
                posBelow += tiePos
                i = j + 1
            }
        }
        return den
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
