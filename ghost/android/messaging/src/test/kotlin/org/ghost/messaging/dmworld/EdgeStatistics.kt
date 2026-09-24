package org.ghost.messaging.dmworld

import org.ghost.messaging.DmWorld

/**
 * S-DM1 (gating), S-DM2 (reported) and S-DM4 (reported) over one privacy world (Phase 9 design
 * §15.6 "Statistics"; §22.30 records what they are, what they can and cannot see here, and what is
 * deferred).
 *
 * **The attackers** (one family, [EdgeFeatures], run once on the full view and once on LD's):
 *  - **co-occurrence plus fetch → store lag** — a fixed score, the sum of the four timing features
 *    that tie an inbound request of one client to an own request of another (the same second,
 *    60 s, 600 s, and a GET of the own inbox followed by a deposit elsewhere);
 *  - **reply-timing survival** — deposits alone: after a deposit into b's inbox, how soon the next
 *    into a's arrives, against a Poisson arrival at a's rate (L7-D1's SDA, stores only);
 *  - **a logistic regression over every feature** — the fifteen columns of [EdgeFeatures.NAMES],
 *    the structure of the full view's own fields included, cross-fitted over five folds of pairs.
 *
 * **S-DM1**: for each attacker, `AUC(full) − AUC(LD)` by the stratified paired permutation test of
 * [EdgeMath.pairedPermutationTest] (999 permutations, α = 0.001, strata = the observation windows, a
 * permutation flips the sign of a pair's placement difference). It **fails** when any of the three
 * rejects — no correction for three: the family's false-alarm rate is at most 0.003, and on a world
 * whose two views give equal features every p is exactly 1 — when the full view's fields carry any
 * value across two clients' namespaces (its exact half), or below the floor (n ≥ 100 pairs and 100
 * conversations, F8 §19.24 point 6).
 */
internal object EdgeStatistics {

    /** F8 §19.24 point 6: a statistical check with n < 100 fails rather than passes. */
    const val FLOOR: Int = 100

    /** The observation window (a stratum) at the PR and MEDIUM scales: six hours. */
    const val WINDOW_SECONDS: Long = 6 * DmWorld.HOUR

    /**
     * The most candidate pairs scored: every pair up to it (the PR world's 120 clients make 7 140),
     * and above it every conversation and a fixed hash sample of the rest (the gate world's 600 make
     * 179 700, which over 168 windows would be 30 million units). An AUC does not depend on how many
     * negatives are sampled, only on which, and the sample is the pair's hash, never its features.
     */
    const val PAIR_CAP: Int = 8_000

    /** The clause of a line whose scale and seed have no recorded baseline (dm-report-check.sh pins it). */
    const val NO_BASELINE: String =
        "no baseline recorded for this scale and seed (only the PR world of seed 5eed0001 has been measured, §22.30)"

    /** The attackers, in the order the lines print them. */
    val MEMBERS: List<String> = listOf("co-occurrence+lag", "reply-timing", "logistic")

    /** Both views of one world, featurised; computed once and shared by the three statistics. */
    class Views(
        world: PrivacyWorld,
        val window: Long = WINDOW_SECONDS,
        pairCap: Int = Int.MAX_VALUE,
        keepOutside: (Int) -> Boolean = { true },
    ) {
        val views = EdgeViews(world, keepOutside)
        val edges: Set<Long> = world.acceptedEdges.map { (u, v) -> EdgeFeatures.key(u, v) }.toSet()
        val pairs: List<IntArray> = pairsOf(world, edges, pairCap)
        val start = world.config.startSeconds
        val end = world.end
        val full = EdgeFeatures.extract(views.full, pairs, edges, start, end, window)
        val ld = EdgeFeatures.extract(views.ld, pairs, edges, start, end, window)
        val edgesScored: Int = pairs.count { EdgeFeatures.key(it[0], it[1]) in edges }

        /** The three attackers' scores on one view. */
        fun scores(sample: EdgeFeatures.Sample): List<DoubleArray> = listOf(
            DoubleArray(sample.rows) { r ->
                val x = sample.x[r]
                x[EdgeFeatures.CO0] + x[EdgeFeatures.CO60] + x[EdgeFeatures.CO600] + x[EdgeFeatures.LAG]
            },
            sample.column(EdgeFeatures.REPLY),
            EdgeMath.crossFittedLogistic(sample.x, sample.label, sample.group),
        )

        val fullScores: List<DoubleArray> by lazy { scores(full) }
        val ldScores: List<DoubleArray> by lazy { scores(ld) }
    }

    /** Every activated client pair; above [cap], every conversation and a fixed hash sample of the rest. */
    fun pairsOf(world: PrivacyWorld, edges: Set<Long>, cap: Int): List<IntArray> {
        val clients = world.truth.clients.values.filter { it.inboxNamespace != null }.map { it.index }.sorted()
        val all = ArrayList<IntArray>()
        for (i in clients.indices) for (j in i + 1 until clients.size) all += intArrayOf(clients[i], clients[j])
        if (all.size <= cap) return all
        val positives = all.filter { EdgeFeatures.key(it[0], it[1]) in edges }
        val negatives = all.filter { EdgeFeatures.key(it[0], it[1]) !in edges }
            .sortedBy { EdgeMath.mix(EdgeFeatures.key(it[0], it[1])) }
            .take(maxOf(0, cap - positives.size))
        return positives + negatives
    }

    // ------------------------------------------------------------------------------ S-DM1

    class Sdm1(
        val pairs: Int,
        val edges: Int,
        val windows: Int,
        val windowHours: Long,
        val tests: List<EdgeMath.Permutation>,
        val fullEvents: Int,
        val ldEvents: Int,
        val outsideLd: Map<String, Int>,
        val structure: Map<String, Int>,
        val wholeRun: List<Pair<Double, Double>>,
        /** Units whose feature vectors differ between the two views. */
        val differing: Int,
        val rows: Int,
    ) {
        val floorMet: Boolean get() = pairs >= FLOOR && edges >= FLOOR
        val flagged: List<String> get() = MEMBERS.filterIndexed { i, _ -> tests[i].rejects }
        val structureClean: Boolean get() = structure.values.all { it == 0 }
        val measured: Boolean get() = tests.all { !it.aucFull.isNaN() && !it.aucLd.isNaN() }
        val passed: Boolean get() = floorMet && measured && flagged.isEmpty() && structureClean

        fun line(): String =
            "dm S-DM1: ${if (passed) "PASS" else "FAIL"} full view vs LD over $windows windows of $windowHours h " +
                "(n=$pairs pairs, $edges conversations; stratified paired permutation test of each pair's placement " +
                "difference, ${EdgeMath.PERMUTATIONS} sign flips, alpha=${EdgeMath.ALPHA}): " +
                MEMBERS.indices.joinToString(", ") { i ->
                    val t = tests[i]
                    "${MEMBERS[i]} AUC full ${f4(t.aucFull)} LD ${f4(t.aucLd)} (diff ${sign(t.difference)}, p=${f3(t.p)})"
                } +
                "; features differ between the views on $differing of $rows units; LD view $ldEvents of $fullEvents events (${outsideLd.values.sum()} outside LD's categories" +
                (if (outsideLd.isEmpty()) "" else ": " + outsideLd.entries.joinToString(", ") { "${it.value} ${it.key}" }) +
                "; bytes, exact sizes and TTLs, credentials and verifiers dropped); full-view-only structure across two " +
                "clients' namespaces (8-byte windows at every offset of the stored and served bytes, credentials, verifiers, " +
                "blobs): " + structure.entries.joinToString(", ") { "${it.value} ${it.key}" } +
                "; whole run as one window: " +
                MEMBERS.indices.joinToString(", ") { i -> "${MEMBERS[i]} full ${f4(wholeRun[i].first)} LD ${f4(wholeRun[i].second)}" } +
                (if (flagged.isEmpty()) "" else " (FLAGGED by ${flagged.joinToString()})") +
                (if (structureClean) "" else " (THE FULL VIEW'S FIELDS LINK TWO CLIENTS)") +
                (if (floorMet) "" else " (below the n >= $FLOOR floor)") +
                (if (measured) "" else " (NOTHING COMPARED)")
    }

    /** The index of the logistic attacker in [MEMBERS] (fitted on each view; the others are fixed scores). */
    const val LOGISTIC: Int = 2

    fun sdm1(views: Views, seed: Long, whole: Views? = null): Sdm1 {
        val tests = MEMBERS.indices.map { i ->
            EdgeMath.pairedPermutationTest(
                views.fullScores[i], views.ldScores[i], views.full.label, views.full.stratum, views.full.group, seed + i,
            )
        }
        val wholeRun = MEMBERS.indices.map { i ->
            if (whole == null) Double.NaN to Double.NaN
            else EdgeMath.auc(whole.fullScores[i], whole.full.label) to EdgeMath.auc(whole.ldScores[i], whole.ld.label)
        }
        return Sdm1(
            pairs = views.pairs.size,
            edges = views.edgesScored,
            windows = views.full.windows,
            windowHours = views.window / DmWorld.HOUR,
            tests = tests,
            fullEvents = views.views.full.size,
            ldEvents = views.views.ld.size,
            outsideLd = views.views.outsideLd,
            structure = views.full.structure,
            wholeRun = wholeRun,
            differing = (0 until views.full.rows).count { !views.full.x[it].contentEquals(views.ld.x[it]) },
            rows = views.full.rows,
        )
    }

    // ------------------------------------------------------------------------------ S-DM2

    /** One TTL class of S-DM2: the conversations whose timer the users set lands in [label]'s bucket. */
    class TtlClass(
        val label: String,
        val conversations: Int,
        val auc: Double,
        val median: Int?,
        val p90: Int?,
        val max: Int?,
        val censored: Int,
    )

    class Sdm2(
        val pairs: Int,
        val edges: Int,
        val windows: Int,
        val windowHours: Long,
        val ld: List<Double>,
        val wholeRun: List<Double>,
        val classes: List<TtlClass>,
        val baseline: Baseline?,
    ) {
        val floorMet: Boolean get() = pairs >= FLOOR && edges >= FLOOR
        /** The strongest LD attacker of the three: what S-DM2 records and the regression rule compares. */
        val strongest: Double get() = ld.filter { !it.isNaN() }.maxOrNull() ?: Double.NaN

        fun line(): String =
            "dm S-DM2: REPORTED LD attacker, STANDARD only (HIGH mode is not built), over $windows windows of " +
                "$windowHours h (n=$pairs pairs, $edges conversations): " +
                MEMBERS.indices.joinToString(", ") { "${MEMBERS[it]} AUC ${f4(ld[it])}" } + ", strongest ${f4(strongest)}" +
                "; whole run as one window: " + MEMBERS.indices.joinToString(", ") { "${MEMBERS[it]} ${f4(wholeRun[it])}" } +
                "; per TTL class (the strongest attacker's AUC over the windows; messages until the co-occurrence attacker singles the " +
                "conversation out, median/90th/max, censored): " +
                classes.joinToString("; ") { c ->
                    "${c.label} (${c.conversations} conversations${if (c.conversations < FLOOR) ", below the floor: reported only" else ""}) " +
                        "${f4(c.auc)}, ${c.median ?: "-"}/${c.p90 ?: "-"}/${c.max ?: "-"}, ${c.censored} censored"
                } +
                "; " + (baseline?.let { b ->
                    val within = strongest <= b.value + REGRESSION &&
                        b.classes.all { (label, v) -> classes.firstOrNull { it.label == label }?.auc?.let { it <= v + REGRESSION } == true }
                    "baseline strongest ${f4(b.value)}" + b.classes.entries.joinToString("") { " and ${it.key} class ${f4(it.value)}" } +
                        " (${b.what}): ${if (within) "within" else "ABOVE"} baseline + $REGRESSION"
                } ?: NO_BASELINE) +
                (if (floorMet) "" else " (below the n >= $FLOOR floor)")
    }

    /** §15.6: "the report check fails on a regression above the recorded baseline + 0.02". */
    const val REGRESSION: Double = 0.02

    /**
     * A recorded baseline: the strongest LD attacker's AUC, the same for each TTL class that held at
     * least [FLOOR] conversations in the recorded run (a class below the floor is reported only), and
     * what it is a baseline of.
     */
    class Baseline(val value: Double, val what: String, val classes: Map<String, Double> = emptyMap())

    fun sdm2(views: Views, whole: Views?, world: PrivacyWorld, baseline: Baseline?): Sdm2 {
        val ld = MEMBERS.indices.map { EdgeMath.stratifiedAuc(views.ldScores[it], views.ld.label, views.ld.stratum) }
        val wholeRun = MEMBERS.indices.map { i -> whole?.let { EdgeMath.auc(it.ldScores[i], it.ld.label) } ?: Double.NaN }
        val rounds = roundsToSingleOut(views, world)
        val best = ld.indices.filter { !ld[it].isNaN() }.maxByOrNull { ld[it] } ?: 0
        val classOf = HashMap<Long, String>()
        for ((u, v) in world.acceptedEdges) classOf[EdgeFeatures.key(u, v)] = ttlLabel(Joins.table(world.timerCodeOf(u, v)))
        val classes = TTL_LABELS.map { label ->
            val keys = classOf.filterValues { it == label }.keys
            val rows = (0 until views.ld.rows).filter { r ->
                val p = views.pairs[views.ld.group[r]]
                val k = EdgeFeatures.key(p[0], p[1])
                !views.ld.label[r] || k in keys
            }
            val scores = DoubleArray(rows.size) { views.ldScores[best][rows[it]] }
            val labels = BooleanArray(rows.size) { views.ld.label[rows[it]] }
            val strata = IntArray(rows.size) { views.ld.stratum[rows[it]] }
            val found = keys.mapNotNull { rounds[it] }.sorted()
            TtlClass(
                label = label,
                conversations = keys.count { k -> views.pairs.any { EdgeFeatures.key(it[0], it[1]) == k } },
                auc = if (rows.isEmpty()) Double.NaN else EdgeMath.stratifiedAuc(scores, labels, strata),
                median = found.getOrNull(found.size / 2),
                p90 = found.getOrNull(((found.size - 1) * 9) / 10),
                max = found.lastOrNull(),
                censored = keys.count { it !in rounds },
            )
        }
        return Sdm2(views.pairs.size, views.edgesScored, views.ld.windows, views.window / DmWorld.HOUR, ld, wholeRun, classes, baseline)
    }

    /** The classes a conversation's timer can land in (§10.1: a DM never uses the 90 d bucket). */
    private val TTL_LABELS = listOf("1 h", "1 d", "7 d", "30 d")

    private fun ttlLabel(ttl: Long): String = when (EdgeViews.ttlBucket(ttl)) {
        DmWorld.HOUR -> "1 h"
        DmWorld.DAY -> "1 d"
        7 * DmWorld.DAY -> "7 d"
        30 * DmWorld.DAY -> "30 d"
        else -> error("a conversation timer of TTL $ttl is in no DM class")
    }

    /**
     * Rounds to single out (§15.6, §21.11 point 2): for each conversation, the number of its messages
     * after which the **LD** co-occurrence attacker, counting from the world's start, scores the pair
     * above every pair of either client that is not a conversation — the SDA of L7-D1 with the
     * session co-occurrence of LD. A conversation never singled out within its messages is censored
     * (absent from the map). The messages are the world's record (ground truth, used to count, never
     * to score); the scores are the LD view's alone.
     */
    fun roundsToSingleOut(views: Views, world: PrivacyWorld): Map<Long, Int> {
        // The conversation's messages: distinct deposits between its two clients, in time order.
        val owner = views.views.clusters
        val messages = HashMap<Long, MutableList<Long>>()
        val seen = HashSet<String>()
        for (e in world.relay.events) {
            if (e.op != ViewOp.STORE) continue
            val ns = EdgeViews.hex(e.namespace)
            val c = owner[ns] ?: continue
            if (c.second != 'X' || c.first == e.client) continue
            val k = EdgeFeatures.key(c.first, e.client)
            if (k !in views.edges) continue
            val blob = e.blobHash?.let { EdgeViews.hex(it) } ?: continue
            if (!seen.add("$ns/$blob")) continue
            messages.getOrPut(k) { ArrayList() } += e.second
        }
        // The LD co-occurrence score, accumulated second by second.
        val bySecond = java.util.TreeMap<Long, MutableList<EdgeEvent>>()
        val dedup = HashSet<String>()
        for (e in views.views.ld) {
            if (e.cluster < 0) continue
            if (!dedup.add("${e.op}/${e.namespace}/${e.second}/${e.blob}")) continue
            bySecond.getOrPut(e.second) { ArrayList() } += e
        }
        val checkpoints = java.util.TreeMap<Long, MutableList<Pair<Long, Int>>>()
        for ((k, times) in messages) for ((i, t) in times.sorted().withIndex()) {
            checkpoints.getOrPut(t) { ArrayList() } += k to (i + 1)
        }
        val score = HashMap<Long, Int>()
        val maxNonEdge = HashMap<Int, Int>()
        val out = HashMap<Long, Int>()
        val seconds = java.util.TreeSet<Long>().apply { addAll(bySecond.keys); addAll(checkpoints.keys) }
        for (t in seconds) {
            val events = bySecond[t].orEmpty()
            val owners = HashSet<Int>()
            for (e in events) if (ownRequest(e)) owners += e.cluster
            for (e in events) if (!ownRequest(e)) {
                for (a in owners) {
                    if (a == e.cluster) continue
                    val k = EdgeFeatures.key(a, e.cluster)
                    val s = score.merge(k, 1, Int::plus)!!
                    if (k !in views.edges) {
                        maxNonEdge.merge(a, s) { x, y -> maxOf(x, y) }
                        maxNonEdge.merge(e.cluster, s) { x, y -> maxOf(x, y) }
                    }
                }
            }
            for ((k, n) in checkpoints[t].orEmpty()) {
                if (k in out) continue
                val a = (k ushr 32).toInt()
                val b = k.toInt()
                val s = score[k] ?: 0
                if (s > 0 && s > (maxNonEdge[a] ?: 0) && s > (maxNonEdge[b] ?: 0)) out[k] = n
            }
        }
        return out
    }

    private fun ownRequest(e: EdgeEvent): Boolean = when (e.op) {
        ViewOp.LIST, ViewOp.GET -> e.role == 'X'
        ViewOp.REGISTER -> true
        ViewOp.STORE -> e.role == 'P'
    }

    // ------------------------------------------------------------------------------ S-DM4

    class Sdm4(
        val deposits: Int,
        val inboxes: Int,
        val within: Double,
        val withinNull: Double,
        val withinExceeded: Int,
        val pairs: Int,
        val pairing: Double,
        val pairingNull: Double,
        val pairingExceeded: Int,
        val baseline: Pair<Double, Double>?,
        val baselineWhat: String?,
    ) {
        val floorMet: Boolean get() = deposits >= FLOOR && pairs >= FLOOR
        private fun p(exceeded: Int): Double = (1.0 + exceeded) / (1.0 + EdgeMath.PERMUTATIONS)
        val withinP: Double get() = p(withinExceeded)
        val pairingP: Double get() = p(pairingExceeded)

        fun line(): String =
            "dm S-DM4: REPORTED I(TTL bucket; conversation | inbox) = ${"%.4f".format(within)} bits over $deposits deposits " +
                "in $inboxes inboxes (permutation null ${"%.4f".format(withinNull)}, p=${"%.3f".format(p(withinExceeded))}); " +
                "cross-inbox pairing I(the two inboxes' shared non-default TTL bucket; conversation) = ${"%.4f".format(pairing)} " +
                "bits over $pairs pairs (permutation null ${"%.4f".format(pairingNull)}, p=${"%.3f".format(p(pairingExceeded))}); " +
                (
                    baseline?.let { (w, q) ->
                        val within = this.within <= w + REGRESSION && pairing <= q + REGRESSION
                        "baseline ${"%.4f".format(w)} and ${"%.4f".format(q)} bits ($baselineWhat): " +
                            "${if (within) "within" else "ABOVE"} baseline + $REGRESSION"
                    } ?: NO_BASELINE
                    ) +
                (if (floorMet) "" else " (below the n >= $FLOOR floor)")
    }

    /**
     * S-DM4 (§15.6, §21.11 point 2): how much an inbox's TTL buckets say about which conversation a
     * deposit belongs to — the partition L7-D4 declares — and how much two inboxes' shared
     * non-default bucket says about whether they converse (the cross-inbox pairing). Plug-in mutual
     * information, each beside a permutation null (the TTL buckets shuffled within each inbox; the
     * conversation labels shuffled over the pairs), 999 permutations each. The conversation of a
     * deposit is its sender (ground truth, the label being measured against). Held to the recorded
     * baseline + 0.02 bits by §16.1's rule, where one is recorded.
     *
     * **What it does not separate** (§22.30 item 7). It measures each deposit's bucket, not the
     * TTL-bucket **sequence** §15.6 names. The pairing null shuffles the labels over all pairs, which
     * keeps no degree: inboxes of busy clients receive more buckets and busy clients converse more,
     * so its p says the shared bucket and the label are not independent, not that a TTL residue
     * beyond degree and volume exists. And a plug-in estimate grows with the deposits behind it, so
     * two worlds' values are compared by their excess over their own nulls, not by the raw numbers.
     */
    fun sdm4(views: Views, world: PrivacyWorld, seed: Long, recorded: Pair<Pair<Double, Double>, String>?): Sdm4 {
        val owner = views.views.clusters
        val ttlIndex = EdgeViews.TTL_BUCKETS
        val xs = ArrayList<Int>()
        val ys = ArrayList<Int>()
        val gs = ArrayList<Int>()
        val seen = HashSet<String>()
        val inboundBuckets = HashMap<Int, MutableSet<Int>>()
        for (e in world.relay.events) {
            if (e.op != ViewOp.STORE) continue
            val ns = EdgeViews.hex(e.namespace)
            val c = owner[ns] ?: continue
            if (c.second != 'X' || c.first == e.client) continue
            val blob = e.blobHash?.let { EdgeViews.hex(it) } ?: continue
            if (!seen.add("$ns/$blob")) continue
            val bucket = ttlIndex.indexOf(EdgeViews.ttlBucket(e.ttlSeconds ?: 0))
            xs += bucket
            ys += e.client
            gs += c.first
            inboundBuckets.getOrPut(c.first) { HashSet() } += bucket
        }
        val x = xs.toIntArray()
        val y = ys.toIntArray()
        val g = gs.toIntArray()
        val within = EdgeMath.conditionalMutualInformationBits(x, y, g)
        val (withinNull, withinExceeded) = EdgeMath.conditionalMiNull(x, y, g, within, seed)
        // Pairing: the smallest non-default bucket both inboxes receive (0 when none), per pair.
        val shared = IntArray(views.pairs.size) { i ->
            val p = views.pairs[i]
            val a = inboundBuckets[p[0]].orEmpty()
            val b = inboundBuckets[p[1]].orEmpty()
            (a intersect b).filter { it != 2 }.minOrNull()?.plus(1) ?: 0
        }
        val label = IntArray(views.pairs.size) { i -> if (EdgeFeatures.key(views.pairs[i][0], views.pairs[i][1]) in views.edges) 1 else 0 }
        val pairing = EdgeMath.mutualInformationBits(shared, label)
        val rnd = java.util.SplittableRandom(seed + 1)
        var sum = 0.0
        var exceeded = 0
        val permuted = label.copyOf()
        repeat(EdgeMath.PERMUTATIONS) {
            for (k in permuted.size - 1 downTo 1) {
                val j = rnd.nextInt(k + 1)
                val t = permuted[k]; permuted[k] = permuted[j]; permuted[j] = t
            }
            val v = EdgeMath.mutualInformationBits(shared, permuted)
            sum += v
            if (v >= pairing - 1e-12) exceeded++
        }
        return Sdm4(
            deposits = x.size,
            inboxes = g.toSet().size,
            within = within,
            withinNull = withinNull,
            withinExceeded = withinExceeded,
            pairs = views.pairs.size,
            pairing = pairing,
            pairingNull = sum / EdgeMath.PERMUTATIONS,
            pairingExceeded = exceeded,
            baseline = recorded?.first,
            baselineWhat = recorded?.second,
        )
    }

    private fun f4(v: Double): String = if (v.isNaN()) "n/a" else "%.4f".format(v)
    private fun f3(v: Double): String = "%.3f".format(v)
    private fun sign(v: Double): String = if (v.isNaN()) "n/a" else "%+.4f".format(v)
}
