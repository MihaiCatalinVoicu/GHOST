package org.ghost.messaging.dmworld

/**
 * The features of the conversation-edge attackers of S-DM1 and S-DM2 (Phase 9 design §15.6:
 * "reply-timing survival, co-occurrence plus fetch → store lag, logistic regression over every
 * effective-view feature"), computed by **one** function of a view — so the LD attacker is the same
 * family as the full-view one, given less, and never a different piece of code that could be given
 * more by mistake.
 *
 * A **unit** is an unordered pair of clients {a, b} (their namespaces, by the clustering oracle of
 * [EdgeViews]) in one observation **window**; its label is whether the pair holds a conversation
 * (an accepted request, `PrivacyWorld.acceptedEdges`) — ground truth, used only to score. Within a
 * window the attacker sees exactly the view's events of that window: a relay operator who watched
 * for that long. The windows are the strata of the permutation test.
 *
 * **Requests.** AD-1 sees one store at each relay of an inbox's set; the timing features count a
 * request once (op, namespace, second, bytes), the structure features every event. Per window, a
 * client's **own** requests are the lists and gets of its inbox, the registrations of either of its
 * namespaces and the stores into its bundle namespace (its publications); its **inbound** requests
 * are the stores into its inbox (deposits) and the reads of its bundle namespace by others (fetches).
 */
internal object EdgeFeatures {

    /** The feature columns; the first [TIMING] are the timing family, the rest structure. */
    val NAMES: List<String> = listOf(
        "co-occurrence at the same second",
        "co-occurrence within 60 s",
        "co-occurrence within 600 s",
        "fetch-to-store lag",
        "reply-timing survival",
        "TTL-class pairing",
        "size-class pairing",
        "volume",
        "co-presence",
        "shared byte windows",
        "shared credentials",
        "shared verifiers",
        "shared circuits",
        "shared blobs",
        "co-read unknown namespaces",
    )

    const val CO0 = 0
    const val CO60 = 1
    const val CO600 = 2
    const val LAG = 3
    const val REPLY = 4
    const val TTL = 5
    const val SIZE = 6
    const val VOLUME = 7
    const val PRESENCE = 8
    const val BYTES = 9
    const val CREDENTIALS = 10
    const val VERIFIERS = 11
    const val CIRCUITS = 12
    const val BLOBS = 13
    const val UNKNOWN = 14

    /** The reply-survival horizons: 5 minutes, 30 minutes, 2 hours. */
    private val TAUS = doubleArrayOf(300.0, 1_800.0, 7_200.0)

    /** The fetch-to-store and co-occurrence horizons, in seconds. */
    private const val NEAR = 60L
    private const val FAR = 600L

    /** The byte windows compared across namespaces: 8 bytes at every 16th offset. */
    const val BYTE_STRIDE: Int = 16

    /**
     * One view's units: [rows] = windows × pairs, row `w * pairs.size + p` for window `w` and pair
     * `p`. [structure] counts, over the whole view, the distinct values of each structure kind
     * seen on the namespaces of two different clients (the exact half of S-DM1).
     */
    class Sample(
        val pairs: List<IntArray>,
        val windows: Int,
        val x: Array<DoubleArray>,
        val label: BooleanArray,
        val stratum: IntArray,
        val group: IntArray,
        val structure: Map<String, Int>,
    ) {
        val rows: Int get() = x.size
        fun column(k: Int): DoubleArray = DoubleArray(rows) { x[it][k] }
    }

    /** A request: one timing observation (deduplicated over relays). */
    private class Request(val op: ViewOp, val second: Long, val seq: Int, val cluster: Int, val role: Char, val ttl: Long, val size: Int)

    fun extract(
        view: List<EdgeEvent>,
        pairs: List<IntArray>,
        edges: Set<Long>,
        start: Long,
        end: Long,
        window: Long,
    ): Sample {
        val windows = maxOf(1, ((end - start + window - 1) / window).toInt())
        val pairIndex = HashMap<Long, Int>(pairs.size * 2)
        for ((i, p) in pairs.withIndex()) pairIndex[key(p[0], p[1])] = i
        val n = windows * pairs.size
        // Most (window, pair) units see nothing: they share one zero row until a feature is added.
        val zero = DoubleArray(NAMES.size)
        val x = Array(n) { zero }
        val label = BooleanArray(n)
        val stratum = IntArray(n)
        val group = IntArray(n)
        for (w in 0 until windows) for ((i, p) in pairs.withIndex()) {
            val r = w * pairs.size + i
            label[r] = key(p[0], p[1]) in edges
            stratum[r] = w
            group[r] = i
        }
        fun add(w: Int, a: Int, b: Int, k: Int, v: Double = 1.0) {
            if (a == b || a < 0 || b < 0) return
            val i = pairIndex[key(a, b)] ?: return
            val r = w * pairs.size + i
            if (x[r] === zero) x[r] = DoubleArray(NAMES.size)
            x[r][k] += v
        }
        fun windowOf(second: Long): Int = ((second - start) / window).toInt().coerceIn(0, windows - 1)

        // Requests, per window, deduplicated over the relays that saw them.
        val perWindow = Array(windows) { ArrayList<Request>() }
        val seen = HashSet<String>()
        val unknownAt = Array(windows) { HashMap<Long, MutableSet<String>>() }
        for (e in view) {
            if (e.cluster < 0) {
                unknownAt[windowOf(e.second)].getOrPut(e.second) { HashSet() } += e.namespace
                continue
            }
            if (!seen.add("${e.op}/${e.namespace}/${e.second}/${e.blob}")) continue
            perWindow[windowOf(e.second)] += Request(e.op, e.second, e.seq, e.cluster, e.role, e.ttl, e.size)
        }
        for (w in 0 until windows) timing(w, perWindow[w], unknownAt[w], window, ::add)

        // The structure the full view's fields carry across two clients' namespaces.
        val structure = LinkedHashMap<String, Int>()
        structure["byte windows"] = shared(view, windowOf = ::windowOf) { e, emit ->
            val b = e.bytes ?: return@shared
            var o = 0
            while (o + 8 <= b.size) {
                var v = 0L
                for (k in 0 until 8) v = (v shl 8) or (b[o + k].toLong() and 0xff)
                emit(v)
                o += BYTE_STRIDE
            }
        }.also { it.forEach { (w, a, b) -> add(w, a, b, BYTES) } }.size
        structure["credentials"] = shared(view, windowOf = ::windowOf) { e, emit -> e.credential?.let { emit(fold(it)) } }
            .also { it.forEach { (w, a, b) -> add(w, a, b, CREDENTIALS) } }.size
        structure["verifiers"] = shared(view, windowOf = ::windowOf) { e, emit -> e.verifier?.let { emit(fold(it)) } }
            .also { it.forEach { (w, a, b) -> add(w, a, b, VERIFIERS) } }.size
        structure["circuits"] = shared(view, windowOf = ::windowOf) { e, emit -> emit(e.circuit) }
            .also { it.forEach { (w, a, b) -> add(w, a, b, CIRCUITS) } }.size
        structure["blobs"] = shared(view, windowOf = ::windowOf) { e, emit -> if (e.blob >= 0) emit(e.blob.toLong()) }
            .also { it.forEach { (w, a, b) -> add(w, a, b, BLOBS) } }.size

        // Counts are compared on a log scale, the reply excess as it is.
        for (row in x) if (row !== zero) for (k in row.indices) if (k != REPLY) row[k] = Math.log1p(row[k])
        check(zero.all { it == 0.0 }) { "the shared zero row was written" }
        return Sample(pairs, windows, x, label, stratum, group, structure)
    }

    private fun timing(
        w: Int,
        requests: List<Request>,
        unknownAt: Map<Long, Set<String>>,
        window: Long,
        add: (Int, Int, Int, Int, Double) -> Unit,
    ) {
        fun own(r: Request): Boolean = when (r.op) {
            ViewOp.LIST, ViewOp.GET -> r.role == 'X'
            ViewOp.REGISTER -> true
            ViewOp.STORE -> r.role == 'P'
        }
        val owns = requests.filter(::own).sortedWith(compareBy({ it.second }, { it.seq }))
        val inbound = requests.filter { !own(it) }
        val ownSeconds = owns.map { it.second }.toLongArray()
        val ownAt = HashMap<Long, MutableSet<Int>>()
        for (r in owns) ownAt.getOrPut(r.second) { HashSet() } += r.cluster

        // Co-occurrence: an inbound request of b beside an own request of a.
        for (r in inbound) {
            val same = ownAt[r.second].orEmpty()
            for (a in same) add(w, a, r.cluster, CO0, 1.0)
            val near = HashSet<Int>()
            val far = HashSet<Int>()
            var i = lowerBound(ownSeconds, r.second - FAR)
            while (i < owns.size && owns[i].second <= r.second + FAR) {
                val o = owns[i]
                val d = Math.abs(o.second - r.second)
                if (o.cluster !in same) {
                    if (d <= NEAR) near += o.cluster else far += o.cluster
                }
                i++
            }
            for (a in near) add(w, a, r.cluster, CO60, 1.0)
            for (a in far - near) add(w, a, r.cluster, CO600, 1.0)
        }
        // Co-presence: own requests of two clients in the same second.
        for (clients in ownAt.values) if (clients.size > 1) {
            val l = clients.toList()
            for (i in l.indices) for (j in i + 1 until l.size) add(w, l[i], l[j], PRESENCE, 1.0)
        }
        // Fetch → store: a deposit into b's inbox after a GET of a's own inbox within 600 s.
        val gets = owns.filter { it.op == ViewOp.GET && it.role == 'X' }
        val getSeconds = gets.map { it.second }.toLongArray()
        val deposits = inbound.filter { it.op == ViewOp.STORE && it.role == 'X' }.sortedWith(compareBy({ it.second }, { it.seq }))
        for (d in deposits) {
            val before = HashSet<Int>()
            var i = lowerBound(getSeconds, d.second - FAR)
            while (i < gets.size && (gets[i].second < d.second || (gets[i].second == d.second && gets[i].seq < d.seq))) {
                before += gets[i].cluster
                i++
            }
            for (a in before) add(w, a, d.cluster, LAG, 1.0)
        }
        // Reply-timing survival over the deposits alone (stores into inboxes): after a deposit into
        // b's inbox, how soon the next one into a's arrives, against a Poisson arrival of a's rate.
        val byInbox = deposits.groupBy { it.cluster }
        val length = window.toDouble()
        val inboxes = byInbox.keys.toList()
        for (i in inboxes.indices) for (j in i + 1 until inboxes.size) {
            val a = inboxes[i]
            val b = inboxes[j]
            val s = survival(byInbox.getValue(b), byInbox.getValue(a), length) + survival(byInbox.getValue(a), byInbox.getValue(b), length)
            if (s != 0.0) add(w, a, b, REPLY, s)
        }
        // TTL- and size-class pairing (the non-default classes two inboxes both receive), and volume.
        val ttls = inboxes.map { c -> byInbox.getValue(c).filter { it.ttl != 604_800L }.groupingBy { it.ttl }.eachCount() }
        val sizes = inboxes.map { c -> byInbox.getValue(c).filter { it.size > 4_096 }.groupingBy { EdgeViews.sizeBucket(it.size) }.eachCount() }
        for (i in inboxes.indices) for (j in i + 1 until inboxes.size) {
            val t = ttls[i].entries.sumOf { (k, v) -> minOf(v, ttls[j][k] ?: 0) }
            val s = sizes[i].entries.sumOf { (k, v) -> minOf(v, sizes[j][k] ?: 0) }
            if (t > 0) add(w, inboxes[i], inboxes[j], TTL, t.toDouble())
            if (s > 0) add(w, inboxes[i], inboxes[j], SIZE, s.toDouble())
            add(
                w, inboxes[i], inboxes[j], VOLUME,
                Math.log1p(byInbox.getValue(inboxes[i]).size.toDouble()) * Math.log1p(byInbox.getValue(inboxes[j]).size.toDouble()),
            )
        }
        // Namespaces no card names, attributed to the clients whose own requests share their second.
        val readers = HashMap<String, MutableSet<Int>>()
        for ((second, namespaces) in unknownAt) {
            val present = ownAt[second] ?: continue
            for (ns in namespaces) readers.getOrPut(ns) { HashSet() } += present
        }
        for (clients in readers.values) if (clients.size > 1) {
            val l = clients.toList()
            for (i in l.indices) for (j in i + 1 until l.size) add(w, l[i], l[j], UNKNOWN, 1.0)
        }
    }

    /** Σ over deposits into the first inbox of (the next into the second arrives within τ) − P(Poisson). */
    private fun survival(first: List<Request>, second: List<Request>, length: Double): Double {
        if (first.isEmpty() || second.isEmpty()) return 0.0
        val lambda = second.size / maxOf(1.0, length)
        var score = 0.0
        var j = 0
        for (m in first) {
            while (j < second.size && (second[j].second < m.second || (second[j].second == m.second && second[j].seq <= m.seq))) j++
            val next = if (j < second.size) (second[j].second - m.second).toDouble() else Double.MAX_VALUE
            for (tau in TAUS) score += (if (next <= tau) 1.0 else 0.0) - (1 - Math.exp(-lambda * tau))
        }
        return score
    }

    /**
     * The values of one kind seen on the namespaces of more than one client, as (window, a, b) per
     * pair of clients per distinct value (its first window); a value on a namespace no card names is
     * not attributed here (the co-read feature takes those).
     */
    private fun shared(
        view: List<EdgeEvent>,
        windowOf: (Long) -> Int,
        values: (EdgeEvent, (Long) -> Unit) -> Unit,
    ): List<Triple<Int, Int, Int>> {
        // Pass 1, in primitive memory (the PR world's bytes alone are some 1.6 million windows): each
        // value's first owner, or MULTI once a second owner shows it. Pass 2 collects the owners and
        // first window of the MULTI values only, which the honest world has none of.
        val first = LongIntMap()
        for (e in view) {
            if (e.cluster < 0) continue
            values(e) { v ->
                val seen = first.get(v)
                if (seen == LongIntMap.ABSENT) first.put(v, e.cluster) else if (seen != e.cluster && seen != MULTI) first.put(v, MULTI)
            }
        }
        if (!first.anyValue(MULTI)) return emptyList()
        val owners = HashMap<Long, MutableSet<Int>>()
        val firstWindow = HashMap<Long, Int>()
        for (e in view) {
            if (e.cluster < 0) continue
            values(e) { v ->
                if (first.get(v) == MULTI) {
                    owners.getOrPut(v) { HashSet(2) } += e.cluster
                    firstWindow.putIfAbsent(v, windowOf(e.second))
                }
            }
        }
        val out = ArrayList<Triple<Int, Int, Int>>()
        for ((v, clients) in owners) {
            val l = clients.sorted()
            for (i in l.indices) for (j in i + 1 until l.size) out += Triple(firstWindow.getValue(v), l[i], l[j])
        }
        return out
    }

    private const val MULTI = -2

    /** An open-addressing map from 64-bit values to non-negative ints (or [MULTI]), with no boxing. */
    private class LongIntMap {
        private var keys = LongArray(1 shl 16)
        private var vals = IntArray(1 shl 16) { ABSENT }
        private var size = 0

        fun get(k: Long): Int {
            var i = slot(k, keys.size)
            while (true) {
                if (vals[i] == ABSENT) return ABSENT
                if (keys[i] == k) return vals[i]
                i = (i + 1) and (keys.size - 1)
            }
        }

        fun put(k: Long, v: Int) {
            if ((size + 1) * 2 > keys.size) grow()
            var i = slot(k, keys.size)
            while (vals[i] != ABSENT && keys[i] != k) i = (i + 1) and (keys.size - 1)
            if (vals[i] == ABSENT) size++
            keys[i] = k
            vals[i] = v
        }

        fun anyValue(v: Int): Boolean = vals.any { it == v }

        private fun grow() {
            val oldKeys = keys
            val oldVals = vals
            keys = LongArray(oldKeys.size * 2)
            vals = IntArray(oldVals.size * 2) { ABSENT }
            size = 0
            for (i in oldKeys.indices) if (oldVals[i] != ABSENT) put(oldKeys[i], oldVals[i])
        }

        private fun slot(k: Long, n: Int): Int {
            var z = k * -0x61c8864680b583ebL
            z = z xor (z ushr 29)
            return (z.toInt()) and (n - 1)
        }

        companion object {
            const val ABSENT = Int.MIN_VALUE
        }
    }

    private fun fold(bytes: ByteArray): Long {
        val d = ViewRelay.sha256(bytes)
        var v = 0L
        for (i in 0 until 8) v = (v shl 8) or (d[i].toLong() and 0xff)
        return v
    }

    private fun lowerBound(a: LongArray, v: Long): Int {
        var lo = 0
        var hi = a.size
        while (lo < hi) {
            val mid = (lo + hi) ushr 1
            if (a[mid] < v) lo = mid + 1 else hi = mid
        }
        return lo
    }

    fun key(a: Int, b: Int): Long = (minOf(a, b).toLong() shl 32) or maxOf(a, b).toLong()
}
