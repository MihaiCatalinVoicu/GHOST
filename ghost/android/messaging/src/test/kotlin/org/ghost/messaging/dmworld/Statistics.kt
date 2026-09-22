package org.ghost.messaging.dmworld

import java.util.SplittableRandom

/**
 * S-DM3 (Phase 9 design §15.6, gating): "an attacker holding every `ghost1` but no card maps
 * namespaces to identities within the 99.9 % binomial interval of chance; a control with a colluding
 * subset's cards maps exactly that subset's contacts." Floors as in F8 §19.24 point 6: "a
 * statistical check with n < 100 fails rather than passes".
 *
 * **The attacker, exactly.** It holds every client's public identity material (the Ed25519 key, so
 * the `ghost1` string and hash, and every Olm identity key a card holder could have learned) and
 * every relay's effective view. For **every** namespace the view shows — card-derived or not — it
 * looks the namespace up in JD1's dictionary (every labelled SHA-256 and HKDF of every client's
 * identity material, matched by 16-byte windows) and names the owner of the entry it finds; where it
 * finds none it guesses uniformly among the N identities with a seeded stream. That is the whole of
 * what public identity material can do against a relay view: a `ghost1` never travels (T26), so the
 * only bridge from it to a namespace is a derivation. **It is not a learned attacker**: one that also
 * used store and read timing against, say, public activation times would need a model of what the
 * forum makes public, and §22.16 lists it with S-DM1 as deferred.
 *
 * **What the statistic can and cannot add (§22.16).** Where the dictionary misses, the guess is the
 * attacker's own random stream, so K is Binomial(n, 1/N) **by construction** and the interval test
 * measures that stream, not the engine. The evidence this check carries is therefore the dictionary
 * count, which must be **0** over every namespace of the view — the namespace half of JD1, on the
 * attacker's side of the relay — and the **control**, which runs the same attacker with the
 * colluders' cards added to its dictionary and must (a) name exactly the namespaces of the
 * identities whose cards the colluders hold, all correctly, and (b) push K **out** of the interval:
 * the statistic rejects chance when the attacker has real information. Mutant PM-3 (a namespace equal
 * to SHA-256(label ‖ `ghost1` hash)) puts every namespace in the dictionary.
 */
internal object Sdm3 {

    class Result(
        val n: Int,
        val identities: Int,
        val viewNamespaces: Int,
        val correct: Int,
        val byDictionary: Int,
        val lo: Int,
        val hi: Int,
        val pValue: Double,
        /** The positive control: the same attacker with the colluders' cards. */
        val colluders: Int,
        val controlMapped: Int,
        val controlCorrect: Int,
        val controlExpected: Int,
        val controlExact: Boolean,
        val controlK: Int,
        val controlP: Double,
    ) {
        val floorMet: Boolean get() = n >= FLOOR
        val withinChance: Boolean get() = correct in lo..hi
        val controlRejects: Boolean get() = controlK !in lo..hi
        val passed: Boolean
            get() = floorMet && byDictionary == 0 && withinChance && controlExact && controlMapped > 0 && controlRejects

        fun line(): String =
            "dm S-DM3: ${if (passed) "PASS" else "FAIL"} K=$correct of n=$n namespaces " +
                "(N=$identities identities, $byDictionary named by the dictionary over $viewNamespaces view namespaces), " +
                "99.9% interval [$lo, $hi], p=${"%.4f".format(pValue)}; control: $colluders colluders' cards map " +
                "$controlMapped of $controlExpected expected namespaces, $controlCorrect correct, " +
                "K=$controlK ${if (controlRejects) "outside" else "INSIDE"} the interval (p=${"%.2e".format(controlP)})" +
                (if (controlExact) "" else " (NOT EXACT)") +
                (if (byDictionary == 0) "" else " (THE DICTIONARY NAMED $byDictionary)") +
                (if (floorMet) "" else " (below the n >= $FLOOR floor)")

        fun failureMessage(): String = line()
    }

    const val FLOOR: Int = 100

    /** The attacker: for each namespace, the owner a dictionary hit names, or null. */
    private fun named(dictionary: ByteDictionary, namespace: ByteArray): Int? {
        var owner: Int? = null
        dictionary.scan(namespace) { entry, _ -> if (owner == null) owner = entry.owner ?: -1 }
        return owner
    }

    fun run(world: PrivacyWorld, seed: Long): Result {
        val owner = world.ownerOf()
        val identities = world.truth.clients.size
        val dictionary = Joins.identityDictionary(world)
        val view = LinkedHashSet<String>()
        for (e in world.relay.events) view += Joins.hex(e.namespace)
        // Every namespace of the view is looked up; only card namespaces have an owner to score.
        var byDictionary = 0
        val hits = HashMap<String, Int>()
        for (ns in view) {
            named(dictionary, ViewRelay.unhex(ns))?.let {
                byDictionary++
                hits[ns] = it
            }
        }
        val observed = view.filter { it in owner }
        val p = 1.0 / identities
        val n = observed.size
        val (lo, hi) = interval(n, p, 0.001)

        fun score(extra: Map<String, Int>): Int {
            val rnd = SplittableRandom(seed)
            var correct = 0
            for (ns in observed) {
                val guess = extra[ns] ?: hits[ns] ?: rnd.nextInt(identities)
                if (guess == owner[ns]) correct++
            }
            return correct
        }
        val correct = score(emptyMap())
        val pValue = twoSided(correct, n, p)

        // The positive control: the same attacker, its dictionary extended with a colluding subset's
        // cards — every card a colluder holds (its own and its accepted contacts'), derived with the
        // colluder's own DM context into the card's two namespaces, each naming the card's owner.
        val residue = Math.floorMod(seed, 10L).toInt()
        val colluders = (0 until identities).filter { it % 10 == residue }.toSet()
        val held = HashSet<Int>()
        for (c in colluders) {
            held += c
            for ((u, v) in world.acceptedEdges) {
                if (u == c) held += v
                if (v == c) held += u
            }
        }
        val controlMap = HashMap<String, Int>()
        val deriver = world.clients[colluders.first()].device.crypto
        for (holder in held) {
            val card = world.truth.clients[holder]?.card ?: continue
            val derived = deriver.deriveCard(card, 0)
            if (derived is org.ghost.crypto.bridge.DmCards.DeriveResult.Ok) {
                controlMap[Joins.hex(derived.values.inboxNamespace)] = holder
                controlMap[Joins.hex(derived.values.bundleNamespace)] = holder
                derived.values.clearSecrets()
            }
        }
        val controlDictionary = ByteDictionary()
        for ((ns, holder) in controlMap) controlDictionary.add("card of c$holder", ViewRelay.unhex(ns), holder)
        val controlNamed = HashMap<String, Int>()
        for (ns in observed) named(controlDictionary, ViewRelay.unhex(ns))?.let { controlNamed[ns] = it }
        val controlK = score(controlNamed)
        val expected = observed.filter { owner[it] in held }.toSet()
        val mapped = controlNamed.keys
        val controlCorrect = mapped.count { controlNamed[it] == owner[it] }
        return Result(
            n = n,
            identities = identities,
            viewNamespaces = view.size,
            correct = correct,
            byDictionary = byDictionary,
            lo = lo,
            hi = hi,
            pValue = pValue,
            colluders = colluders.size,
            controlMapped = mapped.size,
            controlCorrect = controlCorrect,
            controlExpected = expected.size,
            controlExact = mapped == expected && controlCorrect == mapped.size,
            controlK = controlK,
            controlP = twoSided(controlK, n, p),
        )
    }

    /** The central [1 − α] interval of Binomial(n, p): P(K < lo) ≤ α/2 and P(K > hi) ≤ α/2. */
    fun interval(n: Int, p: Double, alpha: Double): Pair<Int, Int> {
        val pmf = pmf(n, p)
        var cumulative = 0.0
        var lo = 0
        while (lo < n && cumulative + pmf[lo] <= alpha / 2) {
            cumulative += pmf[lo]
            lo++
        }
        var upper = 0.0
        var hi = n
        while (hi > 0 && upper + pmf[hi] <= alpha / 2) {
            upper += pmf[hi]
            hi--
        }
        return lo to hi
    }

    /** Two-sided exact binomial p-value: twice the smaller tail, capped at 1. */
    fun twoSided(k: Int, n: Int, p: Double): Double {
        val pmf = pmf(n, p)
        val lower = (0..k).sumOf { pmf[it] }
        val upper = (k..n).sumOf { pmf[it] }
        return minOf(1.0, 2 * minOf(lower, upper))
    }

    /** Binomial(n, p) probabilities in log space, so n in the thousands does not underflow. */
    fun pmf(n: Int, p: Double): DoubleArray {
        val logP = Math.log(p)
        val logQ = Math.log1p(-p)
        val logFact = DoubleArray(n + 1)
        for (i in 1..n) logFact[i] = logFact[i - 1] + Math.log(i.toDouble())
        return DoubleArray(n + 1) { k ->
            Math.exp(logFact[n] - logFact[k] - logFact[n - k] + k * logP + (n - k) * logQ)
        }
    }
}
