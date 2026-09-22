package org.ghost.messaging.dmworld

import org.ghost.messaging.DmWorld
import org.ghost.messaging.api.Timer
import java.util.SplittableRandom

/** The events of [a] that [b] lacks, as multisets: one twin's view against another's. */
internal fun minus(a: List<String>, b: List<String>): List<String> {
    val left = b.groupingBy { it }.eachCount().toMutableMap()
    return a.filter { e ->
        val n = left[e] ?: 0
        if (n > 0) {
            left[e] = n - 1
            false
        } else {
            true
        }
    }
}

/** A multiset difference as a report line names it: count, ops, and the first event. */
internal fun describe(events: List<String>, where: String): String {
    if (events.isEmpty()) return "0 events only in $where"
    val ops = events.groupingBy { it.substringBefore(' ') }.eachCount().toSortedMap()
    return "${events.size} events only in $where (ops $ops; first: ${events.first()})"
}

/**
 * NI-DM1 (Phase 9 design §15.6): "Twins (identical shape views `(op, relay, ns, size, ttl, minute,
 * scope, key_kind, batch_count, result, circuit open/close minute)`): NI-DM1 inbound content (valid,
 * malformed, replays, probes, forged, key-changed, requests) with identical user actions".
 *
 * **The twins.** Four clients: A (0) and C (2) are B's (1) contacts, S (3) is a stranger. Every twin
 * runs the same plan and the same user actions — A writes to B once at `t0` — and differs in exactly
 * one thing: what the relay hands **B** in place of A's blob. The arrival minute is A's in every twin,
 * because arrival times are NI-DM6's variable and not this one's:
 *  - [Variant.VALID]: A's blob as stored;
 *  - [Variant.MALFORMED]: A's blob with one byte flipped inside the AEAD, so the hint still names A's
 *    key and the open fails (§6.5 step 3, a forgery "counted");
 *  - [Variant.PROBE]: uniform bytes of the same bucket, which match no hint (`unknown_seal`);
 *  - [Variant.REQUEST]: S's first flight to B (S scanned B's card an hour before `t0`; the relay
 *    withholds it from B until it serves it in A's place). B's user decides nothing.
 * Replays, forged bindings and key-changed senders are not twins here (§22.16).
 *
 * **What is compared.** B's shape view from `t0` to the end of the world: every relay event B made —
 * stores, lists, gets, registrations — as `(op, relay, namespace, size, TTL, minute, credential
 * scope, key kind, period)`. Circuit open and close minutes, batch counts and results are not in the
 * model relay (§22.16). The view must be equal across the four twins, it must contain B's GET of the
 * substituted blob in every twin, and the substitution must have happened exactly once in each.
 */
internal object NiDm1 {

    enum class Variant { VALID, MALFORMED, PROBE, REQUEST }

    class Run(val variant: Variant, val view: List<String>, val substituted: Int, val bGets: Int)

    class Result(val runs: List<Run>) {
        val reference: Run get() = runs.first { it.variant == Variant.VALID }

        /**
         * Each twin that differs from VALID, as the two multiset differences: the events only VALID
         * has, and the events only the twin has. Which side holds the extra STORE is what tells an
         * automatic receipt (PM-2: only in VALID) from an automatic reset (PM-6: only in MALFORMED).
         */
        val differences: List<String>
            get() = runs.filter { it.view != reference.view }.map { run ->
                val onlyReference = minus(reference.view, run.view)
                val onlyRun = minus(run.view, reference.view)
                "${run.variant} vs VALID: ${describe(onlyReference, "VALID")}, ${describe(onlyRun, run.variant.name)}"
            }

        val applied: Boolean get() = runs.all { it.substituted == 1 && it.bGets > 0 }

        val passed: Boolean get() = differences.isEmpty() && applied && reference.view.isNotEmpty()

        fun line(): String =
            "dm NI-DM1: ${if (passed) "PASS" else "FAIL"} ${runs.size} twins " +
                "(${runs.joinToString(", ") { it.variant.name }}) equal over ${reference.view.size} events of B's view" +
                (if (applied) "" else "; a substitution did not happen exactly once") +
                (if (differences.isEmpty()) "" else "; " + differences.joinToString("; "))
    }

    fun run(seed: Long, mutant: PrivacyMutant? = null): Result =
        Result(Variant.entries.map { twin(seed, it, mutant) })

    private const val A = 0
    private const val B = 1
    private const val C = 2
    private const val S = 3

    fun twin(seed: Long, variant: Variant, mutant: PrivacyMutant?): Run {
        val start = DmWorld.WEEK_ORIGIN + 2_870 * DmWorld.WEEK + 2 * DmWorld.DAY
        val t0 = start + DmWorld.DAY + 3 * DmWorld.HOUR
        val plan = Plan.scripted(
            activation = LongArray(4) { start },
            edges = listOf(
                Plan.Edge(A, B, start + DmWorld.HOUR, reject = false, timer = Timer.DAYS_7, bursts = emptyList()),
                Plan.Edge(C, B, start + 2 * DmWorld.HOUR, reject = false, timer = Timer.DAYS_7, bursts = emptyList()),
            ),
            seed = seed,
        )
        val config = PrivacyWorldConfig(seed = seed, clients = 4, days = 3, mutant = mutant, plan = plan)
        PrivacyWorld(config).use { world ->
            var substituted = 0
            var strangerBlob: ByteArray? = null
            if (variant == Variant.REQUEST) {
                world.schedule(t0 - DmWorld.HOUR) {
                    world.session(S, t0 - DmWorld.HOUR, 12, mapOf(0 to {
                        world.userAdd(S, B)
                        world.userSend(S, B, 40)
                    }))
                }
                world.relay.serveFilter = { reader, from -> !(reader == B && from == S) }
            }
            world.relay.serveTransform = { reader, from, storedAt, blob ->
                if (reader == B && from == A && storedAt >= t0 && substituted == 0) {
                    substituted++
                    when (variant) {
                        Variant.VALID -> blob
                        Variant.MALFORMED -> blob.copyOf().also { it[it.size / 2] = (it[it.size / 2].toInt() xor 0x5a).toByte() }
                        Variant.PROBE -> ByteArray(blob.size).also { SplittableRandom(seed).nextBytes(it) }
                        Variant.REQUEST -> {
                            strangerBlob = strangerBlob ?: world.relay.events.first {
                                it.op == ViewOp.STORE && it.client == S &&
                                    world.truth.clients[B]?.inboxNamespace?.contentEquals(it.namespace) == true
                            }.bytes
                            strangerBlob
                        }
                    }
                } else {
                    null
                }
            }
            world.schedule(t0) {
                world.session(A, t0, 3, mapOf(0 to { world.userSend(A, B, 40) }))
            }
            world.run()
            val view = shapeView(world, B, t0)
            val gets = world.relay.events.count { it.client == B && it.op == ViewOp.GET && it.second >= t0 }
            return Run(variant, view, substituted, gets)
        }
    }

    /** A client's shape view from [from]: §15.6's tuple, as far as the model relay carries it. */
    fun shapeView(world: PrivacyWorld, client: Int, from: Long): List<String> =
        world.relay.events.filter { it.client == client && it.second >= from }.map { e ->
            "${e.op} slot=${e.relaySlot} ns=${Joins.hex(e.namespace).take(16)} size=${e.bytes?.size} " +
                "ttl=${e.ttlSeconds} minute=${e.second / 60} " +
                "scope=${e.credential?.let { Joins.hex(Joins.sha256(it)).take(12) }} " +
                "kind=${e.keyKind} period=${e.period}"
        }
}

/**
 * NI-DM3 (Phase 9 design §15.6): "degree (k vs k′ idle contacts)" — two worlds that differ only in
 * how many contacts one client holds, the extra ones idle, give that client identical shape views.
 *
 * **The twins.** Five clients: C (0) has two established contacts (1 and 2) in both worlds; in the
 * `k′` world C's user also scans the cards of 3 and 4 in person at `t0` and never writes to them.
 * Contact 1 then writes to C at `t0 + 3 h` in both, so the compared window is not an idle one. With
 * a correct engine an added card is local state: no namespace is registered for an idle contact
 * (§5.1: a contact inbox is registered at the first send), no bundle is fetched (`EST-START` runs
 * from a send, §21.7), and no credential is installed for a namespace that is not registered. C's
 * view from `t0` must be equal, and non-empty, in the two worlds; a failure is reported as the two
 * multiset differences. **Not here:** a `k′` world whose extra contacts were established and then
 * fell idle (their establishment traffic is declared leakage, §1.2, and would need a window that
 * starts after it), and the redeem-lane half PM-1 and PM-11 would need (§22.16).
 */
internal object NiDm3 {

    class Result(val k: List<String>, val kPrime: List<String>, val added: Int) {
        val passed: Boolean get() = k == kPrime && k.isNotEmpty() && added == 2

        fun line(): String =
            "dm NI-DM3: ${if (passed) "PASS" else "FAIL"} k=2 vs k'=4 contacts ($added idle cards added): " +
                "C's view equal over ${k.size} events" +
                (if (k == kPrime) "" else "; ${describe(minus(kPrime, k), "k'")}, ${describe(minus(k, kPrime), "k")}") +
                (if (added == 2) "" else "; the k' world added $added cards, not 2")
    }

    private const val C = 0

    fun run(seed: Long, mutant: PrivacyMutant? = null): Result {
        val k = twin(seed, idle = false, mutant = mutant)
        val kPrime = twin(seed, idle = true, mutant = mutant)
        return Result(k.first, kPrime.first, kPrime.second)
    }

    private fun twin(seed: Long, idle: Boolean, mutant: PrivacyMutant?): Pair<List<String>, Int> {
        val start = DmWorld.WEEK_ORIGIN + 2_870 * DmWorld.WEEK + 2 * DmWorld.DAY
        val t0 = start + DmWorld.DAY
        val plan = Plan.scripted(
            activation = LongArray(5) { start },
            edges = listOf(
                Plan.Edge(1, C, start + DmWorld.HOUR, reject = false, timer = Timer.DAYS_7, bursts = emptyList()),
                Plan.Edge(2, C, start + 2 * DmWorld.HOUR, reject = false, timer = Timer.DAYS_7, bursts = emptyList()),
            ),
            seed = seed,
        )
        PrivacyWorld(PrivacyWorldConfig(seed = seed, clients = 5, days = 3, mutant = mutant, plan = plan)).use { world ->
            var added = 0
            if (idle) {
                world.schedule(t0) {
                    world.session(C, t0, 2, mapOf(0 to {
                        for (peer in listOf(3, 4)) {
                            if (world.userAdd(C, peer) == org.ghost.messaging.api.AddContactResult.ADDED) added++
                        }
                    }))
                }
            }
            world.schedule(t0 + 3 * DmWorld.HOUR) {
                world.session(1, t0 + 3 * DmWorld.HOUR, 3, mapOf(0 to { world.userSend(1, C, 40) }))
            }
            world.run()
            // From the minute after the scan: the scan's own foreground session is a user action
            // the k world does not take, and a session start is declared leakage (LIMITE L2.1 #1);
            // what NI-DM3 is about is what the extra contacts cause afterwards.
            return NiDm1.shapeView(world, C, t0 + 2 * DmWorld.MINUTE) to added
        }
    }
}
