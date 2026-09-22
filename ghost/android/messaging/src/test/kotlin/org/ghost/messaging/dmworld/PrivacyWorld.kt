package org.ghost.messaging.dmworld

import org.ghost.messaging.DmDevice
import org.ghost.messaging.DmWorld
import org.ghost.messaging.MovableClock
import org.ghost.messaging.api.AddContactResult
import org.ghost.messaging.api.CardSource
import org.ghost.messaging.api.ContactId
import org.ghost.messaging.api.MessageId
import org.ghost.messaging.api.SendResult
import org.ghost.messaging.api.Timer
import org.ghost.storage.JdbcSqlExecutor
import org.ghost.storage.MigrationRunner
import org.ghost.storage.SqlExecutor
import java.security.MessageDigest
import java.util.PriorityQueue
import java.util.SplittableRandom

/**
 * The scale of a privacy world (Phase 9 design §15.6 "World": N = 120 over 14 days at the PR scale,
 * N = 600 over 42 days at the gate scale).
 *
 * [SMALL] is this slice's own, for the privacy mutants: §15.7 kills every mutant "against a
 * same-scale control world", and §16.2 runs the mutants "on a small world" in the `android` job,
 * so a mutant and its control run at [SMALL] and never at [PR]. [MEDIUM] exists for the one kill a
 * statistic makes: S-DM3 refuses a sample under 100 namespaces (§15.6's floor), and [SMALL]'s 16
 * clients own 32.
 */
internal enum class PrivacyScale(val clients: Int, val days: Int) {
    SMALL(16, 5),
    MEDIUM(56, 2),
    PR(120, 14),
    GATE(600, 42),
    ;

    companion object {
        /** `-Dghost.dm.privacy=gate` selects the gate scale; anything else is the PR scale. */
        fun selected(): PrivacyScale =
            if (System.getProperty("ghost.dm.privacy") == "gate") GATE else PR

        /**
         * `-Dghost.dm.privacy=off` skips every privacy world: `messaging-exit-gate.yml` runs the
         * whole `:messaging` suite for S10's crash enumeration, and the privacy worlds are
         * `dm-privacy-gate.yml`'s and the `android` job's, which check their report.
         */
        val enabled: Boolean get() = System.getProperty("ghost.dm.privacy") != "off"
    }
}

/**
 * A DM privacy world (Phase 9 design §15.6): [config]'s clients, each a real `:messaging` +
 * `:crypto-bridge` + `:sync` stack on its own migrated v5 database with a real DM context in
 * `ghost-dm-host`, driven through the facade by a scripted behaviour model, over a [ViewRelay] that
 * records the effective view, and a [GroundTruth] recorded from the engine's own calls.
 *
 * **The behaviour model, and where it is narrower than §15.6** (each narrowing is listed in §22.16):
 *  - degree ~ Poisson(6) by the configuration model; each edge is established **in person** (the
 *    one-scan flow of §12.2: the initiator scans the responder's card, the responder accepts the
 *    request and replies), and 3 % of requests are rejected;
 *  - 10 % of clients onboard by invite, later than the rest, and message their inviter first;
 *  - bursty conversations: per edge a Poisson process of bursts (one per two days on average), each
 *    a geometric number of alternating messages with LogNormal reply delays of median 2 minutes, or
 *    1–6 hours when the peer is offline (30 %);
 *  - the conversation timer drawn once per edge from §15.6's mix (60 % 7 d, 10 % 30 d, 5 % off,
 *    10 % 1 d, 10 % 1 h, 5 % 5 min) and set by the initiator with a TIMER_SET;
 *  - body lengths mostly short, with 4 % in `[1 501, 2 220]` and 1 % in `[2 221, 3 900]`, the
 *    second band straddling the 4/16 KiB boundary of R-B1 so JD4 and NI-DM2's mutant can bite;
 *  - background relay sessions every 1–4 hours and one-minute foreground passes during sessions.
 *  **Not modelled:** key changes, restores, clock offsets, the ES slot-table change, HIGH mode,
 *  hostile modes and the PQ-C cadence.
 *
 * Everything is planned from [PrivacyWorldConfig.seed] before the first event runs, so a twin world
 * built from the same seed differs only in what its variant changes. Native randomness is the OS's
 * (§22.8.10 point 7's seeded `getrandom` backend is not built), so ciphertexts differ run to run and
 * every check here is on shapes, joins and ground truth — never on bytes that would need it.
 */
internal class PrivacyWorld(val config: PrivacyWorldConfig) : AutoCloseable {

    val truth = GroundTruth()
    var now: Long = config.startSeconds
        private set
    val relay = ViewRelay { now }

    /** One client of the world. */
    inner class Client(val index: Int) {
        private val executor: JdbcSqlExecutor = JdbcSqlExecutor(":memory:").also {
            MigrationRunner(it).migrate()
        }
        private val sql: SqlExecutor = config.mutant?.rewrite?.let { RewritingSqlExecutor(executor, it) } ?: executor
        val clock = MovableClock(config.startSeconds)
        val seeds: DmDevice.DeviceSeeds = seedsOf(config.seed, index)
        val device: DmDevice = DmDevice(
            branch = index,
            slotCount = SLOTS,
            operators = OPERATORS,
            startSeconds = config.startSeconds,
            identityBranch = index + 1,
            harness = DmDevice.HarnessOverride(
                sql = sql,
                clock = clock,
                bootIndex = 0,
                decorate = { native ->
                    val mutated = config.mutant?.envelopes?.invoke(this@PrivacyWorld, index, native) ?: native
                    RecordingEnvelopes(mutated, index, truth)
                },
                decorateCrypto = { native ->
                    val mutated = config.mutant?.crypto?.invoke(this@PrivacyWorld, index, native) ?: native
                    RecordingCrypto(mutated, index, truth)
                },
            ),
            seeds = seeds,
        )

        init {
            config.mutant?.configure?.invoke(device)
        }

        var activated = false

        /** Message ids of this client's user actions: JD6's `oracle_user_action` (§15.1). */
        val userMessages = HashSet<String>()

        fun sync() {
            clock.now = now
            clock.monotonic = now * 1_000
        }

        fun close() {
            device.close()
            executor.close()
        }
    }

    val clients: List<Client> = List(config.clients) { Client(it) }

    val plan: Plan = config.plan ?: Plan.draw(config)

    private val queue = PriorityQueue<Scheduled>(compareBy<Scheduled>({ it.at }, { it.seq }))
    private var sequence = 0L

    private class Scheduled(val at: Long, val seq: Long, val action: () -> Unit)

    fun schedule(at: Long, action: () -> Unit) {
        queue += Scheduled(at, sequence++, action)
    }

    /** Counts of what the behaviour did, for the report line and the floors. */
    val counters = LinkedHashMap<String, Int>()

    private fun count(key: String, n: Int = 1) {
        counters.merge(key, n, Int::plus)
    }

    /** The edges whose request was accepted, as (initiator, responder). */
    val acceptedEdges = LinkedHashSet<Pair<Int, Int>>()

    private val lastWake = HashMap<Int, Long>()

    // ---------------------------------------------------------------- running

    /** The end of the planned behaviour. */
    val end: Long get() = config.startSeconds + config.days * DmWorld.DAY

    /** Runs the whole plan. */
    fun run(): PrivacyWorld {
        runUntil(end)
        return this
    }

    /** Runs until [second]; the twin and seizure worlds stop mid-run to change or dump something. */
    fun runUntil(second: Long) {
        installPlan()
        truth.now = { now }
        while (queue.isNotEmpty() && queue.peek().at <= second) {
            val next = queue.poll()
            now = next.at
            next.action()
        }
        now = maxOf(now, second)
    }

    private var installed = false

    private fun installPlan() {
        if (installed) return
        installed = true
        plan.install(this)
    }

    /**
     * Requests a planned peer's user decides whenever a relay session shows one: the user opens the
     * notification. Filled by [Plan.install]; `(responder, initiator) → accept`.
     */
    val pendingDecisions = HashMap<Int, MutableMap<Int, Boolean>>()

    private fun decidePending(c: Int) {
        val pending = pendingDecisions[c] ?: return
        for ((peer, accept) in pending.entries.toList()) {
            if (userDecide(c, peer, accept)) {
                pending.remove(peer)
                if (accept) {
                    acceptedEdges += peer to c
                    userSend(c, peer, 9)
                }
            }
        }
    }

    // ---------------------------------------------------------------- steps

    fun activate(c: Int) {
        val client = clients[c]
        client.sync()
        client.device.engine.onActivated()
        requireNotNull(client.device.engine.myCard()) { "client $c has no card after ACTIVATE" }
        client.activated = true
        count("activations")
        wake(c)
    }

    /**
     * One relay session of a client: the read lane serves, a time-triggered actor pass runs, the
     * outbox is collected and pending registrations run. Every wake is a relay session.
     */
    fun wake(c: Int) {
        val client = clients[c]
        if (!client.activated) return
        if (lastWake[c] == now) return
        lastWake[c] = now
        client.sync()
        relay.beginSession(c)
        relay.serve(c, client.device, ownNamespaces(c), contactBundles)
        client.device.timeTriggeredPass()
        relay.collect(c, client.device)
        relay.register(c, client.device)
        count("wakes")
        decidePending(c)
        config.mutant?.afterWake?.invoke(this, c)
        // Anything a reflex put in the outbox reaches the relay in the same session, as it would.
        relay.collect(c, client.device)
    }

    /** A background job run: one relay session, then the next one 1–4 hours later. */
    fun background(c: Int, rnd: SplittableRandom) {
        wake(c)
        count("background sessions")
        schedule(now + DmWorld.HOUR + rnd.nextLong(3 * DmWorld.HOUR)) { background(c, rnd) }
    }

    /**
     * A foreground session of [minutes] minutes: a relay session every minute, with [atMinute]'s
     * user actions after the minute's wake, and the conversation displayed at the end.
     */
    fun session(c: Int, start: Long, minutes: Int, atMinute: Map<Int, () -> Unit>) {
        for (k in 0 until minutes) {
            schedule(start + k * DmWorld.MINUTE) {
                wake(c)
                atMinute[k]?.let {
                    clients[c].sync()
                    it()
                    relay.collect(c, clients[c].device)
                }
                if (k == minutes - 1) displayAll(c)
            }
        }
        count("foreground sessions")
    }

    // ----------------------------------------------------------- user actions

    fun contactIdOf(c: Int, peer: Int): ContactId? {
        val pk = truth.clients[peer]?.identityPk ?: return null
        var id: ByteArray? = null
        clients[c].device.sql.query(
            "SELECT contact_id FROM dm_contact WHERE identity_pk = ?",
            listOf(pk),
        ) { id = it.blob(0) }
        return id?.let { ContactId(it) }
    }

    fun trustOf(c: Int, peer: Int): String? {
        val pk = truth.clients[peer]?.identityPk ?: return null
        var trust: String? = null
        clients[c].device.sql.query(
            "SELECT trust_state FROM dm_contact WHERE identity_pk = ?",
            listOf(pk),
        ) { trust = it.string(0) }
        return trust
    }

    private fun outgoingIds(c: Int): Set<String> {
        val out = HashSet<String>()
        clients[c].device.sql.query("SELECT hex(message_id) FROM dm_message WHERE direction = 'out'") {
            out += it.string(0).lowercase()
        }
        return out
    }

    /** A user action through the facade, with every message it created recorded as the user's. */
    private fun <T> userAction(c: Int, what: String, body: () -> T): T {
        val before = outgoingIds(c)
        val result = body()
        clients[c].userMessages += outgoingIds(c) - before
        return result
    }

    fun userAdd(c: Int, peer: Int): AddContactResult {
        val card = requireNotNull(truth.clients[peer]?.card) { "client $peer has no card" }
        val result = userAction(c, "add") {
            clients[c].device.engine.addContact(card, CardSource.QR_IN_PERSON)
        }
        count("contacts added")
        config.mutant?.afterAdd?.invoke(this, c, peer)
        return result
    }

    fun userSend(c: Int, peer: Int, length: Int): SendResult? {
        val contact = contactIdOf(c, peer) ?: return null
        val text = textOf(c, length)
        val result = userAction(c, "send") { clients[c].device.engine.send(contact, text, null) }
        count("sends")
        if (result != SendResult.QUEUED) count("sends not queued: $result")
        return result
    }

    fun userSetTimer(c: Int, peer: Int, timer: Timer): SendResult? {
        val contact = contactIdOf(c, peer) ?: return null
        val result = userAction(c, "timer") { clients[c].device.engine.setTimer(contact, timer) }
        count("timers set")
        return result
    }

    /** Accepts (or rejects) the request of [peer], if there is one; true when it was decided now. */
    fun userDecide(c: Int, peer: Int, accept: Boolean): Boolean {
        if (trustOf(c, peer) != "request") return false
        val contact = contactIdOf(c, peer) ?: return false
        userAction(c, if (accept) "accept" else "reject") {
            if (accept) clients[c].device.engine.acceptRequest(contact)
            else clients[c].device.engine.rejectRequest(contact)
        }
        count(if (accept) "requests accepted" else "requests rejected")
        return true
    }

    private fun displayAll(c: Int) {
        val engine = clients[c].device.engine
        val ids = ArrayList<MessageId>()
        clients[c].device.sql.query("SELECT message_id FROM dm_message WHERE state = 'unread'") {
            ids += MessageId(it.blob(0))
        }
        if (ids.isNotEmpty()) engine.markDisplayed(ids)
    }

    private val texts = HashMap<Int, Int>()

    private fun textOf(c: Int, length: Int): String {
        val n = texts.merge(c, 1, Int::plus)!!
        val seed = "c$c-m$n-"
        val out = StringBuilder(length)
        while (out.length < length) out.append(seed)
        return out.substring(0, length)
    }

    // ------------------------------------------------------------ ground truth

    /** Own namespaces of a client, hex, as its own card says (inbox and bundle). */
    fun ownNamespaces(c: Int): Set<String> {
        val t = truth.clients[c] ?: return emptySet()
        return setOfNotNull(t.inboxNamespace?.let { hex(it) }, t.bundleNamespace?.let { hex(it) })
    }

    /**
     * Every activated client's bundle namespace, hex → that client's identity key (JD7's window
     * truth). Kept by the recorder as each card is first read, so a client that activates late is in
     * it from its activation on.
     */
    val contactBundles: Map<String, ByteArray> get() = truth.bundleOwners

    /** Namespace hex → the client that owns it (inbox or bundle), from the ground truth. */
    fun ownerOf(): Map<String, Int> {
        val out = HashMap<String, Int>()
        for (t in truth.clients.values) {
            t.inboxNamespace?.let { out[hex(it)] = t.index }
            t.bundleNamespace?.let { out[hex(it)] = t.index }
        }
        return out
    }

    fun weekOf(second: Long): Long = Math.floorDiv(second - DmWorld.WEEK_ORIGIN, DmWorld.WEEK)

    override fun close() {
        for (client in clients) runCatching { client.close() }
    }

    companion object {
        const val SLOTS: Int = 4
        const val OPERATORS: Int = 2

        fun hex(bytes: ByteArray): String = bytes.joinToString("") { "%02x".format(it) }

        /** Each client's key material, from the world seed and its index (never shared). */
        fun seedsOf(seed: Long, index: Int): DmDevice.DeviceSeeds {
            fun derive(label: String): ByteArray =
                MessageDigest.getInstance("SHA-256").digest("ghost-s11/$seed/$index/$label".toByteArray())
            return DmDevice.DeviceSeeds(
                messagingBranch = derive("messaging"),
                identitySeed = derive("identity"),
                sessionStateKey = derive("state-key"),
                randomStream = "privacy-$seed-$index",
            )
        }
    }
}

/** A privacy world's parameters. */
internal class PrivacyWorldConfig(
    val seed: Long,
    val clients: Int,
    val days: Int,
    val mutant: PrivacyMutant? = null,
    /** A Tuesday deep inside the Phase 8 grid, as every DM world uses. */
    val startSeconds: Long = DmWorld.WEEK_ORIGIN + 2_870 * DmWorld.WEEK + 2 * DmWorld.DAY,
    /** Mean degree of the contact graph (§15.6: Poisson(6)). */
    val meanDegree: Double = 6.0,
    /** Mean number of conversation bursts per edge per day. */
    val burstsPerDay: Double = 0.5,
    /** A hand-written plan (the twin and seizure worlds); null draws one from [seed]. */
    val plan: Plan? = null,
    /** The share of bodies in `[2 221, 3 900]`, R-B1's 16 KiB class, in percent. */
    val longPercent: Int = 1,
) {
    companion object {
        fun of(scale: PrivacyScale, seed: Long, mutant: PrivacyMutant? = null): PrivacyWorldConfig =
            PrivacyWorldConfig(
                seed = seed,
                clients = scale.clients,
                days = scale.days,
                mutant = mutant,
                longPercent = if (scale == PrivacyScale.SMALL) 5 else 1,
            )
    }
}

/**
 * The world's behaviour, drawn entirely before the first event runs (see [PrivacyWorld]).
 */
internal class Plan private constructor(
    val activation: LongArray,
    val invitee: BooleanArray,
    val edges: List<Edge>,
    private val seed: Long,
) {
    class Edge(
        val initiator: Int,
        val responder: Int,
        val at: Long,
        val reject: Boolean,
        val timer: Timer,
        val bursts: List<Burst>,
    )

    class Burst(val start: Long, val messages: List<Message>)

    /** One message of a burst: which side writes it, after what delay, and how long it is. */
    class Message(val fromInitiator: Boolean, val delaySeconds: Long, val length: Int)

    fun install(world: PrivacyWorld) {
        for (c in activation.indices) {
            world.schedule(activation[c]) { world.activate(c) }
            val rnd = SplittableRandom(seed * 1_000_003L + c)
            world.schedule(activation[c] + DmWorld.MINUTE + rnd.nextLong(2 * DmWorld.HOUR)) {
                world.background(c, rnd)
            }
        }
        for (edge in edges) installEdge(world, edge)
    }

    private fun installEdge(world: PrivacyWorld, edge: Edge) {
        val u = edge.initiator
        val v = edge.responder
        // The one-scan flow of §12.2, in person: both are in the foreground.
        world.session(
            u, edge.at, 12,
            mapOf(
                0 to {
                    world.userAdd(u, v)
                    world.userSend(u, v, 12)
                },
                10 to {
                    if (edge.timer != Timer.DAYS_7 && world.trustOf(u, v) != null) {
                        world.userSetTimer(u, v, edge.timer)
                    }
                },
            ),
        )
        // The responder is there too; it decides the request at the first relay session that shows
        // it, in this session or, if the first flight is late, at its next one.
        world.schedule(edge.at) {
            world.pendingDecisions.getOrPut(v) { HashMap() }[u] = !edge.reject
        }
        world.session(v, edge.at + 2 * DmWorld.MINUTE, 10, emptyMap())
        if (edge.reject) return
        for (burst in edge.bursts) {
            var t = burst.start
            for (message in burst.messages) {
                t += message.delaySeconds
                val from = if (message.fromInitiator) u else v
                val to = if (message.fromInitiator) v else u
                world.session(
                    from, t, 3,
                    mapOf(
                        0 to {
                            if (world.trustOf(from, to) in SENDABLE) world.userSend(from, to, message.length)
                        },
                    ),
                )
            }
        }
    }

    companion object {
        private val SENDABLE = setOf("unverified", "verified")

        /** A hand-written plan: every client activates at [activation], no invitees. */
        fun scripted(activation: LongArray, edges: List<Edge>, seed: Long): Plan =
            Plan(activation, BooleanArray(activation.size), edges, seed)

        fun draw(config: PrivacyWorldConfig): Plan {
            val rnd = SplittableRandom(config.seed)
            val n = config.clients
            val start = config.startSeconds
            val end = start + config.days * DmWorld.DAY
            val invitee = BooleanArray(n) { it >= 2 && rnd.nextInt(10) == 0 }
            val activation = LongArray(n) { c ->
                if (invitee[c]) {
                    start + DmWorld.DAY + rnd.nextLong(minOf(6, config.days - 1).coerceAtLeast(1) * DmWorld.DAY)
                } else {
                    start + rnd.nextLong(DmWorld.DAY / 2)
                }
            }

            // The configuration model over Poisson(meanDegree) stubs; self-loops and repeats dropped.
            val stubs = ArrayList<Int>()
            for (c in 0 until n) repeat(poisson(rnd, config.meanDegree)) { stubs += c }
            for (i in stubs.indices.reversed()) {
                val j = rnd.nextInt(i + 1)
                val t = stubs[i]; stubs[i] = stubs[j]; stubs[j] = t
            }
            val pairs = LinkedHashSet<Pair<Int, Int>>()
            var i = 0
            while (i + 1 < stubs.size) {
                val a = stubs[i]; val b = stubs[i + 1]
                if (a != b) pairs += minOf(a, b) to maxOf(a, b)
                i += 2
            }
            // Every invitee messages its inviter first: one edge to an earlier, non-invitee client.
            val inviteEdges = LinkedHashMap<Int, Int>()
            for (c in 0 until n) {
                if (!invitee[c]) continue
                var inviter = rnd.nextInt(n)
                while (invitee[inviter] || inviter == c) inviter = rnd.nextInt(n)
                inviteEdges[c] = inviter
                pairs += minOf(c, inviter) to maxOf(c, inviter)
            }

            val edges = ArrayList<Edge>()
            for ((a, b) in pairs) {
                val invitation = inviteEdges[a] == b || inviteEdges[b] == a
                val initiator: Int
                val responder: Int
                if (invitation) {
                    initiator = if (inviteEdges[a] == b) a else b
                    responder = if (initiator == a) b else a
                } else if (rnd.nextBoolean()) {
                    initiator = a; responder = b
                } else {
                    initiator = b; responder = a
                }
                val ready = maxOf(activation[a], activation[b]) + 10 * DmWorld.MINUTE
                val at = if (invitation) {
                    activation[initiator] + 10 * DmWorld.MINUTE
                } else {
                    ready + rnd.nextLong(minOf(3L, config.days.toLong()) * DmWorld.DAY / 2 + 1)
                }
                if (at >= end - DmWorld.HOUR) continue
                val reject = !invitation && rnd.nextInt(100) < 3
                val timer = drawTimer(rnd)
                val bursts = ArrayList<Burst>()
                var t = at + DmWorld.HOUR
                while (true) {
                    t += exponential(rnd, DmWorld.DAY / config.burstsPerDay)
                    if (t >= end - DmWorld.HOUR) break
                    val messages = ArrayList<Message>()
                    var fromInitiator = rnd.nextBoolean()
                    val count = 1 + geometric(rnd, 0.45)
                    val offline = rnd.nextInt(10) < 3
                    for (k in 0 until count) {
                        val delay = when {
                            k == 0 -> 0L
                            offline && k == 1 -> DmWorld.HOUR + rnd.nextLong(5 * DmWorld.HOUR)
                            else -> logNormalSeconds(rnd, medianSeconds = 120.0, sigma = 1.0)
                        }
                        messages += Message(fromInitiator, delay, drawLength(rnd, config.longPercent))
                        fromInitiator = !fromInitiator
                    }
                    bursts += Burst(t, messages)
                }
                edges += Edge(initiator, responder, at, reject, timer, bursts)
            }
            return Plan(activation, invitee, edges, config.seed)
        }

        /** §15.6's timer mix. */
        private fun drawTimer(rnd: SplittableRandom): Timer = when (rnd.nextInt(100)) {
            in 0 until 60 -> Timer.DAYS_7
            in 60 until 70 -> Timer.DAYS_30
            in 70 until 75 -> Timer.OFF
            in 75 until 85 -> Timer.DAY_1
            in 85 until 95 -> Timer.HOUR_1
            else -> Timer.MIN_5
        }

        /**
         * Mostly short; 4 % up to the 4 KiB capacity; [longPercent] % across the 4/16 KiB boundary
         * of R-B1 (1 % at every scale but [PrivacyScale.SMALL], whose few hundred messages would
         * otherwise draw none in about one world of twelve, and PM-4 lives in that band).
         */
        private fun drawLength(rnd: SplittableRandom, longPercent: Int): Int = rnd.nextInt(100).let { r ->
            when {
                r < 80 - longPercent -> 1 + rnd.nextInt(120)
                r < 95 -> 121 + rnd.nextInt(1_380)
                r < 100 - longPercent -> 1_501 + rnd.nextInt(720)
                else -> 2_221 + rnd.nextInt(1_680)
            }
        }

        private fun poisson(rnd: SplittableRandom, mean: Double): Int {
            val limit = Math.exp(-mean)
            var k = 0
            var p = 1.0
            while (true) {
                p *= rnd.nextDouble()
                if (p <= limit) return k
                k++
            }
        }

        private fun geometric(rnd: SplittableRandom, p: Double): Int {
            var k = 0
            while (rnd.nextDouble() >= p) k++
            return k
        }

        private fun exponential(rnd: SplittableRandom, mean: Double): Long =
            (-Math.log(1.0 - rnd.nextDouble()) * mean).toLong().coerceAtLeast(DmWorld.MINUTE)

        private fun logNormalSeconds(rnd: SplittableRandom, medianSeconds: Double, sigma: Double): Long {
            // Box–Muller on the world's own stream, so a seed names one world.
            val u1 = 1.0 - rnd.nextDouble()
            val u2 = rnd.nextDouble()
            val z = Math.sqrt(-2.0 * Math.log(u1)) * Math.cos(2.0 * Math.PI * u2)
            val seconds = medianSeconds * Math.exp(sigma * z)
            return seconds.toLong().coerceIn(DmWorld.MINUTE, 6 * DmWorld.HOUR)
        }
    }
}

/**
 * Statement rewriting over a real connection: the SQL-level privacy mutants (§15.7, "implemented
 * only in `src/test`"), the mechanism `FaultyDmSqlExecutor.rewrite` gave S10 without its event bus.
 */
internal class RewritingSqlExecutor(
    private val delegate: SqlExecutor,
    private val rewrite: (String, List<Any?>) -> Pair<String, List<Any?>>,
) : SqlExecutor {
    override fun exec(sql: String, args: List<Any?>) {
        val (s, a) = rewrite(sql, args)
        delegate.exec(s, a)
    }

    override fun execUpdate(sql: String, args: List<Any?>): Int {
        val (s, a) = rewrite(sql, args)
        return delegate.execUpdate(s, a)
    }

    override fun query(sql: String, args: List<Any?>, onRow: (SqlExecutor.Row) -> Unit) {
        val (s, a) = rewrite(sql, args)
        delegate.query(s, a, onRow)
    }

    override fun <T> transaction(block: () -> T): T = delegate.transaction(block)

    override val inTransaction: Boolean get() = delegate.inTransaction

    override var userVersion: Int
        get() = delegate.userVersion
        set(value) {
            delegate.userVersion = value
        }
}
