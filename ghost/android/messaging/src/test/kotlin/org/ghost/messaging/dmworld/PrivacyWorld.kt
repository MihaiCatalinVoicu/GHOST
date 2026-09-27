package org.ghost.messaging.dmworld

import org.ghost.messaging.DmDevice
import org.ghost.messaging.DmWorld
import org.ghost.messaging.MovableClock
import org.ghost.messaging.api.AddContactResult
import org.ghost.messaging.api.CardSource
import org.ghost.messaging.api.ContactId
import org.ghost.messaging.api.MessageId
import org.ghost.messaging.api.MessageKind
import org.ghost.messaging.api.SendResult
import org.ghost.messaging.api.Timer
import org.ghost.messaging.port.ExpiryWake
import org.ghost.storage.JdbcSqlExecutor
import org.ghost.storage.MigrationRunner
import org.ghost.storage.SqlExecutor
import org.ghost.sync.api.SessionKind
import org.ghost.sync.api.SyncChange
import org.ghost.sync.api.SyncListener
import org.ghost.sync.engine.KeyedRandomSources
import org.ghost.sync.engine.QuietRunScheduler
import org.ghost.sync.engine.TrafficPolicy
import java.security.MessageDigest
import java.util.PriorityQueue
import java.util.SplittableRandom
import java.util.TreeSet

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
 *  - a periodic job every 1–4 hours (JobScheduler's period, stretched by Doze and the standby
 *    buckets), and foreground sessions of a few minutes while a user writes, scans or reads.
 *  **Not modelled:** key changes, restores, clock offsets, the ES slot-table change, HIGH mode,
 *  hostile modes but WITHHOLD_ALL_BUNDLES ([PrivacyWorldConfig.withholdAllBundles], a variant world
 *  of its own, §22.21) and the PQ-C cadence as a behaviour (the engine runs it on its own).
 *
 * **The triggers are production's** (phase review MD-2 and MD-3, design §22.36; until then every
 * foreground minute was a relay session start, the design's cadence and not the wiring's). The DM
 * actor runs every pass through the entry points `MessagingWiring` and `MessagingRuntime` use on a
 * device ([DmDevice.Wiring]), and the world decides only **when** Phase 7's scheduler and Android
 * would call them:
 *  - a **relay session start** ([DmDevice.relaySessionStart], the one trigger that may open a later
 *    bundle-fetch attempt) where Phase 7 opens a relay session: when the app becomes visible — one
 *    per foreground period, however many of the plan's sessions overlap in it — and at a periodic job
 *    while it is hidden, unless the job is a **quiet run** (Phase 8's `QuietRunScheduler`, one job in
 *    eight, drawn by the production component from a key of the world's seed), which opens no relay
 *    session. A job that comes while the app is visible returns at once (`SyncRuntime.runJob`);
 *  - the relay traffic of a session: at its start and then every minute while the app stays visible
 *    — the read lane's lists and fetches, the work lane's stores and registrations — as one model
 *    relay round per minute ([ViewRelay]); what the fetches deliver and the stores decide is handed to
 *    the actor as `INBOX` and `OUTCOMES` hints ([DmDevice.listener]), and every hint the DM layer's own
 *    commits make (`CAPABILITIES`, `TOPOLOGY`, …) reaches it through the same listener;
 *  - the **consumer tail** ([DmDevice.consumerTail]) after every background session and quiet run,
 *    whose output waits for the next session (it runs after the transport closed);
 *  - the **actor timer** (the production `ExpiryTimer`, scheduled by `MessagingRuntime`'s own schedule:
 *    the row deadlines, the owner's `t_pub` and week boundary, the next `EST-READY`) while the process
 *    runs — while the app is visible, and at a job or an alarm; while it is hidden the cached-app
 *    freezer has stopped it (Phase 7 design §5.1), so a wake that falls due then fires when the
 *    process next runs;
 *  - the **alarm** (`ExpiryAlarm`'s one inexact wake, the row deadlines alone) at its minute, which
 *    starts the process as the broadcast does (Doze's deferral of it is not modelled).
 * Every relay session is instantaneous (§22.30 item 4 (e)): its requests arrive in one world second,
 * and its session-start pass runs before its read lane lists (as the actor's pass runs a moment after
 * READY, before the first pair event), so a fetch attempt opened there is listed in that session.
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
    val relay = ViewRelay { now }.also { it.withholdBundles = config.withholdAllBundles }

    /** One wake a client's process is owed at [at] (the actor timer's or the alarm's). */
    internal class OwedWake(val at: Long, val task: () -> Unit) {
        var cancelled = false
    }

    /** One client of the world. */
    inner class Client(val index: Int) {
        private val executor: JdbcSqlExecutor = JdbcSqlExecutor(":memory:").also {
            MigrationRunner(it).migrate()
        }
        private val sql: SqlExecutor = config.mutant?.rewrite?.let { RewritingSqlExecutor(executor, it) } ?: executor
        val clock = MovableClock(config.startSeconds)
        val seeds: DmDevice.DeviceSeeds = seedsOf(config.seed, index)

        /** A turn of this client's DM actor that threw: the world fails on it (a throw ended the world before). */
        private val failed = ArrayList<Throwable>()

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
                wiring = DmDevice.Wiring(
                    timer = { delay, task -> scheduleTimer(this, delay, task) },
                    alarm = ExpiryWake { delay -> setAlarm(this, delay) },
                    failed = { failed += it },
                ),
            ),
            seeds = seeds,
        )

        /**
         * The hints the sync layer committed on this client's database and not yet handed to its actor
         * (see [flushHints]): the one listener slot of its `SyncDatabase`, as `MessagingWiring` fills
         * it, with the hand-off that posts on a device done by the world after the commit's step.
         */
        val hints = LinkedHashSet<SyncChange>()

        init {
            config.mutant?.configure?.invoke(device)
            device.stores.inbox.setListener(
                SyncListener { changes ->
                    hints += changes
                    hinted += index
                },
            )
        }

        /** Throws the first turn of this client's actor that failed, if any. */
        fun checkTurns() {
            failed.firstOrNull()?.let { throw AssertionError("c$index: a DM actor turn threw at $now", it) }
        }

        var activated = false

        /** The end of the foreground period the app is visible in (exclusive); before it, hidden. */
        var visibleUntil: Long = Long.MIN_VALUE

        /** The second of the last job or alarm that ran the process while it was hidden. */
        var thawedAt: Long = Long.MIN_VALUE

        /** The actor timer's wake that fell due while the process was frozen: it fires at the next run. */
        internal var overdueTimer: OwedWake? = null

        /** The alarm's pending wake. */
        internal var alarm: OwedWake? = null

        /** Periodic jobs so far, the index of the next one's quiet draw ("every job draws", `SyncRuntime.runJob`). */
        var jobs: Long = 0

        /**
         * Phase 8's quiet-run draw ([QuietRunScheduler], the production component) on a key of this
         * client's own, from the world's seed: a PRF of the key and the job's index, like the device's.
         */
        val quietRuns = QuietRunScheduler(KeyedRandomSources(quietKeyOf(config.seed, index)), clock)

        /**
         * Message ids of this client's user actions: JD6's `oracle_user_action` (§15.1). Only the
         * message a facade call is **for** is here — the one text a send created with the typed
         * text, the one TIMER_SET a timer change created — never anything else the call created
         * ([unexplained]).
         */
        val userMessages = HashSet<String>()

        /** Outgoing messages a user action created that are not what the user asked for. */
        val unexplained = ArrayList<String>()

        fun sync() {
            clock.now = now
            clock.monotonic = now * 1_000
        }

        fun close() {
            device.close()
            executor.close()
        }
    }

    /** The clients whose [Client.hints] are waiting for [flushHints]. */
    private val hinted = LinkedHashSet<Int>()

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

    /** The second of each client's last relay round (its read lane's lists), so one second holds one. */
    private val lastPoll = HashMap<Int, Long>()

    private val lastPass = HashMap<Int, Long>()

    /**
     * The second of a client's last DM pass — its last SWEEP, whatever triggered it — or null before
     * the first. Every trigger the world hands the actor runs a pass at that second (the actor
     * coalesces only hints that arrive while one is queued), so this is exact.
     */
    fun lastPassOf(c: Int): Long? = lastPass[c]

    /**
     * The seconds at which each client's relay sessions started (`MessagingWiring.onRelaySessionStart`):
     * ground truth of the trigger, and the only moments a later bundle-fetch attempt may open
     * (§21.7 point 5, phase review MD-2), which is what JD7's windows are built on ([Joins.Windows]).
     */
    val sessionStarts = HashMap<Int, TreeSet<Long>>()

    /**
     * The triggers the world handed the DM actors, by kind (session start, hint, timer, alarm, tail):
     * the production trigger mix this world ran, for the test's output and the design's notes.
     */
    val triggers = java.util.TreeMap<String, Long>()

    /**
     * JD7's establishment truth (§15.6: "one bundle fetch per establishment, reset or reconnect"):
     * every user send by a client to a peer it holds **no session** with, by the recorder's
     * [GroundTruth.sessions] — what the crypto port saw, never the reader's `dm_contact` row.
     */
    class Establishment(val reader: Int, val owner: Int, val at: Long)

    val establishments = ArrayList<Establishment>()

    /**
     * JD5's timer truth: each conversation's timer changes as the users made them, from the plan's
     * `edge.timer` through [userSetTimer], and the message id of each TIMER_SET. [queued] is true
     * when the setter held no session with the peer at the change (by the recorder's
     * [GroundTruth.sessions]), so the TIMER_SET waited as a pending item for `EST-READY`'s flush —
     * the path of NI-DM2's declared open defect (§22.21 item 2) — instead of being sealed at once.
     */
    class TimerChange(
        val setter: Int,
        val peer: Int,
        val at: Long,
        val oldCode: Int,
        val newCode: Int,
        val messageId: String?,
        val queued: Boolean,
    )

    val timerChanges = ArrayList<TimerChange>()

    /** The user texts, `message id hex → (sender, peer)`: JD5 checks each one's TTL. */
    val userTexts = HashMap<String, Pair<Int, Int>>()

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
            // Every hint an action's commits made reaches the actor in its own second: a device
            // posts it at the commit, and no step of the world may leave one behind.
            while (hinted.isNotEmpty()) flushHints(hinted.first())
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
        flushHints(c)
        // The user onboards with the app open: a foreground minute, whose relay session's start is
        // the first time trigger the activated DM layer gets.
        foreground(c, now + DmWorld.MINUTE)
    }

    /**
     * A periodic job (`SyncJobService`, `SyncRuntime.runJob`), then the next one 1–4 hours later.
     * Every job draws its quiet-run decision, whatever becomes of it. While the app is visible the
     * job returns at once; otherwise the process runs — an actor timer that fell due while it was
     * frozen fires first — and the job is a **quiet run** (no relay session, then the consumer tail)
     * or a **background relay session** followed by the consumer tail, which runs after the lanes and
     * the transport close, so what it enqueues waits for the next session.
     */
    fun background(c: Int, rnd: SplittableRandom) {
        job(c)
        schedule(now + DmWorld.HOUR + rnd.nextLong(3 * DmWorld.HOUR)) { background(c, rnd) }
    }

    private fun job(c: Int) {
        val client = clients[c]
        if (!client.activated) return
        val quiet = client.quietRuns.quiet(client.jobs++)
        count("jobs")
        if (now < client.visibleUntil) {
            count("jobs while the app is visible")
            return
        }
        client.thawedAt = now
        thaw(c)
        if (quiet) {
            count("quiet runs")
            tail(c, SessionKind.QUIET)
            return
        }
        count("background sessions")
        if (lastPoll[c] != now) round(c, sessionStart = true)
        tail(c, SessionKind.BACKGROUND)
    }

    /**
     * A foreground session of [minutes] minutes: the app is visible from [start] for that long, with a
     * relay round every minute ([foreground]) — the first of a foreground period is its relay
     * session's start — [atMinute]'s user actions after the minute's round, and the conversation
     * displayed at the end.
     */
    fun session(c: Int, start: Long, minutes: Int, atMinute: Map<Int, () -> Unit>) {
        val until = start + minutes * DmWorld.MINUTE
        for (k in 0 until minutes) {
            schedule(start + k * DmWorld.MINUTE) {
                foreground(c, until)
                atMinute[k]?.let {
                    clients[c].sync()
                    it()
                    store(c)
                }
                if (k == minutes - 1) displayAll(c)
            }
        }
        count("foreground sessions")
    }

    /**
     * The app is visible at this second and at least until [until]: the minute's relay round of its
     * foreground session, which starts that session when the app was hidden just before — after the
     * process ran what it owed (an actor timer that fell due while it was frozen). Overlapping
     * sessions of the plan are one foreground period, and one relay session.
     */
    private fun foreground(c: Int, until: Long) {
        val client = clients[c]
        if (!client.activated) return
        val starts = now >= client.visibleUntil
        client.visibleUntil = maxOf(client.visibleUntil, until)
        if (starts) thaw(c)
        if (lastPoll[c] == now) return
        round(c, sessionStart = starts)
    }

    /**
     * One relay round of a client at this second ([ViewRelay]): its session's start first when it is
     * one (`MessagingWiring.onRelaySessionStart`; on a device the pass runs a moment after READY,
     * before the read lane's first pair event, so an attempt it opens is listed in this session);
     * then the read lane's lists and fetches, what they delivered handed over as an `INBOX` hint; the
     * work lane's stores, whose outcomes are an `OUTCOMES` hint, and its registrations. A user whose
     * request arrived decides it now (the notification), and anything a reflex put in the outbox
     * reaches the relay in the same round, as it would.
     */
    private fun round(c: Int, sessionStart: Boolean) {
        val client = clients[c]
        lastPoll[c] = now
        client.sync()
        if (sessionStart) {
            relay.beginSession(c)
            sessionStarts.getOrPut(c) { TreeSet() } += now
            trigger(c, "session start") { it.relaySessionStart() }
        }
        if (relay.serve(c, client.device, ownNamespaces(c), contactBundles) > 0) commit(c, SyncChange.INBOX)
        store(c)
        relay.register(c, client.device)
        count("relay rounds")
        decidePending(c)
        config.mutant?.afterWake?.invoke(this, c)
        store(c)
    }

    /** The work lane's stores: the outbox collected, and the outcomes the relay decided hinted (`OUTCOMES`). */
    private fun store(c: Int) {
        if (relay.collect(c, clients[c].device) > 0) commit(c, SyncChange.OUTCOMES)
    }

    /**
     * A commit of the sync layer that the model relay stands in for (the fetch's, the store result's):
     * its hint, handed to the actor at once, with whatever the DM layer's own commits left.
     */
    private fun commit(c: Int, change: SyncChange) {
        clients[c].hints += change
        hinted += c
        flushHints(c)
    }

    /**
     * The consumer tail of a background session or a quiet run (`SyncRuntime.runConsumerTail`), with
     * the job budget's deadline less its reserve, from the production policy.
     */
    private fun tail(c: Int, kind: SessionKind) {
        val client = clients[c]
        client.sync()
        val deadline = client.clock.monotonicMillis() + POLICY.jobBudgetMillis - POLICY.consumerTailReserveMillis
        trigger(c, "consumer tail") { it.consumerTail.run(kind, deadline) }
    }

    /** The process runs (the app shown, a job, an alarm): the actor timer's wake owed while it was frozen fires first. */
    private fun thaw(c: Int) {
        val client = clients[c]
        val owed = client.overdueTimer ?: return
        client.overdueTimer = null
        trigger(c, "actor timer") { owed.task() }
    }

    /** `ExpiryTimer`'s scheduler for [client]: its one wake, [delay] seconds from now. */
    private fun scheduleTimer(client: Client, delay: Long, task: () -> Unit): () -> Unit {
        val wake = OwedWake(now + delay, task)
        schedule(wake.at) { fireTimer(client, wake) }
        return {
            wake.cancelled = true
            if (client.overdueTimer === wake) client.overdueTimer = null
        }
    }

    private fun fireTimer(client: Client, wake: OwedWake) {
        if (wake.cancelled) return
        if (now >= client.visibleUntil && now != client.thawedAt) {
            // Hidden: the cached-app freezer has stopped the process (Phase 7 design §5.1), and the
            // timer fires when it next runs.
            client.overdueTimer = wake
            return
        }
        trigger(client.index, "actor timer") { wake.task() }
    }

    /** `ExpiryAlarm` for [client]: the one inexact alarm, each call replacing the last (one request code). */
    private fun setAlarm(client: Client, delay: Long?) {
        client.alarm?.cancelled = true
        client.alarm = null
        if (delay == null) return
        val wake = OwedWake(now + delay) {}
        client.alarm = wake
        schedule(wake.at) { fireAlarm(client, wake) }
    }

    /** The alarm is due: its broadcast runs the process (an owed actor timer first), then `MessagingWiring.onAlarm`. */
    private fun fireAlarm(client: Client, wake: OwedWake) {
        if (wake.cancelled) return
        client.alarm = null
        client.thawedAt = now
        thaw(client.index)
        trigger(client.index, "alarm") { it.alarmFired() }
    }

    /** A trigger of [kind] handed to [c]'s actor now (each runs a pass at this second), then the hints it left. */
    private fun trigger(c: Int, kind: String, body: (DmDevice) -> Unit) {
        hand(c, kind, body)
        flushHints(c)
    }

    private fun hand(c: Int, kind: String, body: (DmDevice) -> Unit) {
        val client = clients[c]
        client.sync()
        lastPass[c] = now
        triggers.merge(kind, 1L, Long::plus)
        body(client.device)
        client.checkTurns()
    }

    /**
     * The hints [c]'s sync layer committed, handed to its actor through the production listener as a
     * committing thread hands them ([DmDevice.deliver]: one coalesced pass), then the hints that pass
     * committed in turn, until none is left. A pass that re-posts its own hint without end is a
     * finding, not a hang.
     */
    private fun flushHints(c: Int) {
        val client = clients[c]
        var handed = 0
        while (client.hints.isNotEmpty()) {
            check(++handed <= MAX_HINTS_AT_ONE_SECOND) { "c$c: $handed hint hand-offs at one second — a pass re-posts its own hint" }
            val changes = client.hints.toSet()
            client.hints.clear()
            hand(c, "hint") { it.deliver(changes) }
        }
        hinted -= c
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

    /** What a user action is for: the one message it should create, if any (JD6's oracle). */
    private sealed interface Expect {
        /** Adding a card, accepting or rejecting a request: no message of the user's. */
        data object Nothing : Expect

        /** A send: exactly the text the user typed. */
        class Text(val text: String) : Expect

        /** A timer change: one TIMER_SET. */
        data object TimerSet : Expect
    }

    /**
     * A user action through the facade. The message the action is **for** — the one text a send
     * created with the typed text, the one TIMER_SET of a timer change — is recorded as the user's
     * (JD6's `oracle_user_action`); anything else the call created goes to [Client.unexplained],
     * so a receipt piggy-backed on a send, or a message an acceptance created, maps to no user
     * action. Returns what the call returned and the id of the message it was for.
     */
    private fun <T> userAction(c: Int, peer: Int?, expect: Expect, body: () -> T): Pair<T, String?> {
        val before = outgoingIds(c)
        val result = body()
        val created = outgoingIds(c) - before
        if (created.isEmpty()) return result to null
        val contact = peer?.let { contactIdOf(c, it) }
        val views = contact?.let { clients[c].device.engine.conversation(it, created.size + 10, null) }.orEmpty()
        val byId = views.associateBy { hex(it.id.toByteArray()) }
        val wanted = created.sorted().firstOrNull { id ->
            val view = byId[id]
            view != null && view.outgoing && when (expect) {
                is Expect.Text -> view.kind == MessageKind.TEXT && view.text == expect.text
                Expect.TimerSet -> view.kind == MessageKind.TIMER_SET
                Expect.Nothing -> false
            }
        }
        wanted?.let { clients[c].userMessages += it }
        clients[c].unexplained += created - setOfNotNull(wanted)
        // The hints the call's commits made (a send's `EST-START` registers `P_c`, …) post their pass
        // behind the call, as behind the facade's actor turn on a device.
        flushHints(c)
        return result to wanted
    }

    fun userAdd(c: Int, peer: Int): AddContactResult {
        val card = requireNotNull(truth.clients[peer]?.card) { "client $peer has no card" }
        val (result, _) = userAction(c, null, Expect.Nothing) {
            clients[c].device.engine.addContact(card, CardSource.QR_IN_PERSON)
        }
        if (result == AddContactResult.ADDED) truth.cardSource[c to peer] = "in person"
        count("contacts added")
        config.mutant?.afterAdd?.invoke(this, c, peer)
        return result
    }

    fun userSend(c: Int, peer: Int, length: Int, quote: MessageId? = null): SendResult? {
        val contact = contactIdOf(c, peer) ?: return null
        val text = textOf(c, length)
        val at = now
        val establishing = (c to peer) !in truth.sessions
        val (result, id) = userAction(c, peer, Expect.Text(text)) { clients[c].device.engine.send(contact, text, quote) }
        if (establishing) establishments += Establishment(c, peer, at)
        id?.let { userTexts[it] = c to peer }
        count("sends")
        if (result != SendResult.QUEUED) count("sends not queued: $result")
        return result
    }

    /** The conversation timer the users set between [a] and [b] (§10.1: 7 d until one is set). */
    fun timerCodeOf(a: Int, b: Int): Int =
        timerChanges.lastOrNull { (it.setter == a && it.peer == b) || (it.setter == b && it.peer == a) }?.newCode
            ?: Timer.DAYS_7.code

    fun userSetTimer(c: Int, peer: Int, timer: Timer): SendResult? {
        val contact = contactIdOf(c, peer) ?: return null
        val at = now
        val old = timerCodeOf(c, peer)
        val establishing = (c to peer) !in truth.sessions
        val (result, id) = userAction(c, peer, Expect.TimerSet) { clients[c].device.engine.setTimer(contact, timer) }
        if (establishing) establishments += Establishment(c, peer, at)
        if (result == SendResult.QUEUED && id != null) {
            timerChanges += TimerChange(c, peer, at, old, timer.code, id, queued = establishing)
        } else {
            count("timers not queued: $result")
        }
        count("timers set")
        return result
    }

    /** Accepts (or rejects) the request of [peer], if there is one; true when it was decided now. */
    fun userDecide(c: Int, peer: Int, accept: Boolean): Boolean {
        if (trustOf(c, peer) != "request") return false
        val contact = contactIdOf(c, peer) ?: return false
        userAction(c, peer, Expect.Nothing) {
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

        /** The production traffic policy: the job budget and the consumer tail's reserve. */
        private val POLICY: TrafficPolicy = TrafficPolicy.DEFAULT

        /** Hint hand-offs to one client at one second before a pass re-posting its own hint is a finding. */
        private const val MAX_HINTS_AT_ONE_SECOND: Int = 256

        fun hex(bytes: ByteArray): String = bytes.joinToString("") { "%02x".format(it) }

        /** The key of a client's quiet-run draws: from the world's seed and its index (never shared). */
        fun quietKeyOf(seed: Long, index: Int): ByteArray =
            MessageDigest.getInstance("SHA-256").digest("ghost-privacy-quiet/$seed/$index".toByteArray())

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
    /**
     * Hostile mode WITHHOLD_ALL_BUNDLES (§15.6 "hostile modes", §21.7 point 6): no relay shows any
     * reader a bundle it does not own, so every establishment runs out its attempts (the JD7
     * variant of §21.7 point 6 and PM-31's detector; §22.21).
     */
    val withholdAllBundles: Boolean = false,
) {
    companion object {
        fun of(
            scale: PrivacyScale,
            seed: Long,
            mutant: PrivacyMutant? = null,
            withholdAllBundles: Boolean = false,
        ): PrivacyWorldConfig =
            PrivacyWorldConfig(
                seed = seed,
                clients = scale.clients,
                days = scale.days,
                mutant = mutant,
                longPercent = if (scale == PrivacyScale.SMALL) 5 else 1,
                withholdAllBundles = withholdAllBundles,
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
                // Ten minutes in, normally after `EST-READY`. A TIMER_SET set before a session
                // exists would wait for `EST-READY`'s flush, the path of NI-DM2's declared open
                // defect (§22.21 item 2); JD5 prints how many did, so its line never reads as
                // covering a path this world does not take.
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
