package org.ghost.sync.harness

import org.ghost.sync.api.Outcome
import org.ghost.sync.api.PrivacyMode
import org.ghost.sync.engine.Steps
import org.ghost.sync.engine.SessionKind
import org.ghost.sync.engine.TrafficPolicy
import java.util.concurrent.Callable
import java.util.concurrent.ExecutionException
import java.util.concurrent.Executors
import java.util.concurrent.Future
import java.util.concurrent.atomic.AtomicLong

/** Harness-wide settings (design §8.3, §8.5, §11.3). */
internal object Harness {
    /** The enumeration policy: production parameters with LIST_LIMIT = 4 (design §8.3). */
    val POLICY: TrafficPolicy = TrafficPolicy(listLimit = 4)

    /** Background job period (JobScheduler, 15 min); the quiescence tail advances only by it (§11.2 #4). */
    const val JOB_PERIOD: Long = 15 * World.MINUTE

    /** Seeded worlds: `-Dghost.sync.seeds` (the build forwards it; 20 000 in the sync-exit-gate job). */
    val seeds: Int get() = System.getProperty("ghost.sync.seeds")?.toIntOrNull() ?: 1_000

    /**
     * The sync-exit-gate job sets `-Dghost.sync.exhaustive=full`: double crashes in both journal
     * modes. The default build runs them in WAL mode (single crashes always run in both).
     */
    val fullExhaustive: Boolean get() = System.getProperty("ghost.sync.exhaustive") == "full"

    /** Outcome-truth invariants after every commit (on by default; a profiling switch). */
    @Volatile
    var checkEveryCommit: Boolean = true

    /** Worker threads for independent runs. */
    val threads: Int get() = System.getProperty("ghost.sync.threads")?.toIntOrNull() ?: Runtime.getRuntime().availableProcessors().coerceIn(1, 16)

    /** Every crash the buses injected and every crash the runner caught at the top level (§11.2 #11). */
    val injectedCrashes = AtomicLong()
    val caughtCrashes = AtomicLong()

    /** Runs [tasks] on [threads] workers; the first failure is rethrown with its label. */
    fun <T> parallel(tasks: List<Pair<String, () -> T>>): List<T> {
        if (tasks.isEmpty()) return emptyList()
        val pool = Executors.newFixedThreadPool(minOf(threads, tasks.size))
        try {
            val futures: List<Pair<String, Future<T>>> = tasks.map { (label, task) -> Pair(label, pool.submit(Callable { task() })) }
            return futures.map { (label, f) ->
                try {
                    f.get()
                } catch (e: ExecutionException) {
                    val cause = e.cause ?: e
                    throw AssertionError("$label: ${cause.message}", cause)
                }
            }
        } finally {
            // Tasks not started are dropped; running ones finish before the caller goes on, so no run
            // outlives its test (the crash counters stay exact).
            pool.shutdownNow()
            pool.awaitTermination(10, java.util.concurrent.TimeUnit.MINUTES)
        }
    }
}

/** What identifies the world a crash leaves behind (design §8.3 enumeration, verified by digests). */
internal data class CrashKey(
    val dirtyCommits: Long,
    val autocommitWrites: Long,
    val relayMutations: Long,
    val worldActions: Long,
    val records: Long,
    val rebootAt: Long?,
    val boots: Int,
    val bootScript: Int,
    /** A store call in flight: what a crash inside it adds to the records. */
    val storePhase: Int,
    val scriptState: Long,
)

/** A scenario of design §8.3 (or a seeded world, §8.5). */
internal abstract class Scenario(val name: String) {
    /** Longest quiescence tail, in job periods. */
    open val maxTailRounds: Int = 48

    /** The tail plays Phase 8: it installs the capabilities `needed()` reports (liveness premise). */
    open val renewCapabilitiesInTail: Boolean = true

    /** Builds relays, clients, setup (unarmed) and the timeline; sets [World.endMillis]. */
    abstract fun build(w: World)

    /**
     * Outcomes accepted for an op (SENT unless the script made it infeasible; the reason is the
     * override). [w] tells whether faults were injected (some scenarios pin the exact outcome only
     * in the fault-free run; the truth of every outcome is checked structurally in every run).
     */
    open fun allowed(op: OpRecord, w: World): Set<Outcome> = setOf(Outcome.SENT)

    /** Scenario-specific checks at the end. */
    open fun finalChecks(w: World) {}

    /** A mutant substitution for the armed client (design §8.8), or null for the real engine. */
    var mutation: Mutation? = null

    /** The armed client, with [mutation] applied. */
    protected fun subject(
        w: World,
        name: String,
        mode: PrivacyMode = PrivacyMode.STANDARD,
        policy: TrafficPolicy = Harness.POLICY,
        consumer: ConsumerPolicy = ConsumerPolicy(),
    ): Client {
        val m = mutation
        val consumerPolicy = if (m?.consumeOutsideTransaction == true) {
            ConsumerPolicy(consumer.paused, consumer.deferOnce, consumer.deferSeconds, consumeOutsideTransaction = true)
        } else {
            consumer
        }
        return w.client(ClientSpec(name, armed = true, mode = mode, policy = policy, steps = m?.steps ?: Steps.DEFAULT, consumer = consumerPolicy, rewrite = m?.rewrite?.invoke(w)))
    }

    override fun toString(): String = "Scenario($name)"
}

/** How one run injects faults. Event indices count the armed phase from 1; a second crash counts again from the first reboot. */
internal class RunSpec(
    val crashAt: Long? = null,
    val secondCrashAt: Long? = null,
    val networkFaultAt: Long? = null,
    val networkCategory: String = "timeout",
    /** Record the classification key of every event (and of every recovery event after the first crash). */
    val classify: Boolean = false,
    /** Stop after the first reboot's structural check and digest (a class already recovered). */
    val stopAfterFirstReboot: Boolean = false,
    /** A custom plan (seeded worlds); overrides the fields above. */
    val plan: ((World) -> FaultPlan)? = null,
    /** Keep the lines of the first reboot's digest (diagnosing a classification mismatch). */
    val dump: Boolean = false,
)

internal class RunResult(
    val events: Long,
    val keys: List<CrashKey>,
    val recoveryKeys: List<CrashKey>,
    val recoveryKinds: List<EventKind>,
    val kinds: List<EventKind>,
    val crashes: Int,
    val tailRounds: Int,
    val firstRebootDigest: String?,
    val firstCrashKey: CrashKey?,
    val millis: Long,
) {
    var firstRebootDump: List<String>? = null
}

/** Runs one scenario world under one [RunSpec] (design §8.3, §8.4). */
internal class Runner(private val scenario: Scenario, private val journal: JournalMode, private val seed: Long = 1) {

    private var phase = 0
    private var tailRound = 0

    fun run(spec: RunSpec): RunResult {
        val started = System.nanoTime()
        World(scenario.name, seed, journal).use { w ->
            scenario.build(w)
            val keys = ArrayList<CrashKey>()
            val kinds = ArrayList<EventKind>()
            val recoveryKeys = ArrayList<CrashKey>()
            val recoveryKinds = ArrayList<EventKind>()
            var crashes = 0
            var firstDigest: String? = null
            var firstKey: CrashKey? = null
            var firstDump: List<String>? = null
            phase = 0
            tailRound = 0
            w.bus.plan = spec.plan?.invoke(w) ?: FaultPlan { e ->
                when {
                    phase == 0 && spec.crashAt == e.index -> Fault.Crash
                    phase == 1 && spec.secondCrashAt == e.index -> Fault.Crash
                    phase == 0 && spec.networkFaultAt == e.index -> Fault.Network(spec.networkCategory)
                    else -> null
                }
            }
            if (spec.classify) {
                w.bus.onEvent = { e ->
                    if (phase == 0) {
                        check(keys.size.toLong() == e.index - 1) { "event counter out of step" }
                        keys += key(w)
                        kinds += e.kind
                    } else if (phase == 1) {
                        recoveryKeys += key(w)
                        recoveryKinds += e.kind
                    }
                }
            }
            w.bus.armed = true
            var stop = false
            val onCrash: (SimulatedCrash) -> Unit = { crash ->
                crashes++
                Harness.caughtCrashes.incrementAndGet()
                check(w.bus.injected.lastOrNull() === crash) { "the crash that reached the top level is not the one injected" }
                val keyAtCrash = key(w)
                reboot(w)
                if (crashes == 1) {
                    firstKey = keyAtCrash
                    firstDigest = Invariants.digest(w)
                    if (spec.dump) firstDump = Invariants.dump(w)
                    if (spec.stopAfterFirstReboot) stop = true
                }
                if (phase == 0) {
                    phase = 1
                    w.bus.resetCount()
                } else {
                    phase = 2
                }
            }
            if (!drive(w, onCrash, { stop }) { w.driver.runUntil(w.endMillis) }) {
                return result(w, keys, recoveryKeys, recoveryKinds, kinds, crashes, 0, firstDigest, firstKey, started).also { it.firstRebootDump = firstDump }
            }
            val tailDone = drive(w, onCrash, { stop }) { tail(w) }
            val rounds = tailRound
            if (!tailDone) return result(w, keys, recoveryKeys, recoveryKinds, kinds, crashes, rounds, firstDigest, firstKey, started).also { it.firstRebootDump = firstDump }
            w.bus.armed = false
            w.clients.forEach { Invariants.structural(it, "end") }
            w.clients.forEach { Invariants.quotaCharges(it) }
            Invariants.storeWindow(w)
            scenario.finalChecks(w)
            return result(w, keys, recoveryKeys, recoveryKinds, kinds, crashes, rounds, firstDigest, firstKey, started).also { it.firstRebootDump = firstDump }
        }
    }

    private fun result(
        w: World,
        keys: List<CrashKey>,
        recoveryKeys: List<CrashKey>,
        recoveryKinds: List<EventKind>,
        kinds: List<EventKind>,
        crashes: Int,
        rounds: Int,
        digest: String?,
        key: CrashKey?,
        started: Long,
    ): RunResult {
        if (w.bus.injected.size != crashes) throw AssertionError("an injected crash did not reach the top level")
        return RunResult(
            if (keys.isNotEmpty()) keys.size.toLong() else w.bus.count, keys, recoveryKeys, recoveryKinds, kinds, crashes, rounds, digest, key,
            (System.nanoTime() - started) / 1_000_000,
        )
    }

    /**
     * Runs [block] until it returns; an injected crash that reaches this top level is handled by
     * [onCrash] (reboot) and the block runs again. Returns false when [stop] asks to end early.
     */
    private fun drive(w: World, onCrash: (SimulatedCrash) -> Unit, stop: () -> Boolean, block: () -> Unit): Boolean {
        while (true) {
            try {
                block()
                return true
            } catch (crash: SimulatedCrash) {
                onCrash(crash)
                if (stop()) return false
            }
        }
    }

    /** Process restart of the subject after an injected crash (design §8.1). */
    private fun reboot(w: World) {
        val s = w.subject
        val crashTime = maxOf(w.clock.millis, w.driver.time)
        s.kill()
        s.boot()
        Invariants.recordLeftInFlight(s)
        Invariants.structural(s, "reboot")
        val foreground = s.foregroundUntil > crashTime
        val rebootAt = if (foreground) crashTime else w.driver.nextSessionStart(s, crashTime)
        if (foreground) {
            w.driver.scheduleSession(crashTime, s, "fg-restart:${s.name}") { if (s.session == null) s.startSession(SessionKind.FOREGROUND) }
        }
        rebootAt?.let { s.oracle.drainAt(it) }
    }

    private fun key(w: World): CrashKey {
        val s = w.subject
        val t = maxOf(w.clock.millis, w.driver.time)
        val rebootAt = if (s.foregroundUntil > t) t else w.driver.nextSessionStart(s, t)
        return CrashKey(s.sql.dirtyCommits, s.sql.autocommitWrites, w.relayMutations(), w.driver.worldActions, w.records.version, rebootAt, s.boots, s.bootstrapScript.size, s.port.storePhase, w.scriptState)
    }

    /**
     * The fault-free quiescence tail (design §8.4): rounds one job period apart; each round plays
     * Phase 8 (installs needed capabilities), runs one background job per client and drains the
     * consumers; it ends when every quiescence invariant holds. The clock advances only by the job
     * schedule, never past a backoff (§11.2 #4). Resumable after a crash: a round interrupted by a
     * crash still ends at its slot, and the next round starts one period later.
     */
    private fun tail(w: World) {
        while (true) {
            w.clients.forEach { Invariants.structural(it, "tail round $tailRound", heavy = false) }
            val problems = w.clients.flatMap { c -> Invariants.quiescenceProblems(c) { op -> scenario.allowed(op, w) }.map { "${c.name}: $it" } }
            if (problems.isEmpty() && !w.driver.busy) return
            if (tailRound >= scenario.maxTailRounds) throw InvariantViolation("no quiescence after $tailRound tail rounds: $problems")
            val slot = w.endMillis + tailRound * Harness.JOB_PERIOD
            tailRound++
            if (scenario.renewCapabilitiesInTail) w.at(slot, "phase8") { w.clients.forEach { renewNeeded(it) } }
            for (c in w.clients) {
                w.driver.scheduleSession(slot, c, "tail-job:${c.name}") { if (c.session == null) c.startSession(SessionKind.BACKGROUND) }
                w.driver.scheduleProcess(slot + Harness.JOB_PERIOD - 1, c, "tail-drain:${c.name}") { c.oracle.drain() }
            }
            w.driver.runUntil(slot + Harness.JOB_PERIOD - 1)
        }
    }

    /** Phase 8's part in the tail: a fresh token for every need `Capabilities.needed()` reports. */
    private fun renewNeeded(c: Client) {
        for (need in c.stores.capabilities.needed()) {
            val node = c.relayIds.entries.firstOrNull { it.value == need.relay }?.let { c.world.relays[it.key] } ?: continue
            c.capability(node, need.namespace, need.kind)
        }
    }
}

/** Scenario timeline helpers. */
internal fun World.jobs(c: Client, from: Long, to: Long, every: Long = Harness.JOB_PERIOD) {
    var t = from
    while (t <= to) {
        driver.scheduleSession(t, c, "job:${c.name}") { if (c.session == null) c.startSession(SessionKind.BACKGROUND) }
        t += every
    }
}

/** A foreground window [from, to): a running background session drains first (design §1.4). */
internal fun World.foreground(c: Client, from: Long, to: Long) {
    driver.scheduleSession(from, c, "fg:${c.name}") {
        c.foregroundUntil = to
        val s = c.session
        if (s == null) {
            c.startSession(SessionKind.FOREGROUND)
        } else {
            c.foregroundPending = true
            s.stop()
        }
    }
    at(to, "fg-stop:${c.name}") {
        c.foregroundUntil = Long.MIN_VALUE
        c.foregroundPending = false
        c.session?.stop()
    }
    driver.onSessionFinished = { client, _ ->
        if (client.foregroundPending && client.foregroundUntil > clock.millis && client.session == null) {
            client.foregroundPending = false
            client.startSession(SessionKind.FOREGROUND)
        }
    }
}
