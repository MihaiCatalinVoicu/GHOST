package org.ghost.messaging.harness

/**
 * The crash-enumeration loop of Phase 9 design §15.3, slice S10.
 *
 * > For each scenario: run it without faults and record K events …; for every k crash at k, reboot
 * > …, check the structural invariants, run to quiescence, check everything. Every relay event also
 * > runs as "timeout after apply". Double crashes (the second during recovery) for SCN-A, SCN-B,
 * > SCN-F and SCN-I.
 *
 * **What a crash does to the step it interrupted.** The step is *lost*: the run goes on at the next
 * one. That is what a process death does to a user action whose transaction had not committed, and
 * it is the only model that keeps a crash run comparable to the recording run — a harness that
 * re-ran the interrupted step would be testing retry, which is the user's affordance and not an
 * atomicity property. What must hold either way is everything §15.3 asks for: the structural
 * invariants at the reboot, quiescence after it, and CS-2 at the end.
 *
 * **What is asserted in every run, faulted or not.** The structural invariants (at the reboot and
 * at the end), quiescence, and CS-2 — "`oracle_displayed` at most one row per device and
 * `message_id`", which here is the `dm_message` primary key plus the check that no message was
 * rendered twice in one conversation. What is asserted only in the **fault-free** run is the
 * scenario's own `finalChecks`, because a scenario that lost its third send to a crash cannot be
 * asked to have delivered it.
 */
internal class DmScenario(
    val name: String,
    /** Builds the nodes and everything before the armed phase. Never faulted. */
    val setup: (DmCrashWorld) -> Unit,
    /** The armed script. Each entry is named, so a failure says which step was running. */
    val steps: List<Step>,
    /** Checks that hold only when nothing was injected. */
    val finalChecks: (DmCrashWorld) -> Unit = {},
    /** Checks that hold in **every** run, including faulted ones. */
    val alwaysChecks: (DmCrashWorld) -> Unit = {},
    /** §15.3 runs double crashes for SCN-A, SCN-B, SCN-F and SCN-I. */
    val doubles: Boolean = false,
    /** Quiescence rounds after the script. */
    val tailRounds: Int = 24,
) {
    class Step(val label: String, val body: (DmCrashWorld) -> Unit)

    override fun toString(): String = "DmScenario($name)"
}

internal fun step(label: String, body: (DmCrashWorld) -> Unit): DmScenario.Step =
    DmScenario.Step(label, body)

/** How one run injects faults. Indices count the armed phase from 1. */
internal class DmRunSpec(
    val crashAt: Long? = null,
    val secondCrashAt: Long? = null,
    val storageFullAt: Long? = null,
    val timeoutAt: Long? = null,
    /** A plan of the caller's own (the seeded worlds); overrides the fields above. */
    val plan: ((DmCrashWorld) -> DmFaultPlan)? = null,
    /** Record every event's kind (the recording run). */
    val record: Boolean = false,
)

internal class DmRunResult(
    val events: Long,
    val kinds: List<DmEventKind>,
    val crashes: Int,
    val reboots: Int,
    val storageFulls: Int,
    val timeouts: Int,
    val digests: Map<String, String>,
)

/** Runs one [DmScenario] under one [DmRunSpec]. */
internal class DmCrashRunner(private val scenario: DmScenario) {

    /**
     * The fault-free recording run: K events, their kinds, and the scenario's own final checks.
     */
    fun record(): DmRunResult = run(DmRunSpec(record = true))

    fun run(spec: DmRunSpec): DmRunResult {
        DmCrashWorld(scenario.name).use { world ->
            scenario.setup(world)
            world.checkAll("setup")

            val kinds = ArrayList<DmEventKind>()
            var phase = 0
            var reboots = 0

            world.bus.plan = spec.plan?.invoke(world) ?: DmFaultPlan { e ->
                when {
                    phase == 0 && spec.crashAt == e.index -> DmFault.Crash
                    phase == 1 && spec.secondCrashAt == e.index -> DmFault.Crash
                    phase == 0 && spec.storageFullAt == e.index && e.kind.canBeFull ->
                        DmFault.StorageFull
                    phase == 0 && spec.timeoutAt == e.index && e.kind.relay ->
                        DmFault.TimeoutAfterApply

                    else -> null
                }
            }
            if (spec.record) world.bus.onEvent = { kinds += it.kind }
            world.bus.armed = true

            val onDeath: (Error) -> Unit = { death ->
                val node = nodeOf(death)
                check(world.bus.injected.lastOrNull() === death) {
                    "the crash that reached the top level is not the one injected: $death"
                }
                reboots++
                world[node].reboot()
                // §15.3: "check the structural invariants" — at the reboot, before anything runs.
                DmStructuralInvariants.check(world[node], "reboot $reboots of $node")
                if (phase == 0) {
                    phase = 1
                    world.bus.resetCount()
                } else {
                    phase = 2
                }
            }

            for (s in scenario.steps) {
                try {
                    s.body(world)
                } catch (death: SimulatedDmCrash) {
                    onDeath(death)
                } catch (death: SimulatedNativeCrash) {
                    onDeath(death)
                }
            }

            // Run to quiescence. A crash in the tail reboots and the tail starts again; the bound
            // on reboots is the bound on crash points the plan can still reach.
            var guard = 0
            while (true) {
                try {
                    world.quiesce(scenario.tailRounds)
                    break
                } catch (death: SimulatedDmCrash) {
                    onDeath(death)
                } catch (death: SimulatedNativeCrash) {
                    onDeath(death)
                }
                if (++guard > 8) break
            }

            world.bus.armed = false
            // One unarmed settling round, so a run whose last crash landed mid-round is compared at
            // the same place as the recording run.
            world.quiesce(scenario.tailRounds)

            world.checkAll("end")
            displayedAtMostOnce(world)
            onlyExpectedExceptionsWereSwallowed(world)
            scenario.alwaysChecks(world)
            if (!world.bus.faulted) scenario.finalChecks(world)

            return DmRunResult(
                events = world.bus.count,
                kinds = kinds,
                crashes = world.bus.injected.size,
                reboots = reboots,
                storageFulls = world.bus.storageFulls,
                timeouts = world.bus.timeouts,
                digests = world.nodes().associate { it.name to DmStructuralInvariants.digest(it) },
            )
        }
    }

    /**
     * CS-2, in the shape this harness can see it: **at most one row per device and `message_id`**.
     *
     * `dm_message.message_id` is the primary key, so a duplicate row cannot exist; what can, and
     * what CS-2 is really about, is the same message arriving twice under two ids and being
     * rendered twice. The `dm_seen` tag is what refuses that, so the check is: no conversation
     * renders two inbound messages with the same `(sort_minute, minute_index)` — the pair that
     * §7.7 makes the rendering order — which is exactly the duplicate a broken D1/D3 produces.
     */
    private fun displayedAtMostOnce(world: DmCrashWorld) {
        for (node in world.nodes()) {
            var duplicates = 0L
            node.raw.query(
                "SELECT count(*) FROM (SELECT conversation_id, sort_minute, minute_index " +
                    "FROM dm_message WHERE direction = 'in' " +
                    "GROUP BY conversation_id, sort_minute, minute_index HAVING count(*) > 1)",
            ) { duplicates = it.long(0) }
            if (duplicates != 0L) {
                dmViolation("${node.name}: CS-2 broken, $duplicates rendered positions hold two messages")
            }
        }
    }

    /**
     * A pass that threw is a finding unless the run asked for it.
     *
     * The device's actor thread absorbs whatever a pass throws (see [DmCrashWorld.swallowed]), so
     * without this check an engine that failed every pass would look exactly like one that
     * succeeded. What may be absorbed: nothing in a fault-free run, and — in a run that injected a
     * full disk — only a `StorageFullException`, because that is the one failure §7.8 says the
     * engine owes nothing more than a retry for.
     */
    private fun onlyExpectedExceptionsWereSwallowed(world: DmCrashWorld) {
        for (thrown in world.swallowed) {
            val full = generateSequence(thrown) { it.cause }
                .any { it is org.ghost.storage.StorageFullException }
            if (full && world.bus.storageFulls > 0) continue
            dmViolation(
                "${scenario.name}: a pass threw ${thrown::class.simpleName}: ${thrown.message}",
            )
        }
    }

    private fun nodeOf(death: Error): String = when (death) {
        is SimulatedDmCrash -> death.node
        is SimulatedNativeCrash -> death.node
        else -> error("not an injected death: $death")
    }

    /**
     * The enumeration of §15.3: the recording run, then one crash run per event, then one
     * "timeout after apply" run per relay event, then (for the four scenarios that ask for it) a
     * double crash per crash class.
     *
     * [sample] takes every n-th event instead of every one, so the same enumeration runs at a
     * local scale and at a gate scale; `1` is the gate.
     */
    fun enumerate(sample: Int = 1, doubles: Boolean = scenario.doubles): DmScenarioReport {
        val recorded = record()
        val tasks = ArrayList<Pair<String, () -> Unit>>()
        var singles = 0
        var doubleRuns = 0
        var timeouts = 0
        var k = 1L
        while (k <= recorded.events) {
            val at = k
            tasks += "${scenario.name} crash@$at" to { run(DmRunSpec(crashAt = at)); Unit }
            singles++
            if (doubles) {
                // The second crash lands early in the recovery phase, which is where §15.3 wants
                // it: "the second during recovery".
                tasks += "${scenario.name} crash@$at+3" to
                    { run(DmRunSpec(crashAt = at, secondCrashAt = 3)); Unit }
                doubleRuns++
            }
            k += sample
        }
        for ((index, kind) in recorded.kinds.withIndex()) {
            if (!kind.relay) continue
            val at = index + 1L
            if ((at - 1) % sample != 0L) continue
            tasks += "${scenario.name} timeout@$at" to { run(DmRunSpec(timeoutAt = at)); Unit }
            timeouts++
        }
        DmHarness.parallel(tasks)
        return DmScenarioReport(
            scenario = scenario.name,
            events = recorded.events,
            singles = singles,
            doubles = doubleRuns,
            timeouts = timeouts,
            relayEvents = recorded.kinds.count { it.relay },
        )
    }

    /**
     * SCN-J's other half: `SQLITE_FULL` at every statement, which is a typed failure and not a
     * death. The run must survive it — the engine rolls its transaction back, reports it and goes
     * on — and the world must still reach quiescence with every invariant intact.
     */
    fun enumerateStorageFull(sample: Int = 1): Int {
        val recorded = record()
        val tasks = ArrayList<Pair<String, () -> Unit>>()
        for ((index, kind) in recorded.kinds.withIndex()) {
            if (!kind.canBeFull) continue
            val at = index + 1L
            if ((at - 1) % sample != 0L) continue
            tasks += "${scenario.name} full@$at" to { run(DmRunSpec(storageFullAt = at)); Unit }
        }
        DmHarness.parallel(tasks)
        return tasks.size
    }
}

/** One scenario's line in the exit-gate report (§15.3: "dm crash classes: <n> singles, <m> doubles"). */
internal class DmScenarioReport(
    val scenario: String,
    val events: Long,
    val singles: Int,
    val doubles: Int,
    val timeouts: Int,
    val relayEvents: Int,
) {
    override fun toString(): String =
        "dm crash classes: $scenario $events events, $singles singles, $doubles doubles, " +
            "$timeouts timeouts over $relayEvents relay events"
}
