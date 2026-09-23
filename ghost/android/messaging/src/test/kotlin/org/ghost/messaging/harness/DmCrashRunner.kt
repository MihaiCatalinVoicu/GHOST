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
 * at the end), quiescence, CS-2 — "`oracle_displayed` at most one row per device and `message_id`",
 * which here is the `dm_message` primary key plus the check that no message was rendered twice in
 * one conversation — the post-sweep half of the T25 clause, and the two oracles §15.3 asks for at
 * quiescence: **session liveness** ("one more message each way decrypts") and **no loss** (a
 * message the sender calls `sent` exists on a recipient). What is asserted only in the
 * **fault-free** run is the scenario's own `finalChecks`, because a scenario that lost its third
 * send to a crash cannot be asked to have delivered it.
 *
 * **Why the two oracles are not optional.** Until they existed, every check a *faulted* run made
 * was a safety property: SCN-A accepted any subsequence of `{m1,m2,m3}`, SCN-B any prefix-ordered
 * subset, SCN-G only the resend bound. A defect that **deleted** work — a split send transaction,
 * a relay that dropped an operation on the floor — passed all of them at every one of the K crash
 * points, because a world with nothing in it breaks no safety property. Liveness and no-loss are
 * the two liveness properties that refuse that, and mutant MC-1 is the registered proof that they
 * can fail.
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
    /** §15.3 runs double crashes for SCN-A, SCN-B, SCN-F and SCN-I (SCN-J too; see its KDoc). */
    val doubles: Boolean = false,
    /** Quiescence rounds after the script. */
    val tailRounds: Int = 24,
    /**
     * §15.3's "at quiescence … session liveness (one more message each way decrypts)": the pair of
     * node names to send between, or null where the scenario's own end state forbids it.
     *
     * Null for SCN-D (the contact is `changed` and a send is refused by design), SCN-G (its last
     * step leaves a relay that refuses everything), RP9 and the CB replay (the contact was
     * rejected), and SCN-K (S10b: the contact is `revoked`, terminal by design). Those are the
     * scenarios whose subject *is* a refusal, and demanding liveness of them would be demanding
     * the opposite of what they assert. SCN-K replaces it with its own liveness property — the
     * revocation took effect, whole, in every run — in its `alwaysChecks`.
     */
    val liveness: Pair<String, String>? = null,
    /**
     * The liveness probe **in turn**: the second node sends only once the first node's probe has
     * been rendered, instead of both sending in the same round (S10b).
     *
     * Off everywhere except SCN-I, and it is not a loosening there. After a restore the contact
     * cannot learn that the restored device exists except from the restored device itself, and
     * everything it seals before it learns is sealed under the lost device's keys — §8.6's declared
     * residue, which SCN-I's own `alwaysChecks` assert stays unopenable. A simultaneous probe asks
     * the contact to answer a device it has not heard from yet, which is asking for that residue
     * to open. What stays demanded is exactly §15.3's sentence: one more message each way decrypts,
     * in the order the only party that knows of the restore can start it.
     */
    val livenessInTurn: Boolean = false,
    /**
     * The no-loss oracle: every message a device has marked `SENT` was rendered by some device.
     *
     * Off where a message may legitimately be sent and then gone: SCN-F and EP (the ephemeral
     * deadline removes it), SCN-D (held, not displayed, until the acknowledgement), RP9 (the relay
     * corrupts the blob on purpose, and the sender is still told the store succeeded), the CB
     * replay (the request was rejected and the contact deleted with it).
     */
    val noLoss: Boolean = false,
    /**
     * The texts this run's own semantics drop **by design**, which the no-loss oracle therefore
     * does not charge to the engine (S10b).
     *
     * An opt-out of one message and not of the oracle, and every scenario that uses it says why in
     * its own KDoc: SCN-K's message from a revoked identity that reaches its contact after the
     * revocation took effect is §8.5's "drops later blobs", and a message the sender calls `SENT`
     * and the recipient refuses is exactly what that sentence promises. It is read at the end of
     * the run, from the world's notes, so a scenario declares a loss only once the run has actually
     * put the message in the position that makes it one — a declaration made up front would excuse
     * a message a crash had lost for some other reason.
     */
    val declaredLoss: (DmCrashWorld) -> Set<String> = { emptySet() },
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
    /**
     * Told how many events the armed phase raised, **before** any check runs (S10b).
     *
     * A mutated world fails its checks, so its recording run never returns a [DmRunResult]; the
     * mutant kill rule still needs its event count, to crash it only at points it reaches.
     */
    val onArmedEvents: ((Long) -> Unit)? = null,
)

internal class DmRunResult(
    val events: Long,
    val kinds: List<DmEventKind>,
    val crashes: Int,
    val reboots: Int,
    val storageFulls: Int,
    val timeouts: Int,
    /**
     * Per node, the order it renders its inbound messages in — §7.7's `(sort_minute, minute_index)`
     * pairs, in the order the read path returns them.
     *
     * This is CS-4's own subject, and [DmCrashRunner.enumerate] compares it across the runs of one
     * scenario: which messages a run has differs (a crash may lose one, and may also *keep* one the
     * fault-free run's deadline deleted), but over the positions two runs have in common the order
     * may not. The field it replaces, `digests`, was computed on every run and read by nothing.
     */
    val renderOrder: Map<String, List<String>>,
    /** Event indices raised inside a split window (see [DmEventBus.vulnerable]); empty unmutated. */
    val vulnerable: List<Long>,
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
                // A process death is not a `finally`. `DmActor.runPass` runs one on the way out —
                // `schedule.afterCommit()` — so the "dead" device performs two more transactions
                // before this line is reached. They are read-only, and until now nothing said so;
                // a write there would make every crash run a crash-plus-one-transaction run
                // without a single test changing.
                if (world.bus.afterDeathWrites.isNotEmpty()) {
                    dmViolation(
                        "${scenario.name}: $node wrote after its process death: " +
                            world.bus.afterDeathWrites.joinToString(", "),
                    )
                }
                world.bus.deadNode = null
                world.bus.afterDeathWrites.clear()
                reboots++
                world[node].reboot()
                // §15.3: "check the structural invariants" — at the reboot, before anything runs.
                DmStructuralInvariants.check(
                    world[node], "reboot $reboots of $node", settled = false,
                )
                // §15.3 says "check the structural invariants" without naming a node, and a crash
                // class is a state of the **world**: the peer that did not die is half of it. Its
                // clauses are checked without the heavy `integrity_check`/`verifyIntegrity` pass,
                // which is a statement about a file that was just reopened and is the crashed
                // node's alone.
                for (other in world.nodes()) {
                    if (other.name == node) continue
                    DmStructuralInvariants.check(
                        other, "reboot $reboots of $node", heavy = false, settled = false,
                    )
                }
                // And the second half of §15.3's post-reboot clause, at the one moment it is a
                // statement about the reboot rather than about the pass that follows it: R-K1 has
                // just run and nothing has been built on top of it yet. Without this, "the WAL is 0
                // bytes" was asserted only by SCN-F and by the seeded worlds, so for SCN-A, SCN-B,
                // SCN-D, SCN-G, SCN-J and SCN-L no crash ever checked it.
                DmStructuralInvariants.checkpointEmptiedTheLog(
                    world[node], "reboot $reboots of $node",
                )
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
                } catch (finding: DmInvariantViolation) {
                    // A check a step makes on its own (EP, SCN-G-week) ends the run here; the
                    // event count it reached is still what a mutant kill has to crash inside.
                    spec.onArmedEvents?.invoke(world.bus.count)
                    throw finding
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
            spec.onArmedEvents?.invoke(world.bus.count)
            // One unarmed settling round, so a run whose last crash landed mid-round is compared at
            // the same place as the recording run.
            world.quiesce(scenario.tailRounds)

            // The fault the run asked for must have **happened**. Without this the gated counts are
            // attempts: a plan whose event index no longer names the statement it was drawn for
            // would leave `singles` and `timeouts` unchanged in the report while the run injected
            // nothing at all, and `dm-report-check.sh`'s "non-empty enumeration" rule would be
            // pinning the attempts.
            theRequestedFaultFired(spec, world)

            world.checkAll("end")
            displayedAtMostOnce(world)
            scenario.alwaysChecks(world)
            if (!world.bus.faulted) scenario.finalChecks(world)

            // §15.3's post-reboot T25 clause, at the end of the run: "after SWEEP and R-K1, no row
            // has `delete_at_minute <= now_e`". One more pass first, because the quiescence loop
            // ends by advancing the clock and a deadline crossed in that last step is owed to the
            // next sweep, not broken by this one.
            world.passes()
            for (node in world.nodes()) {
                DmStructuralInvariants.afterSweep(node, node.clock.now, "end")
                DmStructuralInvariants.retiredSessionsGone(node, node.clock.now, "end")
            }

            // The rendering order **before** the liveness sends, so the comparison across runs is
            // over what the scenario produced and not over two probes whose minute depends on how
            // many quiescence rounds the run happened to take.
            val order = world.nodes().associate { it.name to DmStructuralInvariants.renderOrder(it) }

            if (scenario.noLoss) noMessageTheSenderCallsSentIsMissing(world)
            scenario.liveness?.let { sessionIsStillLive(world, it) }
            // Last, so that anything the two oracles above provoked is included.
            onlyExpectedExceptionsWereSwallowed(world)

            return DmRunResult(
                events = world.bus.count,
                kinds = kinds,
                crashes = world.bus.injected.size,
                reboots = reboots,
                storageFulls = world.bus.storageFulls,
                timeouts = world.bus.timeouts,
                renderOrder = order,
                vulnerable = world.bus.vulnerable.toList(),
            )
        }
    }

    /** The plan named a point; the bus has to have injected there. */
    private fun theRequestedFaultFired(spec: DmRunSpec, world: DmCrashWorld) {
        if (spec.plan != null) return
        if (spec.crashAt != null && world.bus.injected.isEmpty()) {
            dmViolation(
                "${scenario.name}: the crash planned at event ${spec.crashAt} never fired — " +
                    "the run counted ${world.bus.count} events and injected nothing",
            )
        }
        if (spec.storageFullAt != null && world.bus.storageFulls == 0) {
            dmViolation(
                "${scenario.name}: the SQLITE_FULL planned at event ${spec.storageFullAt} never fired",
            )
        }
        if (spec.timeoutAt != null && world.bus.timeouts == 0) {
            dmViolation(
                "${scenario.name}: the timeout planned at relay event ${spec.timeoutAt} never fired",
            )
        }
    }

    /**
     * §15.3's no-loss oracle: a message a device has marked **SENT** was rendered somewhere.
     *
     * `SENT` is the engine's own statement that the op was released with a `sent` outcome, so it is
     * a promise to the user; a run in which that promise is false has lost a message. It is the one
     * check that fails on a defect which *deletes* work, and every other check a faulted run makes
     * is a safety property that an empty world satisfies.
     *
     * The recipient side is the **union** of every other device's rendered text, not a particular
     * one, because the worlds here are small and the pairing is a scenario's business rather than
     * this loop's.
     */
    private fun noMessageTheSenderCallsSentIsMissing(world: DmCrashWorld) {
        // Every conversation of every live node, and what a retired node had rendered before it was
        // lost (SCN-I). The first-contact-only `inboundTexts` was enough while every world was two
        // clients with one contact each; a device holding a request beside its contact is not.
        val rendered = world.nodes().flatMap { DmScripts.everyInboundText(it) }.toSet() +
            world.retiredRendered
        val declared = scenario.declaredLoss(world)
        for (node in world.nodes()) {
            for (text in DmScripts.sentTexts(world, node.name)) {
                if (text !in rendered && text !in declared) {
                    dmViolation(
                        "${scenario.name}: ${node.name} marked it sent and no device rendered it: " +
                            "\"$text\"",
                    )
                }
            }
        }
    }

    /**
     * §15.3's other oracle at quiescence: "session liveness (one more message each way decrypts)".
     *
     * A crash may lose the step it interrupted; it may not leave the two devices unable to talk. A
     * broken ratchet, a session slot demoted on one side only, a pending send nobody will ever
     * flush again — none of them shows up in a structural invariant, and all of them show up here.
     *
     * The relay is made honest first: a scenario's hostile mode is part of what it was testing, and
     * asking whether the *session* survived through a relay that is still flipping bytes asks two
     * questions at once.
     */
    private fun sessionIsStillLive(world: DmCrashWorld, pair: Pair<String, String>) {
        val (a, b) = pair
        world.relay.modes = emptySet()
        world.relay.outcomeFor = { "sent" }
        // A missing contact is a failure, not a pass. Every S10 scenario records its pair in the
        // unfaulted setup, where the two ids always exist, so the `?: return` this replaced never
        // fired; SCN-I records the restored device's contact in an **armed** step, and a crash
        // that lost that step would have turned the liveness oracle off for the run without a
        // word. The scenario re-adds the card when the user's action did not complete (see
        // `DmScenarios.scnI`), so a missing id here is a world that could not reconnect at all.
        val toB = world.contacts["$a->$b"]
            ?: dmViolation("${scenario.name}: the liveness pair has no contact $a->$b")
        val toA = world.contacts["$b->$a"]
            ?: dmViolation("${scenario.name}: the liveness pair has no contact $b->$a")
        world[a].device.engine.send(toB, LIVENESS_A, null)
        var answered = false
        if (!scenario.livenessInTurn) {
            world[b].device.engine.send(toA, LIVENESS_B, null)
            answered = true
        }
        for (round in 0 until LIVENESS_ROUNDS) {
            world.pump()
            world.passes()
            world.advanceBy(org.ghost.messaging.DmWorld.MINUTE)
            val there = DmScripts.inboundTexts(world, b).contains(LIVENESS_A)
            if (there && !answered) {
                // In turn (SCN-I): the answer goes only once the first probe has arrived, and it
                // then has the rounds that remain.
                world[b].device.engine.send(toA, LIVENESS_B, null)
                answered = true
                continue
            }
            if (there && DmScripts.inboundTexts(world, a).contains(LIVENESS_B)) return
        }
        val missing = buildList {
            if (!DmScripts.inboundTexts(world, b).contains(LIVENESS_A)) add("$a → $b")
            if (!DmScripts.inboundTexts(world, a).contains(LIVENESS_B)) add("$b → $a")
        }
        dmViolation(
            "${scenario.name}: the session is not live after the run — " +
                "${missing.joinToString(" and ")} did not decrypt in $LIVENESS_ROUNDS rounds",
        )
    }

    /**
     * CS-2, in the shape this harness can see it: **at most one row per device and `message_id`**.
     *
     * `dm_message.message_id` is the primary key, so a duplicate row cannot exist; what can, and
     * what CS-2 is really about, is the same message arriving twice under two ids and being
     * rendered twice. The `dm_seen` tag is what refuses that, so the check is: no conversation
     * renders two inbound messages with the same `(sort_minute, minute_index)` — the pair that
     * §7.7 makes the rendering order — which is exactly the duplicate a broken D1/D3 produces.
     *
     * **Where the proxy is not CS-2, declared.** `minute_index` is assigned by the author *device*,
     * so two devices of one identity writing into one conversation in the same minute collide here
     * without either being a duplicate — §7.7 settles them with its `message_id` tie-break and
     * nothing is rendered twice. The only place it can happen in this suite is SCN-D, whose whole
     * subject is a second device under one identity, and that scenario keeps the two a minute
     * apart rather than the check being loosened: a proxy that stopped firing on collisions would
     * stop firing on the duplicates it is for.
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

    private companion object {
        // Named so that no scenario's own `startsWith` filter picks them up: SCN-A reads "m…",
        // SCN-B "b…", SCN-L "l…" and the seeded worlds "s…".
        const val LIVENESS_A: String = "probe-out"
        const val LIVENESS_B: String = "probe-back"
        const val LIVENESS_ROUNDS: Int = 16

        /** How many distinct recovery events the double-crash enumeration walks (§15.3). */
        const val DOUBLE_RECOVERY_POINTS: Long = 7
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
        val tasks = ArrayList<Pair<String, () -> DmRunResult>>()
        var singles = 0
        var doubleRuns = 0
        var timeouts = 0
        var k = 1L
        while (k <= recorded.events) {
            val at = k
            tasks += "${scenario.name} crash@$at" to { run(DmRunSpec(crashAt = at)) }
            singles++
            if (doubles) {
                // The second crash lands in the recovery phase, which is where §15.3 wants it:
                // "the second during recovery". **Which** event of the recovery is a function of
                // the first crash point rather than the constant 3 it was, so the enumeration as a
                // whole walks the first several events of recovery instead of sampling one of them
                // ~K times. What stays out of reach either way is the recovery work that runs
                // before the counter restarts — migration, R-K1, `verifyIntegrity` and the new
                // client's own init transaction — and §22.15 item 16 records that.
                val second = 1 + (at % DOUBLE_RECOVERY_POINTS)
                tasks += "${scenario.name} crash@$at+$second" to
                    { run(DmRunSpec(crashAt = at, secondCrashAt = second)) }
                doubleRuns++
            }
            k += sample
        }
        for ((index, kind) in recorded.kinds.withIndex()) {
            if (!kind.relay) continue
            val at = index + 1L
            if ((at - 1) % sample != 0L) continue
            tasks += "${scenario.name} timeout@$at" to { run(DmRunSpec(timeoutAt = at)) }
            timeouts++
        }
        val results = DmHarness.parallel(tasks)
        renderOrderIsTheSameAcrossRuns(recorded, results)
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
     * CS-4's other half: "the rendered order is equal on both devices **and across all crash
     * runs**".
     *
     * Equal is too strong across runs and always was, in **both** directions. A crash may lose a
     * send, so a run can be missing a message the fault-free run rendered; and a crash can delay a
     * delivery past the deadline that deleted it in the fault-free run, so a run can *hold* a
     * message the fault-free run no longer has — SCN-F produces exactly that. So what is asserted
     * is the property that survives both: over the positions the two runs **have in common**, the
     * order is identical. A run that reordered two messages, or rendered one twice, fails it, and
     * those are the things CS-4 forbids; a run that has more or fewer of them does not.
     *
     * The positions are §7.7's `(sort_minute, minute_index)` pairs, which are the *author's* and
     * not the receiver's, so they do not move when a crash changes how many quiescence rounds a
     * run takes — and they are read through the engine's own page, so a rendering order taken from
     * a different column would fail here rather than agree with itself.
     */
    private fun renderOrderIsTheSameAcrossRuns(recorded: DmRunResult, runs: List<DmRunResult>) {
        for (result in runs) {
            for ((node, order) in result.renderOrder) {
                val reference = recorded.renderOrder[node] ?: continue
                val common = order.toSet() intersect reference.toSet()
                val here = order.filter { it in common }
                val there = reference.filter { it in common }
                if (here != there) {
                    dmViolation(
                        "${scenario.name}: $node rendered $here where the fault-free run rendered " +
                            "$there (CS-4 across crash runs)",
                    )
                }
            }
        }
    }

    /**
     * SCN-J's other half: `SQLITE_FULL` at every statement, which is a typed failure and not a
     * death. The run must survive it — the engine rolls its transaction back, reports it and goes
     * on — and the world must still reach quiescence with every invariant intact.
     *
     * The count it returns is the number of statements at which a full disk **fired**, not the
     * number it was planned at: every run asserts that its own injection happened
     * ([theRequestedFaultFired]), so a plan that stopped matching fails the run instead of
     * inflating the line the gate reads.
     */
    fun enumerateStorageFull(sample: Int = 1): Int {
        val recorded = record()
        val tasks = ArrayList<Pair<String, () -> DmRunResult>>()
        for ((index, kind) in recorded.kinds.withIndex()) {
            if (!kind.canBeFull) continue
            val at = index + 1L
            if ((at - 1) % sample != 0L) continue
            tasks += "${scenario.name} full@$at" to { run(DmRunSpec(storageFullAt = at)) }
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
    /**
     * The line itself, and the **only** place it is formatted.
     *
     * `DmReport.scenario` built a second, slightly different one and this `toString` was called by
     * nothing — so a slice that edited the wrong one either broke `dm-report-check.sh` or changed
     * nothing at all, with no way to tell which from reading either file. The relay-event
     * denominator is part of the line now, because "N timeouts" without it cannot be read: a gate
     * that reported 0 timeouts over 0 relay events and one that reported 0 over 900 are different
     * findings.
     */
    override fun toString(): String =
        "dm crash classes: $scenario $events events, $singles singles, $doubles doubles, " +
            "$timeouts timeouts over $relayEvents relay events"
}
