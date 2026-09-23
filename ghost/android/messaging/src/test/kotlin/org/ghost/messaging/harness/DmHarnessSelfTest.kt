package org.ghost.messaging.harness

import org.ghost.messaging.DmWorld
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test

/**
 * The harness testing itself, before any scenario trusts it (Phase 9 design §15.3; the "control"
 * discipline §15.9 item 7 states for the equivalence comparator: *a check that cannot fail is not
 * a check*).
 *
 * Every one of these is a control for a way the crash mechanism could be silently vacuous:
 *  1. the bus really counts events and the count is stable run to run;
 *  2. an injected crash really unwinds, and it is the one that was injected;
 *  3. a reboot really reopens the same file and finds the committed rows;
 *  4. a reboot really loses the uncommitted ones;
 *  5. the structural-invariant checker really fails on a broken database;
 *  6. `SQLITE_FULL` really arrives as a `StorageFullException` and not as a death;
 *  7. R-K1 really truncates the log at every open;
 *  8. the "nothing owed" oracle really fails on work left owed or given up — and the no-loss and
 *     liveness oracles, on the same worlds, really do not (S10b review);
 *  9. SCN-C's two checks of its own really fail on what they are about: an establishment whose
 *     attempt budget never runs out, and a relay that stops withholding the newest bundle (S10c).
 *
 * Without 5 in particular the whole enumeration could pass on an engine that writes nothing.
 */
class DmHarnessSelfTest {

    private fun requireNative() = assumeTrue(DmHarness.SKIP_MESSAGE, DmHarness.nativeAvailable())

    /** 1: the counter runs, and the same scenario produces the same K twice. */
    @Test
    fun theEventCounterIsStableAcrossRuns() {
        requireNative()
        val runner = DmCrashRunner(DmScenarios.scnA())
        val first = runner.record()
        val second = runner.record()
        assertTrue("a recording run produced no events", first.events > 0)
        assertEquals("the same scenario produced a different K", first.events, second.events)
        assertEquals(0, first.crashes)
        assertEquals(0, first.reboots)
    }

    /** 2: a planned crash unwinds to the top level, and the runner reboots exactly once. */
    @Test
    fun aPlannedCrashUnwindsAndIsFollowedByExactlyOneReboot() {
        requireNative()
        val scenario = DmScenarios.scnA()
        val runner = DmCrashRunner(scenario)
        val events = runner.record().events
        val result = runner.run(DmRunSpec(crashAt = events / 2))
        assertEquals("the crash did not reach the top level", 1, result.crashes)
        assertEquals("the crash did not cause a reboot", 1, result.reboots)
    }

    /** 3 and 4: a reboot keeps what committed and loses what did not. */
    @Test
    fun aRebootKeepsCommittedRowsAndLosesUncommittedOnes() {
        requireNative()
        DmCrashWorld("self-test").use { world ->
            val node = world.node("alice", 0x41)
            node.device.engine.onActivated()
            val cardBefore = node.device.card().joinToString("") { "%02x".format(it) }
            val selfRows = DmScripts.count(world, "alice", "SELECT count(*) FROM dm_self")
            assertEquals("ACTIVATE wrote the identity row", 1L, selfRows)

            // Uncommitted work: a transaction that throws on the way out.
            runCatching {
                node.sql.transaction {
                    node.sql.exec(
                        "INSERT INTO dm_orphan_namespace(namespace_id) VALUES (?)",
                        listOf(ByteArray(32) { 7 }),
                    )
                    throw IllegalStateException("rolled back")
                }
            }
            node.reboot()

            assertEquals(2, node.boots)
            assertEquals(
                "the reboot lost a committed identity row",
                1L,
                DmScripts.count(world, "alice", "SELECT count(*) FROM dm_self"),
            )
            assertEquals(
                "the reboot kept a rolled-back row",
                0L,
                DmScripts.count(world, "alice", "SELECT count(*) FROM dm_orphan_namespace"),
            )
            // The same derived identity comes back: a reboot is the same device, not a new one.
            assertEquals(cardBefore, node.device.card().joinToString("") { "%02x".format(it) })
            // And the second boot draws from its own random stream (§15.3's "build a new client").
            assertNotEquals(
                "the second boot repeated the first boot's random draw",
                node.device.random.bytes(16).joinToString(""),
                DmCrashWorld("stream-control").use { other ->
                    other.node("alice", 0x41).device.random.bytes(16).joinToString("")
                },
            )
        }
    }

    /** 5: the invariant checker is not vacuous — a hand-broken database fails it. */
    @Test
    fun theStructuralInvariantCheckerFailsOnABrokenDatabase() {
        requireNative()
        DmCrashWorld("self-test-invariants").use { world ->
            val node = world.node("alice", 0x41)
            node.device.engine.onActivated()
            DmStructuralInvariants.check(node, "control")

            // A held row on a contact that is not `changed` — one of the §15.3 clauses.
            node.raw.exec(
                "INSERT INTO dm_contact(contact_id, identity_pk, card_env, card_index, " +
                    "trust_state, source, establishment) VALUES (?, ?, ?, 0, 'verified', " +
                    "'qr_in_person', 'card_only')",
                listOf(ByteArray(16) { 3 }, ByteArray(32) { 4 }, ByteArray(159) { 5 }),
            )
            node.raw.exec(
                "INSERT INTO dm_held(held_id, contact_id, identity, l1_env, gen_id, " +
                    "hold_until_minute, relay_expiry_hour, consume_minute) " +
                    "VALUES (?, ?, ?, ?, 1, 0, 0, 0)",
                listOf(ByteArray(16) { 6 }, ByteArray(16) { 3 }, ByteArray(32) { 4 }, ByteArray(64) { 7 }),
            )
            val failure = runCatching { DmStructuralInvariants.check(node, "broken") }.exceptionOrNull()
            assertTrue(
                "the checker accepted a held row on a 'verified' contact: $failure",
                failure is DmInvariantViolation,
            )
            assertTrue(
                "the failure does not name the clause it broke: ${failure?.message}",
                failure?.message?.contains("held row") == true,
            )
        }
    }

    /** 6: an injected `SQLITE_FULL` is a typed failure, not a death. */
    @Test
    fun anInjectedStorageFullArrivesAsAStorageFullException() {
        requireNative()
        DmCrashWorld("self-test-full").use { world ->
            val node = world.node("alice", 0x41)
            world.bus.plan = DmFaultPlan { e -> if (e.kind.sql) DmFault.StorageFull else null }
            world.bus.armed = true
            val failure = runCatching { node.device.engine.onActivated() }.exceptionOrNull()
            world.bus.armed = false
            assertTrue(
                "a full disk reached the caller as $failure",
                generateSequence(failure) { it.cause }
                    .any { it is org.ghost.storage.StorageFullException },
            )
            assertTrue("the bus did not count the injection", world.bus.storageFulls > 0)
            assertTrue("a full disk was counted as a death", world.bus.injected.isEmpty())
        }
    }

    /**
     * 8: the "nothing owed" oracle sees what the other two cannot (S10b review).
     *
     * Two worlds, each run twice — with the oracle and without it, no-loss and liveness on both
     * times. In the first, a scheduled reconnect is left due thirty days out, beyond anything
     * quiescence reaches: the work is owed, and the liveness probe — a user send, which discharges
     * a scheduled reconnect (§8.6: "skipped if the user sends to that contact earlier") — makes it
     * vanish, which is the masking by which the review's stranded-send mutant passed every crash
     * point of SCN-I. In the second, every relay
     * refuses one message: it ends FAILED, which is not `SENT`, so no-loss has nothing to say. Both
     * worlds pass without the oracle and fail with it, for the reason it names.
     */
    @Test
    fun theNothingOwedOracleSeesWorkTheOtherOraclesDoNot() {
        requireNative()
        val stranded = step("a reconnect scheduled beyond quiescence") { w ->
            w["alice"].raw.exec(
                "INSERT INTO dm_scheduled(sched_id, contact_id, what, payload, due_minute) " +
                    "VALUES (?, ?, 'reconnect', NULL, ?)",
                listOf(
                    ByteArray(16) { 9 },
                    DmScripts.contact(w, "alice", "bob").toByteArray(),
                    w["alice"].clock.now.let { it - Math.floorMod(it, 60L) } + 30 * DmWorld.DAY,
                ),
            )
        }
        val refused = step("every relay refuses one message") { w ->
            w.relay.refusing = setOf("alice")
            w["alice"].device.engine.send(DmScripts.contact(w, "alice", "bob"), "given up", null)
            w.pump()
            w.passes()
            w.relay.refusing = emptySet()
        }
        for ((what, body) in listOf("scheduled controls" to stranded, "gave up on [given up]" to refused)) {
            DmCrashRunner(controlWorld(body, nothingOwed = false)).run(DmRunSpec())
            val failure = runCatching {
                DmCrashRunner(controlWorld(body, nothingOwed = true)).run(DmRunSpec())
            }.exceptionOrNull()
            assertTrue("the oracle accepted a world that left work owed: $failure", failure is DmInvariantViolation)
            assertTrue(
                "the oracle failed, but not for the reason it states: ${failure?.message}",
                failure?.message?.contains(what) == true,
            )
        }
    }

    private fun controlWorld(body: DmScenario.Step, nothingOwed: Boolean) = DmScenario(
        name = "nothing-owed-control",
        liveness = "alice" to "bob",
        noLoss = true,
        nothingOwed = nothingOwed,
        setup = { world ->
            world.node("alice", 0x41)
            world.node("bob", 0x51)
            DmScripts.activate(world)
            DmScripts.establishBothWays(world, "alice", "bob")
        },
        steps = listOf(body),
    )

    /**
     * 9: SCN-C's own checks are not vacuous (S10c).
     *
     * SCN-C adds two oracles no other scenario has — the spent fetch budget of §21.7 point 5 and
     * the older generation a withheld newest bundle forces — and both could pass for nothing: a
     * budget check over a world that never reached its third window, a generation check over a
     * world in which the relay withheld nothing. So, beside the clean run, two worlds that break
     * one thing each, and each must fail for the reason it names:
     *  - an **unbounded budget**: `dm_contact.fetch_attempts` is never written above 1, so
     *    `EST-END` schedules another window for ever — the behaviour privacy mutant PM-31 names
     *    (§15.7). A control here, not a registered mutant: PM-31 belongs to S11's privacy registry
     *    and its JD7 kill, and this only proves the SCN-C check can see it;
     *  - an **honest relay in part two**: WITHHOLD_NEWEST_BUNDLE is switched off once the budget is
     *    spent, so the fetchers are served bob's newest bundle and build on his current
     *    generation, and "the session names the superseded generation" must fail.
     */
    @Test
    fun scnCsBudgetAndGenerationChecksFailOnWhatTheyAreAbout() {
        requireNative()
        DmCrashRunner(DmScenarios.scnC()).run(DmRunSpec())

        val unbounded = DmMutants.Mutation(
            id = "control-unbounded-fetch-budget",
            defeats = "§21.7 point 5: at most three attempt windows per establishment",
            detectedBy = "SCN-C's spent-budget check",
            expect = "ends it unreachable after the third",
            rewrite = { sql, args ->
                if (sql.startsWith("UPDATE dm_contact SET establishment = ?, fetch_attempts = ?")) {
                    Pair(sql, args.toMutableList().also { it[1] = minOf(it[1] as Long, 1L) })
                } else {
                    Pair(sql, args)
                }
            },
        )
        val base = DmScenarios.scnC()
        val mutated = DmScenario(
            name = "SCN-C/${unbounded.id}",
            setup = { world ->
                world.mutation = unbounded
                base.setup(world)
            },
            steps = base.steps,
            alwaysChecks = base.alwaysChecks,
            finalChecks = base.finalChecks,
            liveness = base.liveness,
            noLoss = base.noLoss,
            expectedFailures = base.expectedFailures,
        )
        assertFailsWith(mutated, unbounded.expect)

        val honest = DmScenario(
            name = "SCN-C/honest-relay-in-part-two",
            setup = base.setup,
            steps = base.steps.map { s ->
                if (s.label.startsWith("bob's next weekly publication")) {
                    step(s.label) { w ->
                        w.relay.modes = emptySet()
                        s.body(w)
                    }
                } else {
                    s
                }
            },
            alwaysChecks = base.alwaysChecks,
            finalChecks = base.finalChecks,
            liveness = base.liveness,
            noLoss = base.noLoss,
            expectedFailures = base.expectedFailures,
        )
        assertFailsWith(honest, "not bob's first")
    }

    private fun assertFailsWith(scenario: DmScenario, expect: String) {
        val failure = runCatching { DmCrashRunner(scenario).run(DmRunSpec()) }.exceptionOrNull()
        assertTrue("${scenario.name} passed: the check is vacuous", failure is DmInvariantViolation)
        assertTrue(
            "${scenario.name} failed, but not for the reason the check states: ${failure?.message}",
            failure?.message?.contains(expect) == true,
        )
    }

    /** 7: R-K1 runs at every open, and the log is empty after it. */
    @Test
    fun everyOpenRunsTheCheckpointOfRK1() {
        requireNative()
        DmCrashWorld("self-test-rk1").use { world ->
            val node = world.node("alice", 0x41)
            node.device.engine.onActivated()
            world.advanceBy(DmWorld.HOUR)
            node.device.timeTriggeredPass()
            assertTrue(
                "the sweep pass left no write-ahead log to truncate: the control is vacuous",
                node.walFile.exists() && node.walFile.length() > 0L,
            )
            node.reboot()
            assertTrue("R-K1 did not truncate the log at the open", node.lastOpenTruncated)
            assertEquals(
                "the log held ${node.walBytesAfterOpen} bytes after R-K1",
                0L,
                node.walBytesAfterOpen,
            )
        }
    }
}
