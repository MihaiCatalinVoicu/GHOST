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
 *  9. SCN-C's checks of its own really fail on what they are about, each where the defect is: an
 *     establishment whose attempt budget never runs out, a relay that stops withholding the newest
 *     bundle, windows an hour apart, windows of thirty minutes, a message that fails before the
 *     third window, a contact reopened before any user action — and the relay-side window oracle
 *     over listings written by hand (S10c and its review);
 * 10. seven of KC12's, RS2's and RP7's checks really fail on what they are about, each on a world
 *     that breaks one thing: a request accepted before the second identity's flight (the trust
 *     check), a second device that is someone else (the contact count), a request row written to
 *     between the setup and the drop (the fault-free "no state change"), a relay that honours no
 *     TTL (the measured loss), an absence of sixty days (the ratchet gap), an in-key of an open
 *     window deleted (every week up to `week(now)`), and an L0 dated in the key's own week (the
 *     render check) — §22.27 and its review, which also lists the checks that have no control;
 * 11. an injected crash reaches the runner even when a pass that had already thrown carries it as
 *     a *suppressed* exception (`DmActor.runPass`'s `finally`; §22.27's review);
 * 12. RP8's render check really fails on a world whose freshness rule drops `accept_after_minute`
 *     and keeps everything else (§22.38).
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
     * 9: SCN-C's own checks are not vacuous (S10c, and the controls its review asked for).
     *
     * SCN-C adds oracles no other scenario has, and each could pass for nothing. So, beside the
     * clean run, worlds that break one thing each, and each must fail for the reason it names —
     * and where the point is **which** check sees it, the failure must be that check's and not an
     * earlier one's:
     *  - an **unbounded budget**: `dm_contact.fetch_attempts` is never written above 1, so
     *    `EST-END` schedules another window for ever — the behaviour privacy mutant PM-31 names
     *    (§15.7). It fails the engine-side spent-budget check, the first SCN-C check it reaches; it
     *    never reaches the relay-side ones. A control, not a registered mutant: PM-31 is S11's;
     *  - an **honest relay in part two**: WITHHOLD_NEWEST_BUNDLE is switched off once the budget is
     *    spent, so the fetchers build on bob's current generation, and "the session names the
     *    superseded generation" must fail;
     *  - [scnCsRelaySideWindowChecksFailOnWhatTheyAreAbout] and
     *    [scnCsWaitingAndGivenUpChecksFailOnWhatTheyAreAbout] carry the rest.
     */
    @Test
    fun scnCsBudgetAndGenerationChecksFailOnWhatTheyAreAbout() {
        requireNative()
        DmCrashRunner(DmScenarios.scnC()).run(DmRunSpec())

        val unbounded = scnCControl("control-unbounded-fetch-budget") { _, sql, args ->
            if (sql.startsWith(SET_ESTABLISHMENT)) {
                Pair(sql, args.toMutableList().also { it[1] = minOf(it[1] as Long, 1L) })
            } else {
                Pair(sql, args)
            }
        }
        assertFailsWith(unbounded, "ends it unreachable after the third")

        val base = DmScenarios.scnC()
        val honest = scnCVariant(
            "honest-relay-in-part-two",
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
        )
        assertFailsWith(honest, "not bob's first")
    }

    /**
     * 9, the relay's side (S10c review): the window checks SCN-C runs over the relay's record of
     * alice's listings can fail, and each on its own.
     *
     * Two engines that break the window's **shape** while everything the engine reports holds —
     * three windows, `unreachable` after the third, `c0` failed only then, no fourth window seven
     * hours later — so that nothing but the relay-side check can see them, and each must:
     *  - **one hour between windows**: `EST-END`'s six hours are written as one. The spacing clause
     *    must fail — measured from the last listing of a window, so a check that measured start to
     *    start at six hours would also have caught this one, but not a gap of five and three
     *    quarters;
     *  - **thirty-minute windows**: `EST-START`'s fifteen minutes are written as thirty. The span
     *    clause must fail.
     *
     * The count clause has no such engine: an engine that lists a fourth window of an establishment
     * it reports as three attempts fails an engine-side check first. So the oracle itself is also
     * run over listing times written by hand: the fault-free shape passes, and a fourth window, a
     * window listed for 22 minutes, and a window five hours and fifty minutes after the last
     * listing of the one before — six hours after its first — each fail their own clause.
     */
    @Test
    fun scnCsRelaySideWindowChecksFailOnWhatTheyAreAbout() {
        val m = DmWorld.MINUTE
        val h = DmWorld.HOUR
        // The fault-free shape: two listings eight minutes apart, the next window six hours and
        // nine minutes after the second.
        val clean = listOf(0L, 8 * m, 6 * h + 17 * m, 6 * h + 25 * m, 12 * h + 34 * m, 12 * h + 42 * m)
        assertEquals(emptyList<String>(), DmScenarios.windowViolations(DmScenarios.listingWindows(clean), "alice"))
        val cases = mapOf(
            "attempt windows" to clean + listOf(18 * h + 51 * m),
            "minutes in one window" to listOf(0L, 8 * m, 16 * m, 22 * m),
            "after the last listing of the window before" to listOf(0L, 10 * m, 6 * h),
        )
        for ((clause, times) in cases) {
            val violations = DmScenarios.windowViolations(DmScenarios.listingWindows(times), "alice")
            assertEquals("the '$clause' clause, alone: $violations", 1, violations.size)
            assertTrue("the '$clause' clause: $violations", violations.single().contains(clause))
        }

        requireNative()
        val hourApart = scnCControl("control-one-hour-between-windows") { now, sql, args ->
            val until = args.getOrNull(2) as? Long
            if (sql.startsWith(SET_ESTABLISHMENT) && args[0] == FETCHING && until != null && until - now() > h) {
                Pair(sql, args.toMutableList().also { it[2] = until - 5 * h })
            } else {
                Pair(sql, args)
            }
        }
        assertFailsWith(hourApart, "after the last listing of the window before")

        val longWindows = scnCControl("control-thirty-minute-windows") { now, sql, args ->
            val until = args.getOrNull(2) as? Long
            if (sql.startsWith(SET_ESTABLISHMENT) && args[0] == FETCHING && until != null && until - now() in 1..20 * m) {
                Pair(sql, args.toMutableList().also { it[2] = until + 15 * m })
            } else {
                Pair(sql, args)
            }
        }
        assertFailsWith(longWindows, "minutes in one window")
    }

    /**
     * 9, the checks between part one's windows and before `c1` (S10c review): each fails where
     * the defect happens, not later.
     *  - **A message that fails early**: `dm_pending_send.fail_after_hour` is written an hour after
     *    the send instead of seven days, so R-T5 fails `c0` at the pass that opens the second
     *    window. Checked only at the end of part one, where `c0` is FAILED either way, that passed
     *    every check; "`c0` still waits while alice is fetching" must fail — the same check an
     *    `EST-END` that failed the pending items at every close would meet one window earlier.
     *  - **A contact reopened without a user action**: once bob's publication step is over, the
     *    control opens a new establishment for alice itself — what an engine that reopened an
     *    `unreachable` contact on its own, after longer than the seven-hour probe, would have done
     *    at that pass. Its window fetches the older bundle and builds on `g1` before `c1` exists,
     *    and every later check holds; the check just before `c1` must fail.
     */
    @Test
    fun scnCsWaitingAndGivenUpChecksFailOnWhatTheyAreAbout() {
        requireNative()
        val failsEarly = scnCControl("control-deadline-of-an-hour") { _, sql, args ->
            if (sql.startsWith("INSERT INTO dm_pending_send")) {
                Pair(sql, args.toMutableList().also { it[2] = (it[2] as Long) - 7 * DmWorld.DAY + DmWorld.HOUR })
            } else {
                Pair(sql, args)
            }
        }
        assertFailsWith(failsEarly, "no longer waits while alice is still fetching")

        val base = DmScenarios.scnC()
        val reopened = scnCVariant(
            "reopened-before-c1",
            steps = base.steps.map { s ->
                if (s.label.startsWith("bob's next weekly publication")) {
                    step(s.label) { w ->
                        s.body(w)
                        val alice = w["alice"].device
                        val bob = alice.engine.contacts().single().id
                        alice.establishment.estStart(bob.toByteArray(), userRetry = true)
                    }
                } else {
                    s
                }
            },
        )
        assertFailsWith(reopened, "before she wrote c1")
    }

    /**
     * 10: the checks of KC12, RS2 and RP7 that no registered mutant reaches are not vacuous either
     * (§22.27). MC-24 is killed by KC12's "no crash" check and MC-21 by RS2's in-key check; what
     * follows are the others, each failing for the reason it names on a world that breaks one thing:
     *  - **KC12, the decision taken before the flight arrives**: bob accepts alice's request first,
     *    so the second identity's first flight is a key change of an accepted contact — §8.3's hold,
     *    correct for the engine and SCN-D's subject — and "no state change" must fail on it;
     *  - **KC12, a second device that is someone else**: another `ghost1` identity writes instead of
     *    alice's second device, so bob gets a second request, and the one-contact check must fail;
     *  - **RS2, a relay that honours no TTL**: the message written into the absence is still held
     *    when bob comes back, so it is served — and refused, since bob's first sweep erased the
     *    week key that sealed it — and the measurement of the declared loss ("the relay let it
     *    expire unserved") must fail: the declaration excuses a loss at the relay and nothing else;
     *  - **RP7, the L0 dated in the key's own week**: the sender's decorator dates the message a
     *    minute earlier instead of a week, binding B1 lets it through, and the render check must
     *    fail — this showed RP7's one check reads the rendering at all while it had no registered
     *    mutant (MC-9 was out of reach until §22.38), and still shows it with no mutant installed.
     */
    @Test
    fun kc12Rs2AndRp7ChecksFailOnWhatTheyAreAbout() {
        requireNative()
        val kc12 = DmSuiteCases.kc12ARequestSendingTwoIdentities()
        val acceptedFirst = DmScenario(
            name = "KC12/accepted-before-the-flight",
            setup = kc12.setup,
            steps = kc12.steps.map { s ->
                if (s.label.startsWith("bob's device takes it")) {
                    step(s.label) { w ->
                        w["bob"].device.engine.acceptRequest(requireNotNull(w.contacts["bob->alice"]))
                        s.body(w)
                    }
                } else {
                    s
                }
            },
            alwaysChecks = kc12.alwaysChecks,
            finalChecks = kc12.finalChecks,
            liveness = kc12.liveness,
            noLoss = kc12.noLoss,
            declaredLoss = kc12.declaredLoss,
        )
        assertFailsWith(acceptedFirst, "the second identity moved it")

        // KC12's fault-free "no state change", which reads every row of bob's DM state and not a
        // fixed list of fields (§22.27's review): the request's `request_until_day` moved between the
        // setup and the drop — the review's own mutant, a second identity keeping a request alive —
        // must fail it. The write is the harness's, raw, in the second device's step.
        assertFailsWith(
            DmScenario(
                name = "KC12/request-extended",
                setup = kc12.setup,
                steps = kc12.steps.map { s ->
                    if (s.label.startsWith("alice's second device writes")) {
                        step(s.label) { w ->
                            s.body(w)
                            w["bob"].raw.exec(
                                "UPDATE dm_contact SET request_until_day = request_until_day + 30 WHERE trust_state = 'request'",
                                emptyList(),
                            )
                        }
                    } else {
                        s
                    }
                },
                alwaysChecks = kc12.alwaysChecks,
                finalChecks = kc12.finalChecks,
                liveness = kc12.liveness,
                noLoss = kc12.noLoss,
                declaredLoss = kc12.declaredLoss,
            ),
            "changed his state",
        )

        val someoneElse = DmSuiteCases.kc12ARequestSendingTwoIdentities(secondIdentityBranch = 0x72)
        assertFailsWith(
            DmScenario(
                name = "KC12/someone-else",
                setup = someoneElse.setup,
                steps = someoneElse.steps,
                alwaysChecks = someoneElse.alwaysChecks,
                finalChecks = someoneElse.finalChecks,
                liveness = someoneElse.liveness,
                noLoss = someoneElse.noLoss,
                declaredLoss = someoneElse.declaredLoss,
            ),
            "bob holds 2 contacts",
        )

        val rs2 = DmSuiteCases.rs2AClientOfflineSixtyDays()
        assertFailsWith(
            DmScenario(
                name = "RS2/no-ttl",
                setup = { world ->
                    world.relay.honoursTtl = false
                    rs2.setup(world)
                },
                steps = rs2.steps,
                alwaysChecks = rs2.alwaysChecks,
                finalChecks = rs2.finalChecks,
                liveness = rs2.liveness,
                noLoss = rs2.noLoss,
                declaredLoss = rs2.declaredLoss,
            ),
            "expire unserved",
        )

        // RS2's ratchet gap: sixty days from this world's Wednesday start is a gap of eight
        // week-indices, where S9's defect (the catch-up cap at eight) is invisible — the review set
        // the cap back and RS2 passed. The case refuses to run there.
        assertFailsWith(DmSuiteCases.rs2AClientOfflineSixtyDays(absenceDays = 60), "not the 9 that clear")

        // RS2's "K_w for every week up to week(now)": an in-key of a week whose window is still open,
        // deleted raw after the return, must fail it (the review's mutant kept only the newest
        // derived week and passed the return-week check alone).
        assertFailsWith(
            DmScenario(
                name = "RS2/open-week-key-deleted",
                setup = rs2.setup,
                steps = rs2.steps.map { s ->
                    if (s.label == "bob answers") {
                        step(s.label) { w ->
                            s.body(w)
                            w["bob"].raw.exec(
                                "DELETE FROM dm_pair_key WHERE direction = 'in' AND week = " +
                                    "(SELECT max(week) - 1 FROM dm_pair_key WHERE direction = 'in')",
                                emptyList(),
                            )
                        }
                    } else {
                        s
                    }
                },
                alwaysChecks = rs2.alwaysChecks,
                finalChecks = rs2.finalChecks,
                liveness = rs2.liveness,
                noLoss = rs2.noLoss,
                declaredLoss = rs2.declaredLoss,
            ),
            "whose window is still open",
        )

        // RP7's render check, which no registered mutant reached until §22.38 registered MC-9 (it
        // was out of every mechanism's reach, §22.27): the sender's L0 dated a minute earlier in the
        // key's **own** week, which binding B1 lets through, must fail it.
        assertFailsWith(
            DmSuiteCases.rp7AnOldL0ResealedUnderALaterWeekKey(sameWeek = true),
            "bob rendered an L0 dated in another week",
        )
    }

    /**
     * 12: RP8's render check (§22.38) is not vacuous, and what it reads is `accept_after_minute`'s
     * refusal and nothing else: RP8 on a world whose freshness rule is the production rule with that
     * one clause dropped — R9's age bound and binding B1 kept, the rule itself called — must fail it.
     * MC-9's registered policy keeps the clause (a restore rule and not MC-9's), and no §15.7 id
     * names it, so this is the check's control rather than a registered mutant.
     */
    @Test
    fun rp8sRenderCheckFailsWithoutAcceptAfter() {
        requireNative()
        val rp8 = DmScenarios.scnI(rp8 = true)
        val noAcceptAfter = DmMutants.Mutation(
            id = "RP8-control",
            defeats = "§8.6: nothing authored before accept_after_minute is applied on a restored device",
            detectedBy = "RP8's render check",
            expect = "the restored device rendered content authored before its restore",
            freshness = org.ghost.messaging.engine.ContentFreshness { author, arrival, fresh, pairWeek, _ ->
                org.ghost.messaging.engine.ContentFreshness.RULE.admits(author, arrival, fresh, pairWeek) { null }
            },
        )
        assertFailsWith(
            DmScenario(
                name = "RP8/no-accept-after",
                setup = { w ->
                    w.mutation = noAcceptAfter
                    rp8.setup(w)
                },
                steps = rp8.steps,
                alwaysChecks = rp8.alwaysChecks,
                finalChecks = rp8.finalChecks,
                liveness = rp8.liveness,
                noLoss = rp8.noLoss,
                declaredLoss = rp8.declaredLoss,
            ),
            "the restored device rendered content authored before its restore",
        )
    }

    /** SCN-C as it is, under [name], with [steps] in place of its own. */
    private fun scnCVariant(
        name: String,
        mutation: DmMutants.Mutation? = null,
        onSetup: (DmCrashWorld) -> Unit = {},
        steps: List<DmScenario.Step>? = null,
    ): DmScenario {
        val base = DmScenarios.scnC()
        return DmScenario(
            name = "SCN-C/$name",
            setup = { world ->
                onSetup(world)
                if (mutation != null) world.mutation = mutation
                base.setup(world)
            },
            steps = steps ?: base.steps,
            alwaysChecks = base.alwaysChecks,
            finalChecks = base.finalChecks,
            liveness = base.liveness,
            noLoss = base.noLoss,
            expectedFailures = base.expectedFailures,
        )
    }

    /**
     * SCN-C under a statement rewrite that is a control, not a registered mutant. [rewrite] also
     * gets the world's clock, since a rewrite that moves a decision minute has to know when "now"
     * is.
     */
    private fun scnCControl(
        id: String,
        rewrite: (now: () -> Long, sql: String, args: List<Any?>) -> Pair<String, List<Any?>>,
    ): DmScenario {
        var world: DmCrashWorld? = null
        val now = { requireNotNull(world) { "the control's world is not set up" }.nodes().maxOf { it.clock.now } }
        val mutation = DmMutants.Mutation(
            id = id,
            defeats = "a control of SCN-C's own checks (DmHarnessSelfTest item 9)",
            detectedBy = "SCN-C",
            expect = "",
            rewrite = { sql, args -> rewrite(now, sql, args) },
        )
        return scnCVariant(id, mutation = mutation, onSetup = { world = it })
    }

    private fun assertFailsWith(scenario: DmScenario, expect: String) {
        val failure = runCatching { DmCrashRunner(scenario).run(DmRunSpec()) }.exceptionOrNull()
        assertTrue("${scenario.name} passed: the check is vacuous", failure is DmInvariantViolation)
        assertTrue(
            "${scenario.name} failed, but not for the reason the check states: ${failure?.message}",
            failure?.message?.contains(expect) == true,
        )
    }

    private companion object {
        /** `ContactStore.setEstablishment`, the one statement that writes a contact's attempt state. */
        const val SET_ESTABLISHMENT = "UPDATE dm_contact SET establishment = ?, fetch_attempts = ?"

        /** `dm_contact.establishment` of a contact whose bundle fetch is under way. */
        const val FETCHING = "fetching"
    }

    /**
     * 11: a crash injected into a pass's `afterCommit`, after the pass itself threw, still kills the
     * process (§22.27's review).
     *
     * `DmActor.runPass` attaches whatever `schedule.afterCommit()` throws to the pass's own exception
     * as *suppressed*, and the world's swallow of that exception used to take the death with it: the
     * review found five crash points of a mutated KC12 at which the crash was injected and nothing
     * rebooted. Here the pass is made to throw at its first statement (the statement the executor
     * runs is replaced by one naming no column there is), the crash is planned at the first event
     * after it — which `afterCommit` raises — and the death must come out of the world's pass, with
     * the pass's own exception still recorded.
     */
    @Test
    fun aCrashAttachedToAPassThatThrewStillKillsTheProcess() {
        requireNative()
        DmCrashWorld("self-test-absorbed-crash").use { world ->
            val node = world.node("alice", 0x41)
            node.device.engine.onActivated()
            world.advanceBy(DmWorld.HOUR)
            node.device.timeTriggeredPass()
            var failedAt: Long? = null
            node.sql.rewrite = { sql, args ->
                if (failedAt == null && world.bus.armed) {
                    failedAt = world.bus.count
                    Pair("SELECT no_such_column FROM dm_self", emptyList())
                } else {
                    Pair(sql, args)
                }
            }
            world.bus.plan = DmFaultPlan { e ->
                val at = failedAt
                if (at != null && e.index > at && world.bus.injected.isEmpty()) DmFault.Crash else null
            }
            world.bus.armed = true
            world.advanceBy(DmWorld.HOUR)
            val death = runCatching { world.pass("alice") }.exceptionOrNull()
            world.bus.armed = false
            assertTrue("the pass never threw: the control is vacuous", failedAt != null)
            assertEquals("the crash was never injected: the control is vacuous", 1, world.bus.injected.size)
            assertTrue(
                "the crash injected after the pass threw was absorbed: $death; swallowed ${world.swallowed}",
                death is SimulatedDmCrash && death === world.bus.injected.single(),
            )
            assertEquals("the pass's own exception is not recorded", 1, world.swallowed.size)
            assertTrue(
                "the death did not come from the pass's suppressed exceptions: the control is vacuous",
                world.swallowed.single().suppressed.any { it === death },
            )
        }
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
