package org.ghost.messaging.entworld

import org.ghost.messaging.api.Establishment
import org.ghost.messaging.api.MessageState
import org.ghost.messaging.harness.DmHarness
import org.ghost.sync.api.NamespaceId
import org.ghost.sync.harness.CallKind
import org.ghost.sync.harness.Invariants
import org.ghost.sync.harness.JournalMode
import org.ghost.sync.harness.ModelRelay
import org.ghost.sync.harness.RunSpec
import org.ghost.sync.harness.Runner
import org.ghost.sync.harness.World
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Before
import org.junit.Test

/**
 * The entitlement world (Phase 9 design §15.1 variant (b), §22.23) proved end to end: a DM
 * conversation between two clients that proceeds **only** because each client's entitlement engine
 * redeemed real tokens for its own namespaces and the registration lane registered its keys — and,
 * in the control, stops exactly where the redemption is taken away.
 *
 * Like every DM world it runs the real DM cryptography through `ghost-dm-host` and reports itself
 * skipped without `-Dghost.dm.native`; a run that means anything shows `0 skipped`.
 */
class EntDmWorldTest {

    @Before
    fun native() {
        assumeTrue(DmHarness.SKIP_MESSAGE, DmHarness.nativeAvailable())
    }

    /**
     * The positive run, under the Phase 7 runner (structural invariants after every commit, the
     * quiescence tail, OUT-3, the store window) and the entitlement engine's own end checks (MS-6,
     * the token accounting, RED-2, T3), plus the DM world's IN-1 and "no pass threw". Then, from
     * the models:
     *  1. every write capability either client holds was minted by a `ModelRedeemRelay` for a token
     *     that client spent there, and every read credential is a v3 credential the DM layer derived
     *     — nothing was installed by the harness;
     *  2. every own namespace has a redeemed write capability at **every** relay of its set;
     *  3. every own namespace has, at every relay of its set, a `done` registration for the current
     *     week of each kind §4.8 names (inbox: DEPOSIT and READ; bundle: FETCH), each held by the
     *     relay model and paid for by a redeemed capability's serial;
     *  4. each side's deposits were charged to the **other** side's DEPOSIT registrations (the
     *     `DepositLedger` of §4.5): the messages were stored because those registrations exist;
     *  5. every redemption named an own namespace of the client that made it, and no (relay,
     *     namespace, week) spent two tokens (T27);
     *  6. the conversation happened: bob shows "hello" and "pair now", alice shows "hi back".
     */
    @Test
    fun conversationRunsOnRedeemedCapabilitiesAndRegisteredKeys() {
        val scenario = EntDmConversation()
        val report = ArrayList<String>()
        scenario.outcome = { s -> verify(s as EntDmConversation, report) }
        val result = Runner(scenario, JournalMode.WAL, SEED).run(RunSpec())
        report += "ENT-DM/conversation: ${result.events} events, ${result.tailRounds} tail rounds, ${result.millis} ms"
        report.forEach(::println)
    }

    /**
     * The same world run on over the boundary of access week 2975, with every check above, and:
     * each own namespace's capability at each relay of its set was renewed with a week-2976 token
     * whose `RedeemToken` reached the relay in the last 23 hours before the boundary (the planner's
     * EXPIRING window), the renewed capability's `c + 1` registrations (week 2977) are done, held by
     * the relay and paid for by a redemption, and a message written after the boundary arrives.
     */
    @Test
    fun renewsAcrossTheWeekBoundaryOnSchedule() {
        val scenario = EntDmConversation(acrossWeekBoundary = true)
        val report = ArrayList<String>()
        scenario.outcome = { s -> verify(s as EntDmConversation, report) }
        val result = Runner(scenario, JournalMode.WAL, SEED).run(RunSpec())
        report += "ENT-DM/renewal: ${result.events} events, ${result.tailRounds} tail rounds, ${result.millis} ms"
        report.forEach(::println)
    }

    private fun verify(s: EntDmConversation, report: MutableList<String>) {
        val world = s.dm
        val clients = listOf(s.aliceDm, s.bobDm)
        val ownByClient = clients.associateWith { it.ownNamespaces() }
        for (dmc in clients) {
            val name = dmc.c.name
            val own = ownByClient.getValue(dmc)
            assertEquals("$name: two own namespaces after ACTIVATE", setOf("bundle", "inbox"), own.keys)
            assertTrue("$name: the K20 hook ran ACTIVATE", dmc.activations.isNotEmpty())

            // 1. No fairy: a write row is a redeemed capability for an own namespace, or the DEPOSIT
            //    credential v3 the DM layer derived from a contact's card for that contact's inbox.
            val ownHexes = own.values.map(::hexOf).toSet()
            val caps = EntDmEvidence.writeCapabilities(world, dmc)
            val unaccounted = caps.filter { !it.accounted }
            assertTrue("$name: write capabilities no redeem relay minted: $unaccounted", unaccounted.isEmpty())
            val misplaced = caps.filter { (it.namespaceHex in ownHexes) != it.redeemed }
            assertTrue("$name: an own namespace without a redemption, or a contact's with one: $misplaced", misplaced.isEmpty())
            assertTrue(
                "$name: a bearer write credential that is not a DEPOSIT credential: $caps",
                caps.filter { it.bearerKind != null }.all { it.bearerKind == ModelRelay.KIND_DEPOSIT },
            )
            assertEquals("$name: read tokens that are not a v3 credential", 0, EntDmEvidence.foreignReadTokens(dmc))

            // 2. A redeemed write capability at every relay of every own namespace's set.
            for ((role, ns) in own) {
                val set = EntDmEvidence.relaySet(world, dmc, ns)
                assertEquals("$name: the $role set is three relays (§5.2)", 3, set.size)
                val nsHex = hexOf(ns)
                for (relay in set) {
                    assertTrue(
                        "$name: no redeemed write capability for its $role at $relay: $caps",
                        caps.any { it.relay == relay && it.namespaceHex == nsHex && it.redeemed },
                    )
                }
            }

            // 3. Done registrations, recorded at the relay and paid for by a redemption.
            val week = ModelRelay.week(world.w.clock.epochSeconds())
            val regs = EntDmEvidence.registrations(world, dmc)
            for ((role, ns) in own) {
                val nsHex = hexOf(ns)
                val kinds = if (role == "inbox") listOf("deposit", "read") else listOf("fetch")
                for (relay in EntDmEvidence.relaySet(world, dmc, ns)) {
                    for (kind in kinds) {
                        val done = regs.filter { it.relay == relay && it.namespaceHex == nsHex && it.kind == kind && it.period == week && it.state == "done" }
                        assertTrue("$name: no done $kind registration of its $role at $relay for week $week: $regs", done.isNotEmpty())
                        assertTrue("$name: a done $kind registration the relay does not hold: $done", done.all { it.recorded && it.paidByRedemption })
                    }
                }
            }
            // 3b. Across the boundary: renewed with the next week's token in the EXPIRING window, and
            //     the renewed capability's `c + 1` rows registered (§4.8 "When the relay sees it").
            if (s.acrossWeekBoundary) {
                val renewed = ModelRelay.week(World.T0) + 1
                val boundary = ModelRelay.weekStart(renewed)
                val redemptions = world.redemptions()
                for ((role, ns) in own) {
                    val nsHex = hexOf(ns)
                    val kinds = if (role == "inbox") listOf("deposit", "read") else listOf("fetch")
                    for (relay in EntDmEvidence.relaySet(world, dmc, ns)) {
                        assertTrue(
                            "$name: its $role at $relay holds no redeemed capability of week $renewed: $caps",
                            caps.any { it.relay == relay && it.namespaceHex == nsHex && it.redeemed && it.week == renewed },
                        )
                        val renewal = redemptions.filter { it.relay == relay && it.namespaceHex == nsHex && it.week == renewed }
                        assertTrue(
                            "$name: its $role at $relay was not renewed in the last 23 h before the boundary: $renewal",
                            renewal.isNotEmpty() && renewal.all { it.atEpochSeconds >= boundary - 23 * 3_600 && it.atEpochSeconds < boundary },
                        )
                        for (kind in kinds) {
                            val next = regs.filter { it.relay == relay && it.namespaceHex == nsHex && it.kind == kind && it.period == renewed + 1 }
                            assertTrue(
                                "$name: no done $kind registration of week ${renewed + 1} of its $role at $relay: $next",
                                next.any { it.state == "done" && it.recorded && it.paidByRedemption },
                            )
                        }
                    }
                }
                val times = redemptions.filter { it.week == renewed && it.namespaceHex in ownHexes }.map { (boundary - it.atEpochSeconds) / 60 }
                report += "$name: renewed with week-$renewed tokens ${times.maxOrNull()}…${times.minOrNull()} min before the boundary"
            }
            report += "$name: ${caps.count { it.redeemed }} redeemed write capabilities (+${caps.count { it.bearerKind != null }} DEPOSIT credentials), " +
                "${regs.count { it.state == "done" }} done registrations " +
                "(${regs.count { it.state == "pending" }} pending), ${dmc.timePasses} time / ${dmc.hintPasses} hint passes"
        }

        // 4. Deposits were charged to the recipient's DEPOSIT registrations.
        for ((sender, recipient) in listOf(s.aliceDm to s.bobDm, s.bobDm to s.aliceDm)) {
            val inbox = hexOf(ownByClient.getValue(recipient).getValue("inbox"))
            val charged = EntDmEvidence.registrations(world, recipient).filter { it.namespaceHex == inbox && it.kind == "deposit" }.sumOf { it.depositBytes }
            assertTrue("${sender.c.name}'s deposits were not charged to ${recipient.c.name}'s DEPOSIT registrations", charged > 0)
            report += "${sender.c.name} -> ${recipient.c.name}: $charged bytes charged to ${recipient.c.name}'s DEPOSIT registrations"
        }

        // 5. Each client redeemed and registered for its own namespaces only (T27, PM-1b: a sender
        //    spends nothing on a contact's namespace), one token per (relay, namespace, week).
        for (dmc in clients) {
            val mine = ownByClient.getValue(dmc).values.map(::hexOf).toSet()
            for (kind in listOf(CallKind.REDEEM, CallKind.REGISTER)) {
                val calls = world.relayEvents.filter { it.client == dmc.c.name && it.kind == kind }
                assertTrue("${dmc.c.name} made no $kind call that was sent to a relay", calls.isNotEmpty())
                val foreign = calls.filter { it.namespaceHex !in mine }
                assertTrue("${dmc.c.name}: $kind calls for a namespace it does not own: $foreign", foreign.isEmpty())
            }
        }
        val redemptions = world.redemptions()
        val perPair = EntDmEvidence.tokensPerPair(world)
        val doubled = perPair.filter { it.value.size > 1 }
        assertTrue("a (relay, namespace, week) spent more than one token (T27): ${doubled.keys}", doubled.isEmpty())
        report += "redemptions: ${redemptions.size} requests, ${perPair.size} (relay, namespace, week) pairs, " +
            "first at ${redemptions.first().atMillis / 60_000} min, last at ${redemptions.last().atMillis / 60_000} min"

        // 6. The conversation.
        val bobSaw = s.inbound(s.bobDm)
        val aliceSaw = s.inbound(s.aliceDm)
        val expected = listOf(EntDmConversation.HELLO, EntDmConversation.PAIR_NOW) +
            if (s.acrossWeekBoundary) listOf(EntDmConversation.AFTER_BOUNDARY) else emptyList()
        assertEquals("bob's inbound texts", expected, bobSaw)
        assertEquals("alice's inbound texts", listOf(EntDmConversation.HI_BACK), aliceSaw)
        assertEquals(MessageState.SENT, s.outgoing(s.aliceDm, EntDmConversation.HELLO))
        assertEquals(MessageState.SENT, s.outgoing(s.bobDm, EntDmConversation.HI_BACK))
    }

    /**
     * The control: the same world with each of bob's `RedeemToken` calls refused before it reaches
     * a relay. Alice's side of the lifecycle still runs — she redeems and registers — so the world
     * is not broken as a whole; bob holds tokens and never a capability, registers nothing, never
     * publishes a bundle, and alice's first message never reaches him: the conversation of the
     * positive run needs exactly the redemption this run takes away.
     */
    @Test
    fun withoutRedemptionNothingIsDelivered() {
        val s = EntDmConversation(refuseBobRedemptions = true)
        World(s.name, SEED, JournalMode.WAL).use { w ->
            s.build(w)
            try {
                horizon(s, w)
            } finally {
                s.dm.close()
            }
        }
    }

    private fun horizon(s: EntDmConversation, w: World) {
        w.driver.runUntil(w.endMillis)
        w.clients.forEach { Invariants.structural(it, "horizon") }
        s.ent.structural("horizon")
        s.dm.finalChecks()

        val world = s.dm
        // Alice's own lifecycle ran.
        val aliceCaps = EntDmEvidence.writeCapabilities(world, s.aliceDm).filter { it.bearerKind == null }
        assertTrue(
            "alice redeemed nothing: the control world is broken: $aliceCaps; relay calls ${world.relayEvents.groupingBy { "${it.client}:${it.kind}" }.eachCount()}",
            aliceCaps.isNotEmpty() && aliceCaps.all { it.redeemed },
        )
        assertTrue(
            "alice registered nothing: the control world is broken",
            EntDmEvidence.registrations(world, s.aliceDm).any { it.state == "done" && it.recorded },
        )
        // Bob held tokens, and every redemption he tried was refused before the relay.
        var tokens = 0L
        s.bob.c.jdbc.query("SELECT count(*) FROM ent_token WHERE kind = 'access'") { tokens = it.long(0) }
        assertTrue("bob holds no token: the control is not a refused redemption", tokens > 0)
        val bobOwn = s.bobDm.ownNamespaces()
        assertEquals("bob's two own namespaces", setOf("bundle", "inbox"), bobOwn.keys)
        val bobHex = bobOwn.values.map(::hexOf).toSet()
        assertTrue("a redemption for bob's namespaces was sent to a relay", world.redemptions().none { it.namespaceHex in bobHex })
        assertTrue("bob holds a write capability", EntDmEvidence.writeCapabilities(world, s.bobDm).isEmpty())
        val bobRegs = EntDmEvidence.registrations(world, s.bobDm)
        assertTrue("bob has no registration row to run: REGROWS never ran", bobRegs.isNotEmpty())
        assertTrue("a registration of bob's reached a relay: $bobRegs", bobRegs.none { it.state == "done" || it.recorded })
        // Bob's bundle was never stored anywhere, so alice never established.
        val bundle = NamespaceId(bobOwn.getValue("bundle"))
        assertTrue("bob's bundle reached a relay", w.relays.none { r -> r.model.namespaces().contains(bundle) })
        val aliceView = s.aliceDm.read { d -> d.engine.contacts().single() }
        assertTrue("alice established with bob: ${aliceView?.establishment}", aliceView?.establishment != Establishment.READY)
        assertTrue("alice's message is SENT", s.outgoing(s.aliceDm, EntDmConversation.HELLO) != MessageState.SENT)
        assertTrue("bob shows something", s.inbound(s.bobDm).isEmpty())
        println(
            "ENT-DM/no-redemption: bob held $tokens access tokens, 0 capabilities, ${bobRegs.size} pending registrations; " +
                "alice: ${aliceCaps.size} redeemed capabilities; alice->bob establishment ${aliceView?.establishment}, " +
                "'hello' ${s.outgoing(s.aliceDm, EntDmConversation.HELLO)}",
        )
    }

    /**
     * The reboot path SCN-E's enumeration will need, sampled: the armed client (alice) dies at
     * [CRASH_SAMPLES] event indices spread evenly over the fault-free run and reboots — a new sync
     * engine, a new entitlement engine and a new DM stack (a new DM context) over the same database
     * file — and every run still passes the Phase 7, Phase 8 and DM world checks **and** the whole
     * positive outcome of [conversationRunsOnRedeemedCapabilitiesAndRegisteredKeys]. This is a
     * smoke test of the mechanism, not §15.3's enumeration: the points are sampled, not classified
     * (see §22.23 for why classification needs the deterministic host randomness first).
     */
    @Test
    fun survivesSampledCrashesOfTheArmedClient() {
        val events = Runner(EntDmConversation(), JournalMode.WAL, SEED).run(RunSpec()).events
        val points = (1..CRASH_SAMPLES).map { events * it / (CRASH_SAMPLES + 1) }
        val results = DmHarness.parallel(
            points.map { k ->
                "crash@$k" to {
                    val s = EntDmConversation()
                    s.outcome = { verify(it as EntDmConversation, ArrayList()) }
                    Runner(s, JournalMode.WAL, SEED).run(RunSpec(crashAt = k))
                }
            },
        )
        for ((k, r) in points.zip(results)) assertEquals("crash@$k did not crash exactly once", 1, r.crashes)
        println("ENT-DM/conversation crashes: ${points.size} sampled single crashes of alice over $events events, every run passed")
    }

    private companion object {
        const val SEED = 1L
        const val CRASH_SAMPLES = 12
    }
}
