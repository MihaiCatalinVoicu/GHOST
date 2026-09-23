package org.ghost.messaging.entworld

import org.ghost.messaging.api.Establishment
import org.ghost.messaging.api.MessageState
import org.ghost.messaging.entworld.EntDmConversation.Companion.AFTER_LAPSE
import org.ghost.messaging.entworld.EntDmConversation.Companion.BEFORE_BOUNDARY
import org.ghost.messaging.entworld.EntDmConversation.Companion.HELLO
import org.ghost.messaging.entworld.EntDmConversation.Companion.HI_BACK
import org.ghost.messaging.entworld.EntDmConversation.Companion.LAPSED_AT
import org.ghost.messaging.entworld.EntDmConversation.Companion.PAIR_NOW
import org.ghost.messaging.entworld.EntDmScenario.Companion.WEEK0
import org.ghost.messaging.harness.DmHarness
import org.ghost.network.EntitlementCrypto
import org.ghost.sync.api.BlobHash
import org.ghost.sync.api.NamespaceId
import org.ghost.sync.harness.CallKind
import org.ghost.sync.harness.EventKind
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
 * in the controls, stops exactly where a redemption is taken away.
 *
 * Every run also carries the world's own checks while it runs (every commit: no capability row but a
 * redeemed capability or a credential v3; every store a relay applied: charged to no capability but a
 * redeemed one) and at quiescence (IN-1 over the DM namespaces, S10b's "nothing owed", no waiting
 * LOCAL need, no pass threw).
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
     * the token accounting, RED-2, T3), plus the DM world's. Then ([verify]):
     *  6. first, the conversation happened: bob shows "hello" and "pair now", alice shows "hi back";
     *  1. every write capability either client holds was minted by a `ModelRedeemRelay` for a token
     *     spent there, and every read credential is a v3 credential the DM layer derived;
     *  2. every own namespace has a redeemed write capability of the current week at **every** relay
     *     of its set;
     *  3. every own namespace has, at every relay of its set, a `done` registration of each kind §4.8
     *     names (inbox: DEPOSIT and READ; bundle: FETCH) for the week `c` **and** `c + 1` of the
     *     capability redeemed on Friday, late in its week — each held by the relay model and paid for
     *     by week-`c` redeemed capabilities' serials only (the "late" half of the OS `{c, c + 1}` case);
     *  4. each side's deposits were charged to the **other** side's DEPOSIT registrations (the
     *     `DepositLedger` of §4.5): the messages were stored because those registrations exist;
     *  5. every redemption and registration a relay saw named an own namespace of the client that
     *     made it, and no (relay, namespace, week) was sent two tokens (T27).
     */
    @Test
    fun conversationRunsOnRedeemedCapabilitiesAndRegisteredKeys() {
        val scenario = EntDmConversation()
        val report = ArrayList<String>()
        scenario.outcome = { s -> verify(s as EntDmConversation, report) }
        val result = Runner(scenario, JournalMode.WAL, SEED).run(RunSpec())
        report += "ENT-DM/conversation: ${result.events} events of the armed client (alice), ${result.tailRounds} tail rounds, ${result.millis} ms"
        report.forEach(::println)
    }

    /**
     * The same world run on into access week 2978, with every check above read at the last minute
     * of week 2975 (the renewed capability of week 2976 now at every relay; registrations of weeks
     * 2975, 2976 **and 2977**, the renewal's `c + 1`, paid for by week-2976 capabilities only — the
     * "early" half of OS `{c, c + 1}`), and:
     *  - each own namespace's capability at each relay of its set was renewed with a week-2976 token
     *    whose `RedeemToken` arrived, on the relay's clock, in the last 23 hours before the boundary
     *    (the planner's EXPIRING window);
     *  - the message alice writes at `start(2978) + 2 h`, when every registration of the Friday
     *    capability is dead, arrives, and bob's week-2977 DEPOSIT registrations — paid for by the
     *    renewal alone — are what the relay charged it to. The control is
     *    [withoutBobsRenewalTheLapsedWeekMessageIsRefused].
     */
    @Test
    fun renewalCarriesDeliveryPastTheOldRegistrations() {
        val scenario = EntDmConversation(acrossWeekBoundary = true)
        val report = ArrayList<String>()
        scenario.outcome = { s -> verify(s as EntDmConversation, report) }
        val result = Runner(scenario, JournalMode.WAL, SEED).run(RunSpec())
        report += "ENT-DM/renewal: ${result.events} events of the armed client (alice), ${result.tailRounds} tail rounds, ${result.millis} ms"
        report.forEach(::println)
    }

    private fun verify(s: EntDmConversation, report: MutableList<String>) {
        // 6. The conversation, first: a check below that fails then fails on a world whose
        //    conversation happened (the fairy control reads exactly that). A run into week 2978
        //    reads it at the last minute of week 2975: by its end the timers (§10.3) have erased it.
        val snap = if (s.acrossWeekBoundary) s.snapshots.getValue(BEFORE_BOUNDARY) else s.snapshot(s.dm.w)
        assertEquals("bob's inbound texts", listOf(HELLO, PAIR_NOW), snap.inbound["bob"])
        assertEquals("alice's inbound texts", listOf(HI_BACK), snap.inbound["alice"])
        assertEquals("alice's 'hello'", MessageState.SENT, snap.outgoing.getValue("alice")[HELLO])
        assertEquals("alice's 'pair now'", MessageState.SENT, snap.outgoing.getValue("alice")[PAIR_NOW])
        assertEquals("bob's 'hi back'", MessageState.SENT, snap.outgoing.getValue("bob")[HI_BACK])
        if (s.acrossWeekBoundary) {
            assertEquals("bob's inbound texts at the end", listOf(AFTER_LAPSE), s.inbound(s.bobDm))
            assertEquals("alice's lapsed-week message", MessageState.SENT, s.outgoing(s.aliceDm, AFTER_LAPSE))
        }

        val capWeek = if (s.acrossWeekBoundary) WEEK0 + 1 else WEEK0
        // Which capability weeks may pay for a registration of each period.
        val periods = if (s.acrossWeekBoundary) {
            mapOf(WEEK0 to setOf(WEEK0), WEEK0 + 1 to setOf(WEEK0, WEEK0 + 1), WEEK0 + 2 to setOf(WEEK0 + 1))
        } else {
            mapOf(WEEK0 to setOf(WEEK0), WEEK0 + 1 to setOf(WEEK0))
        }
        evidence(s, snap, capWeek, periods, report)
        deposits(s, snap, report)
        if (s.acrossWeekBoundary) renewal(s, report)
        ownNamespacesOnly(s, report)
    }

    /** Checks 1–3 on [snap]: no fairy, a redeemed capability of [capWeek] everywhere, and every [periods] registration. */
    private fun evidence(s: EntDmConversation, snap: EntDmScenario.Snapshot, capWeek: Long, periods: Map<Long, Set<Long>>, report: MutableList<String>) {
        for (dmc in listOf(s.aliceDm, s.bobDm)) {
            val name = dmc.c.name
            val own = snap.own.getValue(name)
            assertEquals("$name: two own namespaces after ACTIVATE", setOf("bundle", "inbox"), own.keys)
            assertTrue("$name: the K20 hook's ACTIVATE ran", dmc.activations.isNotEmpty())

            // 1. No fairy: a write row is a redeemed capability for an own namespace, or the DEPOSIT
            //    credential v3 the DM layer derived from a contact's card for that contact's inbox.
            val ownHexes = own.values.map(::hexOf).toSet()
            val caps = snap.caps.getValue(name)
            val unaccounted = caps.filter { !it.accounted }
            assertTrue("$name: write capabilities no redeem relay minted: $unaccounted", unaccounted.isEmpty())
            val misplaced = caps.filter { (it.namespaceHex in ownHexes) != it.redeemed }
            assertTrue("$name: an own namespace without a redemption, or a contact's with one: $misplaced", misplaced.isEmpty())
            assertTrue(
                "$name: a bearer write credential that is not a DEPOSIT credential: $caps",
                caps.filter { it.bearerKind != null }.all { it.bearerKind == ModelRelay.KIND_DEPOSIT },
            )
            assertEquals("$name: read tokens that are not a v3 credential", 0, snap.foreignReads.getValue(name))

            // 2. A redeemed write capability of [capWeek] at every relay of every own namespace's set.
            for ((role, ns) in own) {
                val set = EntDmEvidence.relaySet(s.dm, dmc, ns)
                assertEquals("$name: the $role set is three relays (§5.2)", 3, set.size)
                for (relay in set) {
                    assertTrue(
                        "$name: no redeemed write capability of week $capWeek for its $role at $relay: $caps",
                        caps.any { it.relay == relay && it.namespaceHex == hexOf(ns) && it.redeemed && it.week == capWeek },
                    )
                }
            }

            // 3. For every period: a done registration of each kind at each relay, held by the relay
            //    and paid for only by redeemed capabilities of the weeks allowed for that period.
            val regs = snap.regs.getValue(name)
            var checked = 0
            for ((role, ns) in own) {
                val kinds = if (role == "inbox") listOf("deposit", "read") else listOf("fetch")
                for (relay in EntDmEvidence.relaySet(s.dm, dmc, ns)) {
                    for (kind in kinds) {
                        for ((period, payers) in periods) {
                            val row = regs.singleOrNull { it.relay == relay && it.namespaceHex == hexOf(ns) && it.kind == kind && it.period == period }
                            assertTrue(
                                "$name: the $kind registration of week $period of its $role at $relay is not done, held and paid for by weeks $payers: $row",
                                row != null && row.state == "done" && row.recorded && row.paidByRedemption && row.serialWeeks.all { it in payers },
                            )
                            checked++
                        }
                    }
                }
            }
            assertEquals("$name: registrations checked", 9 * periods.size, checked)
            report += "$name: ${caps.count { it.redeemed }} redeemed write capabilities of week $capWeek (+${caps.count { it.bearerKind != null }} DEPOSIT credentials); " +
                "$checked registrations of weeks ${periods.keys} done, held and paid for (${regs.count { it.state == "pending" }} pending rows); " +
                "${dmc.timePasses} time / ${dmc.hintPasses} hint passes"
        }
    }

    /** 4. Deposits were charged to the recipient's DEPOSIT registrations (read on [snap]). */
    private fun deposits(s: EntDmConversation, snap: EntDmScenario.Snapshot, report: MutableList<String>) {
        for ((sender, recipient) in listOf(s.aliceDm to s.bobDm, s.bobDm to s.aliceDm)) {
            val inbox = hexOf(snap.own.getValue(recipient.c.name).getValue("inbox"))
            val charged = snap.regs.getValue(recipient.c.name).filter { it.namespaceHex == inbox && it.kind == "deposit" }.sumOf { it.depositBytes }
            assertTrue("${sender.c.name}'s deposits were not charged to ${recipient.c.name}'s DEPOSIT registrations", charged > 0)
            report += "${sender.c.name} -> ${recipient.c.name}: $charged bytes charged to ${recipient.c.name}'s DEPOSIT registrations"
        }
    }

    /** 3b and the lapsed week: the renewal's timing, and the delivery only its registrations could carry. */
    private fun renewal(s: EntDmConversation, report: MutableList<String>) {
        val renewed = WEEK0 + 1
        val boundary = ModelRelay.weekStart(renewed)
        val redemptions = s.dm.redemptions()
        for (dmc in listOf(s.aliceDm, s.bobDm)) {
            val name = dmc.c.name
            val own = dmc.ownNamespaces()
            for ((role, ns) in own) {
                for (relay in EntDmEvidence.relaySet(s.dm, dmc, ns)) {
                    val renewal = redemptions.filter { it.client == name && it.relay == relay && it.namespaceHex == hexOf(ns) && it.week == renewed }
                    assertTrue(
                        "$name: its $role at $relay was not renewed in the last 23 h before the boundary: $renewal",
                        renewal.isNotEmpty() && renewal.all { it.relayEpochSeconds >= boundary - 23 * 3_600 && it.relayEpochSeconds < boundary },
                    )
                }
            }
            val times = redemptions.filter { it.client == name && it.week == renewed }.map { (boundary - it.relayEpochSeconds) / 60 }
            report += "$name: renewed with week-$renewed tokens that arrived ${times.maxOrNull()}…${times.minOrNull()} min before the boundary (relay clock)"
        }
        // The lapsed week: bob's week-2977 DEPOSIT registrations, paid for by the renewal alone,
        // carried alice's message. Every earlier registration is dead by then (valid until
        // start(p + 2) + 1 h), so the relay could charge the deposit to nothing else.
        val end = s.snapshot(s.dm.w)
        val bobInbox = hexOf(s.bobDm.ownNamespaces().getValue("inbox"))
        val lapsedWeek = WEEK0 + 2
        check(ModelRelay.registrationValidUntil(renewed) < World.T0 + LAPSED_AT / 1_000) { "the scenario's lapse is not after the old registrations" }
        val next = end.regs.getValue("bob").filter { it.namespaceHex == bobInbox && it.kind == "deposit" && it.period == lapsedWeek }
        assertEquals("bob's week-$lapsedWeek DEPOSIT registrations at the end: $next", 3, next.size)
        assertTrue("a week-$lapsedWeek DEPOSIT registration of bob's is not held or not paid by the renewal alone: $next", next.all { it.recorded && it.serialWeeks.isNotEmpty() && it.serialWeeks.all { w -> w == renewed } })
        val charged = next.sumOf { it.depositBytes }
        assertTrue("alice's lapsed-week message was not charged to bob's week-$lapsedWeek registrations: $next", charged > 0)
        report += "alice -> bob after the lapse: $charged bytes charged to bob's week-$lapsedWeek DEPOSIT registrations, paid for by week-$renewed capabilities only; 'after' ${s.outgoing(s.aliceDm, AFTER_LAPSE)}"
        // What the "nothing owed" oracle excused at the end: own-namespace ops waiting for a purchase.
        for (dmc in listOf(s.aliceDm, s.bobDm)) {
            var waiting = 0L
            dmc.c.jdbc.query("SELECT count(*) FROM outbox_op o JOIN dm_own_namespace d ON d.namespace_id = o.namespace_id WHERE o.released = 0") { waiting = it.long(0) }
            report += "${dmc.c.name} at the end: uncovered=${dmc.ent.uncovered()}, $waiting own-namespace op(s) waiting for a purchase"
        }
    }

    /** 5. Own namespaces only (T27, PM-1b: a sender spends nothing on a contact's namespace), one token per pair. */
    private fun ownNamespacesOnly(s: EntDmConversation, report: MutableList<String>) {
        for (dmc in listOf(s.aliceDm, s.bobDm)) {
            val mine = dmc.ownNamespaces().values.map(::hexOf).toSet()
            for (kind in listOf(CallKind.REDEEM, CallKind.REGISTER)) {
                val calls = s.dm.seen().filter { it.client == dmc.c.name && it.kind == kind }
                assertTrue("${dmc.c.name} made no $kind call a relay saw", calls.isNotEmpty())
                val foreign = calls.filter { it.namespaceHex !in mine }
                assertTrue("${dmc.c.name}: $kind calls for a namespace it does not own: $foreign", foreign.isEmpty())
            }
        }
        val redemptions = s.dm.redemptions()
        val perPair = EntDmEvidence.tokensPerPair(s.dm)
        val doubled = perPair.filter { it.value.size > 1 }
        assertTrue("a (relay, namespace, week) was sent more than one token (T27): ${doubled.keys}", doubled.isEmpty())
        report += "redemptions: ${redemptions.size} that relays received, for ${perPair.size} (relay, namespace, week) pairs " +
            "(${redemptions.count { it.client == "alice" }} alice, ${redemptions.count { it.client == "bob" }} bob), " +
            "first at ${redemptions.first().atMillis / 60_000} min, last at ${redemptions.last().atMillis / 60_000} min"
    }

    /**
     * The control: the same world with each of bob's `RedeemToken` calls answered
     * `relay_unavailable` before it leaves (an unreachable redeem path). Alice's side of the lifecycle
     * still runs — she redeems and registers — so the world is not broken as a whole; bob tries to
     * redeem and no relay ever receives one of his tokens, he holds tokens and never a capability,
     * every registration row of his stays pending and none is held by a relay, his bundle never
     * reaches a relay, alice stays `FETCHING` with "hello" `QUEUED`, and bob shows nothing: the
     * conversation of the positive run needs exactly the redemption this run takes away.
     */
    @Test
    fun withoutRedemptionNothingIsDelivered() {
        horizon(EntDmConversation(refuseBobRedemptions = true)) { s, w ->
            val world = s.dm
            val aliceCaps = EntDmEvidence.writeCapabilities(world, s.aliceDm).filter { it.bearerKind == null }
            assertTrue("alice redeemed nothing: the control world is broken: $aliceCaps", aliceCaps.isNotEmpty() && aliceCaps.all { it.redeemed })
            assertTrue("alice registered nothing: the control world is broken", EntDmEvidence.registrations(world, s.aliceDm).any { it.state == "done" && it.recorded })
            var tokens = 0L
            s.bob.c.jdbc.query("SELECT count(*) FROM ent_token WHERE kind = 'access'") { tokens = it.long(0) }
            assertTrue("bob holds no token: the control is not a refused redemption", tokens > 0)
            val bobOwn = s.bobDm.ownNamespaces()
            assertEquals("bob's two own namespaces", setOf("bundle", "inbox"), bobOwn.keys)
            val tried = world.relayEvents.count { it.client == "bob" && it.kind == CallKind.REDEEM && it.event == EventKind.RELAY_BEFORE_SEND }
            assertTrue("bob never tried to redeem: the control refused nothing", tried > 0)
            assertTrue("a relay received a redemption of bob's", world.redemptions().none { it.client == "bob" })
            assertTrue("bob holds a write capability", EntDmEvidence.writeCapabilities(world, s.bobDm).isEmpty())
            val bobRegs = EntDmEvidence.registrations(world, s.bobDm)
            assertTrue("bob has no registration row to run: REGROWS never ran", bobRegs.isNotEmpty())
            assertTrue("a registration of bob's is done or held by a relay: $bobRegs", bobRegs.all { it.state == "pending" && !it.recorded })
            val bundle = NamespaceId(bobOwn.getValue("bundle"))
            assertTrue("bob's bundle reached a relay", w.relays.none { r -> r.model.namespaces().contains(bundle) })
            val aliceView = checkNotNull(s.aliceDm.read { d -> d.engine.contacts().single() })
            assertEquals("alice's establishment with bob", Establishment.FETCHING, aliceView.establishment)
            assertEquals("alice's 'hello'", MessageState.QUEUED, s.outgoing(s.aliceDm, HELLO))
            assertTrue("bob shows something", s.inbound(s.bobDm).isEmpty())
            // The quiescence oracle is not blind to this world: it names what alice still owes.
            val owed = world.quiescenceProblems()
            for (what in listOf("pending sends", "establishments in progress", "a LOCAL READ need waits (REJECTED)")) {
                assertTrue("the quiescence oracle does not see alice's '$what': $owed", owed.any { it.startsWith("alice") && what in it })
            }
            println("ENT-DM/no-redemption, what the quiescence oracle reports at the horizon: $owed")
            println(
                "ENT-DM/no-redemption: bob tried $tried redemptions and a relay received none; he holds $tokens access tokens, " +
                    "0 capabilities, ${bobRegs.size} registration rows all pending; alice: ${aliceCaps.size} redeemed capabilities; " +
                    "alice->bob establishment ${aliceView.establishment}, 'hello' ${s.outgoing(s.aliceDm, HELLO)}",
            )
        }
    }

    /**
     * The control of [renewalCarriesDeliveryPastTheOldRegistrations]: the same run with bob's
     * week-2976 redemptions — only those — refused before they leave. Everything up to the boundary
     * is the positive run's (the conversation happens); bob is never renewed, so he never holds a
     * week-2977 registration; and at `start(2978) + 2 h`, when his older registrations are dead,
     * alice's deposits of the new message **reach** the relays and are **not stored** — refused,
     * since no live DEPOSIT registration covers them — and bob never shows the message.
     */
    @Test
    fun withoutBobsRenewalTheLapsedWeekMessageIsRefused() {
        horizon(EntDmConversation(refuseBobRenewal = true)) { s, w ->
            val world = s.dm
            val renewed = WEEK0 + 1
            // Up to the lapse, the positive run's world (read at the last minute of week 2975).
            val before = s.snapshots.getValue(BEFORE_BOUNDARY)
            assertEquals("bob's inbound texts", listOf(HELLO, PAIR_NOW), before.inbound["bob"])
            assertEquals("alice's inbound texts", listOf(HI_BACK), before.inbound["alice"])
            assertTrue("alice was not renewed: the control world is broken", before.caps.getValue("alice").filter { it.bearerKind == null }.all { it.redeemed && it.week == renewed })
            assertTrue("bob was renewed", before.caps.getValue("bob").filter { it.bearerKind == null }.none { it.week == renewed })
            val tried = world.relayEvents.count { e ->
                e.client == "bob" && e.kind == CallKind.REDEEM && e.event == EventKind.RELAY_BEFORE_SEND &&
                    s.ent.records.issued[e.hashes.single()]?.let { it.kind == EntitlementCrypto.KIND_ACCESS && it.epoch == renewed } == true
            }
            assertTrue("bob never tried to renew: the control refused nothing", tried > 0)
            assertTrue("a relay received a week-$renewed redemption of bob's", world.redemptions().none { it.client == "bob" && it.week == renewed })
            val bobInbox = s.bobDm.ownNamespaces().getValue("inbox")
            val lapsedWeek = WEEK0 + 2
            val next = EntDmEvidence.registrations(world, s.bobDm).filter { it.period == lapsedWeek }
            assertTrue("bob holds a week-$lapsedWeek registration: $next", next.none { it.state == "done" || it.recorded })
            // Alice's deposits after the lapse reached the relays and were not stored.
            val lapsed = world.seen().filter { it.client == "alice" && it.kind == CallKind.STORE && it.namespaceHex == hexOf(bobInbox) && it.atMillis >= LAPSED_AT }
            assertTrue("alice's lapsed-week message never reached a relay", lapsed.isNotEmpty())
            val stored = lapsed.filter { e ->
                val node = w.relays.single { it.name == e.relay }
                node.model.member(NamespaceId(bobInbox), BlobHash(org.ghost.entitlement.harness.Bytes.unhex(e.hashes.single()))) != null
            }
            assertTrue("a relay stored a deposit of alice's after the lapse: $stored", stored.isEmpty())
            assertTrue("bob shows the lapsed-week message", AFTER_LAPSE !in s.inbound(s.bobDm))
            val state = s.outgoing(s.aliceDm, AFTER_LAPSE)
            assertTrue("alice's lapsed-week message is SENT", state != MessageState.SENT)
            var credentials = ""
            s.alice.c.jdbc.query(
                "SELECT state, generation FROM relay_capability WHERE namespace_id = ?1 AND kind = 'write' ORDER BY relay_id",
                listOf(bobInbox),
            ) { credentials += "${it.string(0)}/g${it.long(1)} " }
            val owed = world.quiescenceProblems()
            assertTrue("the quiescence oracle does not see alice's parked deposit: $owed", owed.any { it.startsWith("alice") && "DM outbox ops the engine has not released" in it })
            println("ENT-DM/no-renewal, what the quiescence oracle reports at the horizon: $owed")
            var deliveries = ""
            s.alice.c.jdbc.query(
                "SELECT d.state, d.attempts, count(*) FROM outbox_delivery d JOIN outbox_op o ON o.operation_id = d.operation_id " +
                    "WHERE o.namespace_id = ?1 AND o.released = 0 GROUP BY d.state, d.attempts",
                listOf(bobInbox),
            ) { deliveries += "${it.string(0)}×${it.long(2)} (attempts ${it.long(1)}) " }
            println("ENT-DM/no-renewal deliveries of alice's unreleased ops to bob's inbox: $deliveries")
            println(
                "ENT-DM/no-renewal: bob tried $tried week-$renewed redemptions and a relay received none; ${lapsed.size} of alice's " +
                    "deposits reached a relay after the lapse and none was stored; 'after' is $state; alice's DEPOSIT credential " +
                    "rows for bob's inbox (state/generation): $credentials",
            )
        }
    }

    /**
     * The checks catch a shortcut. The positive scenario with a "redeem fairy" — at 2 h the Phase 7
     * helper `Client.capability` installs a relay-minted write capability for bob's inbox at every
     * relay of its set, as the core world does — (a) fails at the commit that installs it, with the
     * world's every-commit check on, as in every other run; and (b) with that check off, runs to its
     * end, delivers the whole conversation (the first thing [verify] checks), and fails the end
     * evidence on exactly the fairy's rows.
     */
    @Test
    fun aRedeemFairyIsCaught() {
        val checked = EntDmConversation(fairyAt = FAIRY_AT)
        val atCommit = runCatching { Runner(checked, JournalMode.WAL, SEED).run(RunSpec()) }.exceptionOrNull()
        closeQuietly(checked)
        assertTrue("the fairy was not caught at its commit: $atCommit", atCommit is AssertionError && atCommit.message.orEmpty().contains("no fairy"))

        val unchecked = EntDmConversation(fairyAt = FAIRY_AT, fairyChecked = false)
        unchecked.outcome = { s -> verify(s as EntDmConversation, ArrayList()) }
        val atEnd = runCatching { Runner(unchecked, JournalMode.WAL, SEED).run(RunSpec()) }.exceptionOrNull()
        closeQuietly(unchecked)
        val message = atEnd?.message.orEmpty()
        assertTrue("the fairy was not caught by the end evidence: $atEnd", atEnd is AssertionError && message.contains("write capabilities no redeem relay minted"))
        val rows = Regex("write@S\\d/\\w+ w-?\\d+ redeemed=false").findAll(message).count()
        assertEquals("the end evidence names the fairy's rows: $message", 3, rows)
        println("ENT-DM/fairy: caught at its commit (${atCommit?.message}); without that check the conversation completed and the end evidence failed on $rows rows")
    }

    /**
     * The reboot path SCN-E's enumeration will need, sampled: the armed client dies at
     * [CRASH_SAMPLES] event indices spread evenly over the fault-free run and reboots — a new sync
     * engine, a new entitlement engine and a new DM stack (a new DM context) over the same database
     * file — and every run still passes the Phase 7, Phase 8 and DM world checks **and** the whole
     * positive outcome of [conversationRunsOnRedeemedCapabilitiesAndRegisteredKeys]. Alice armed
     * here; [survivesSampledCrashesOfBob] arms bob, SCN-E's recipient. A smoke test of the mechanism,
     * not §15.3's enumeration: the points are sampled, not classified (§22.23 says what
     * classification still needs).
     */
    @Test
    fun survivesSampledCrashesOfAlice() = sampledCrashes(armBob = false)

    @Test
    fun survivesSampledCrashesOfBob() = sampledCrashes(armBob = true)

    private fun sampledCrashes(armBob: Boolean) {
        val events = Runner(EntDmConversation(armBob = armBob), JournalMode.WAL, SEED).run(RunSpec()).events
        val points = (1..CRASH_SAMPLES).map { events * it / (CRASH_SAMPLES + 1) }
        val results = DmHarness.parallel(
            points.map { k ->
                "crash@$k" to {
                    val s = EntDmConversation(armBob = armBob)
                    s.outcome = { verify(it as EntDmConversation, ArrayList()) }
                    Runner(s, JournalMode.WAL, SEED).run(RunSpec(crashAt = k))
                }
            },
        )
        for ((k, r) in points.zip(results)) assertEquals("crash@$k did not crash exactly once", 1, r.crashes)
        val who = if (armBob) "bob" else "alice"
        println("ENT-DM/conversation crashes of $who: ${points.size} sampled single crashes over $events events of $who, every run passed")
    }

    /**
     * A control run to its fixed horizon (it cannot reach quiescence by design): the structural
     * invariants of every client, the entitlement world's and the DM world's end checks, then [check].
     */
    private fun horizon(s: EntDmConversation, check: (EntDmConversation, World) -> Unit) {
        World(s.name, SEED, JournalMode.WAL).use { w ->
            s.build(w)
            try {
                w.driver.runUntil(w.endMillis)
                w.clients.forEach { Invariants.structural(it, "horizon") }
                s.ent.structural("horizon")
                s.dm.finalChecks()
                check(s, w)
            } finally {
                s.dm.close()
            }
        }
    }

    private fun closeQuietly(s: EntDmConversation) {
        runCatching { s.dm.close() }
    }

    private companion object {
        const val SEED = 1L
        const val CRASH_SAMPLES = 12
        const val FAIRY_AT = 2 * World.HOUR
    }
}
