package org.ghost.messaging.harness

import org.ghost.messaging.DmWorld
import org.ghost.messaging.api.AddContactResult
import org.ghost.messaging.api.CardSource
import org.ghost.messaging.api.ContactId
import org.ghost.messaging.api.RevocationReason
import org.ghost.messaging.api.SendResult
import org.ghost.messaging.api.Timer
import org.ghost.messaging.api.TrustState

/**
 * The named crash scenarios of Phase 9 design §15.3, as far as slices S10, S10b and S10c implement
 * them.
 *
 * Implemented here: **SCN-A** (send), **SCN-B** (receive and reorder), **SCN-D** (key change,
 * including the forged-binding case), **SCN-F** (ephemeral), **SCN-G** (outcomes and resend),
 * **SCN-J** (faults) and **SCN-L** (migration safety), from S10; **SCN-H** (bundle generations,
 * in part), **SCN-I** (restore), **SCN-K** (revocation) and SCN-G's week-boundary retry as
 * `SCN-G-week`, from S10b; **SCN-C** (establishment through WITHHOLD_NEWEST_BUNDLE), from S10c.
 * SCN-E is not here; §22.15 of the design records what it still owes, §22.19 what S10b left of
 * the rest and §22.22 what S10c left of SCN-C.
 *
 * **Two deviations from §15.3's table, declared.** The scenario texts say "3 relays over 2
 * operators, one refusing" (SCN-A) and similar relay-set shapes elsewhere. The relay set, the
 * quorum and which relay refuses are the Phase 7 sync engine's, and the model relay of this
 * harness stands in for that engine as a whole (see [ModelDmRelay]); what a scenario can therefore
 * vary is the *outcome* a store gets, not which of three relays produced it. Every node is built
 * with four relay slots over two operators so the namespace and registration rows have the shape
 * the invariants check, and what a scenario can do to a store's outcome is
 * [ModelDmRelay.outcomeFor]. **Which scenarios actually use it: SCN-G, and no other.** SCN-A's
 * "one refusing" relay and the refusal half of every other scenario's relay-set text are therefore
 * **not exercised**, which is a gap and not a modelling choice; §22.15 item 6 lists it. The second
 * deviation is `PrivacyMode`: every world here is STANDARD, because `DmDevice` fixes the mode at
 * construction; the HIGH halves of SCN-A and SCN-F are deferred with the rest.
 */
internal object DmScenarios {

    // ------------------------------------------------------------------ SCN-A send

    /**
     * **SCN-A — send.** A → B: three messages over an established pair.
     *
     * The most fundamental atomicity property there is: §7.9 says the ratchet step and the outbox
     * op commit **in one transaction**, so at every one of the K crash points either both happened
     * or neither did. A crash between them shows up as one of two things, and the checks below are
     * exactly those two: a message B can never open (the ratchet moved, the bytes never left), or a
     * message A believes it sent twice (the bytes left, the ratchet did not). Mutant MC-1 is the
     * mutation that splits the transaction, and SCN-A is what kills it — really, now: MC-1 is
     * registered, it is killed by a crash inside the split window of this scenario and by nothing
     * else, and `DmMutantDetectionTest.mc1SplitSendTransactionIsDetectedOnlyByACrash` also asserts
     * that the same crash point leaves the *unmutated* world green. That is the control the
     * enumeration was missing: without a mutant only a crash can kill, nothing said that two
     * thousand crash runs could fail at all.
     *
     * **What kills it is the no-loss oracle, not the checks below.** The `alwaysChecks` here are
     * safety properties — a subsequence, in order, each at most once — and a world that simply lost
     * the message satisfies every one of them. §15.3's two liveness oracles are what refuse that,
     * and this scenario turns both on.
     *
     * **Declared gap, §15.3's "3 relays over 2 operators, one refusing".** Neither `relay.modes`
     * nor `relay.outcomeFor` is set here, so every store in SCN-A gets the honest `sent`: the
     * refusing relay of the scenario text is **not** exercised, and §22.15 item 6 now says so.
     * What the model relay can express is the outcome a store got and not which of three relays
     * produced it (item 4), and a refusal here would make SCN-A a second SCN-G rather than the
     * clean atomicity scenario it is.
     */
    fun scnA(): DmScenario = DmScenario(
        name = "SCN-A",
        doubles = true,
        liveness = "alice" to "bob",
        noLoss = true,
        setup = { world ->
            world.node("alice", 0x41)
            world.node("bob", 0x51)
            DmScripts.activate(world)
            DmScripts.establishBothWays(world, "alice", "bob")
            world.notes["baseline"] = DmScripts.inboundTexts(world, "bob").size
        },
        steps = listOf(
            step("send m1") { w ->
                w["alice"].device.engine.send(DmScripts.contact(w, "alice", "bob"), "m1", null)
            },
            step("round 1") { w -> w.pump(); w.passes() },
            step("send m2") { w ->
                w["alice"].device.engine.send(DmScripts.contact(w, "alice", "bob"), "m2", null)
            },
            step("round 2") { w -> w.pump(); w.passes() },
            step("send m3") { w ->
                w["alice"].device.engine.send(DmScripts.contact(w, "alice", "bob"), "m3", null)
            },
            step("round 3") { w -> w.pump(); w.passes() },
        ),
        alwaysChecks = { world ->
            // What holds however the run was faulted: B saw a **prefix-respecting subsequence** of
            // what A sent, in order, each at most once. A crash may lose a send; it may never
            // reorder, duplicate, or invent one.
            val seen = DmScripts.inboundTexts(world, "bob").filter { it.startsWith("m") }
            if (seen != seen.sorted() || seen.toSet().size != seen.size) {
                dmViolation("SCN-A: bob rendered $seen — out of order or duplicated")
            }
            if (seen.any { it !in setOf("m1", "m2", "m3") }) {
                dmViolation("SCN-A: bob rendered a message alice never sent: $seen")
            }
        },
        finalChecks = { world ->
            val seen = DmScripts.inboundTexts(world, "bob").filter { it.startsWith("m") }
            if (seen != listOf("m1", "m2", "m3")) {
                dmViolation("SCN-A fault-free: bob saw $seen, expected [m1, m2, m3]")
            }
            val states = DmScripts.outboundStates(world, "alice").takeLast(3)
            if (states.any { it != "SENT" }) {
                dmViolation("SCN-A fault-free: alice's last three sends are $states")
            }
        },
    )

    // ------------------------------------------------------------------ SCN-B receive

    /**
     * **SCN-B — receive.** Six messages reordered across the relay set (SHUFFLE and REPEATS).
     *
     * §7.7's rendering order is `(sort_minute, minute_index)` and nothing else, so the order B
     * renders must be A's order whatever order the blobs arrive in — that is CS-4, and mutant
     * MC-10 ("arrival-order display") is what it kills.
     *
     * **What REPEATS does, exactly, and what it does not.** It offers every blob a second time with
     * the same bytes, and the second copy is **always refused by the recipient's own `inbox_blob`
     * row** — the D1 tombstone — so it never reaches RECV. That is D1 doing its job, one layer
     * below `:messaging`, and the finalCheck below asserts the refusals happened rather than
     * assuming the mode did something: the mode was a silent no-op before it was measured, and the
     * doc comment that said "REPEATS puts the same bytes in twice, which is D1's job" would have
     * survived the mode being deleted. What is therefore **not** exercised here is a duplicate blob
     * in front of RECV itself, which is RP1/RP2's subject; §22.15 item 6 records it.
     *
     * **Not here:** the RESURRECT-after-tombstone-GC blob and the MC-29 variant with an injected
     * unknown ratchet key against an inactive sending ratchet. The first needs a tombstone-GC step
     * the world does not have; the second needs an envelope the harness cannot build without a
     * second handle on the peer's session state. §22.15 records both. SCN-B's COPY_NAMESPACE blob
     * is covered instead by the RP3 half of `DmSuiteCases.rpHostileBlobsDoNotOpenAndAnswerNothing`,
     * where it is the whole of the case rather than one blob among six.
     */
    fun scnB(): DmScenario = DmScenario(
        name = "SCN-B",
        doubles = true,
        liveness = "alice" to "bob",
        noLoss = true,
        setup = { world ->
            world.node("alice", 0x41)
            world.node("bob", 0x51)
            DmScripts.activate(world)
            DmScripts.establishBothWays(world, "alice", "bob")
            world.relay.modes = setOf(ModelDmRelay.Mode.SHUFFLE, ModelDmRelay.Mode.REPEATS)
        },
        steps = listOf(
            step("six sends") { w ->
                val contact = DmScripts.contact(w, "alice", "bob")
                for (i in 1..6) {
                    w["alice"].device.engine.send(contact, "b$i", null)
                    // Distinct author minutes, so the rendering order is decided by §7.7's pair and
                    // not by the tie-break: a test that cannot tell the two apart proves neither.
                    w.advanceBy(DmWorld.MINUTE)
                }
            },
            step("scrambled delivery") { w -> w.pump(); w.passes() },
            step("second round") { w -> w.pump(); w.passes() },
        ),
        alwaysChecks = { world ->
            val seen = DmScripts.inboundTexts(world, "bob").filter { it.startsWith("b") }
            if (seen != seen.sortedBy { it.substring(1).toInt() }) {
                dmViolation("SCN-B: bob rendered $seen out of A's order (CS-4)")
            }
            if (seen.toSet().size != seen.size) {
                dmViolation("SCN-B: bob rendered a duplicate: $seen")
            }
        },
        finalChecks = { world ->
            val seen = DmScripts.inboundTexts(world, "bob").filter { it.startsWith("b") }
            if (seen != (1..6).map { "b$it" }) {
                dmViolation("SCN-B fault-free: bob saw $seen")
            }
            // SHUFFLE is measured by the order check above; REPEATS is measured here. Both halves
            // of the mode have to be non-vacuous or the scenario is a six-message send.
            if (world.relay.repeatsOffered == 0) {
                dmViolation("SCN-B: REPEATS offered no second copy at all")
            }
            if (world.relay.repeatsRefused != world.relay.repeatsOffered) {
                dmViolation(
                    "SCN-B: ${world.relay.repeatsOffered} second copies were offered and only " +
                        "${world.relay.repeatsRefused} were refused by the tombstone",
                )
            }
        },
    )

    // ------------------------------------------------------------------ SCN-C establishment

    /**
     * **SCN-C — establishment under a relay that withholds the newest bundle** (§15.3, §5.5, §21.7;
     * slice S10c).
     *
     * > card → fetch with WITHHOLD_NEWEST_BUNDLE → `sessionOutbound` → intro PreKey messages → the
     * > recipient's request and accept → provisional reply carrying a root → pair mode on both sides
     *
     * Every other scenario runs the establishment in its **unarmed** setup through an honest relay;
     * this one is the establishment under the enumeration, through a hostile one
     * ([ModelDmRelay.Mode.WITHHOLD_NEWEST_BUNDLE]: in a bundle namespace the newest bundle is never
     * listed, every older one is). The mode has two consequences, and the scenario is built so that
     * the world reaches both.
     *
     * **Part one — the bounded fetch-attempt budget (§21.7 point 5).** bob has just activated, so
     * the one bundle he has published is the newest and nothing is listed. alice scans his card and
     * writes `c0`: `EST-START` opens a 15-minute window, `EST-END` closes it empty and waits six
     * hours, and after the **third** window the contact is `unreachable` and `c0` fails. Checked,
     * in every run, the moment part one is over ([theBudgetIsSpent]): `unreachable` with three
     * attempts, `c0` FAILED, `P_bob` not listened — and seven hours later still no fourth window.
     * And, in every run, from the **relay's** side (L7-D6, §21.7 point 6): alice's listings of
     * `P_bob` fall into at most three windows per establishment, each no longer than the window
     * itself, at least six hours apart ([listingWindows]); fault-free, exactly three.
     *
     * **Part two — an establishment on a superseded generation.** bob's OWNER-WEEK of the next week
     * publishes a new bundle and supersedes the first generation; the relay now withholds *that*
     * one and lists the older, still valid bundle. alice writes `c1` (a send is the user's retry
     * of §21.7 point 5 and §13.5's `unreachable → fetching`, which resets the budget), fetches the
     * older bundle, pins, and `sessionOutbound` builds on generation `g1`; `c1` and `c2` are intro
     * PreKey messages naming it; bob opens them with the superseded generation's secrets (§5.4:
     * kept until `superseded_day + 91`), holds a request, accepts, and answers `c-ack` —
     * provisional, since alice's root cannot ride in a PreKey message, and carrying bob's root;
     * alice answers `c3` in pair mode, bob `c4` in pair mode. carol is the **second fetcher of the
     * same bundle** — §15.7 names SCN-C "with two fetchers of one bundle" as the case in which
     * one-time keys would fail the second PreKey message (MC-11) — and her `d1` must open on `g1`
     * beside alice's first flight.
     *
     * **Checked in every run** (`alwaysChecks`), because every user action the case depends on is
     * done again when a crash interrupted it (below): the spent budget was checked; `c0` never
     * reached bob, and is FAILED if it is still on alice's screen (the conversation keeps the
     * default seven-day timer, and bob's next publication falls days after `c0` expires, so its row
     * is usually gone — §10.6 deletes a FAILED message at its expiry like any other);
     * the relay-side window bounds of both parts; both fetchers' sessions name `g1` and neither ever
     * saw a bundle newer than bob's first week (`bundle_week_seen`); bob still holds `g1`,
     * superseded, and opened exactly two first flights on it; bob's session towards alice sealed a
     * provisional envelope (`prov_anchor_minute`) and both sides sealed a pair envelope
     * (`pair_sent`) that the other side opened (`dm_pair_offer.acknowledged`). The flow orders these:
     * alice seals in pair mode only with an out key from bob's root, and bob's only message before
     * her `c3` is `c-ack`, so "the provisional reply carried the root" is what the two facts say
     * together. **Fault-free** (`finalChecks`): exactly three windows in part one and one per fetcher
     * in part two; the relay kept back exactly the three (bundle, listener) pairs the script makes
     * it — the first bundle from alice in part one, the second from alice and from carol in part
     * two; `c1` and `c2` both reached bob's **request**, before he answered, so both were intro.
     *
     * **The oracles.** No-loss and liveness (alice ↔ bob) on; "nothing owed" on, with `c0` the one
     * message allowed to end FAILED — it is the budget's subject.
     *
     * **User actions are done again when a crash interrupted them**, S10b's rule, each judged from
     * what the user can see: a card in the contact list, a message in the conversation, a request
     * accepted, and each answer only once the message it answers is on screen ([cStage]). A step
     * redoes only the actions of the steps **before** it, so the fault-free run is the script as
     * written. Two settle steps end the script, so a crash that costs one of them the last answer
     * leaves the other to write it. alice writes `c2` only once `c1` **went out** — not merely once
     * it was written: a send is itself the user action that restarts an establishment, so a `c2`
     * written beside a stuck `c1` repairs the very stall the enumeration must see. With `c2` gated
     * on "written", it did exactly that for 34 consecutive crash points of `c1`'s send, and the
     * engine defect §22.22 records stayed invisible at every one of them.
     *
     * **What the model relay stands in for, declared.** "The first relay session start at least
     * 6 h later" is modelled by jumping the clock to the engine's own decision minute and running a
     * time-triggered pass **before** the next pump, and every window and fetch round of SCN-C runs
     * one before its first pump, so a window is closed by the pass a device would run at a session
     * start and not listed once more by the harness's own ordering. Quiescence pumps first; the
     * span bound allows its one step. Part one runs **alice's** passes only: bob and carol have
     * nothing to do in it, and their passes would add crash points on idle devices and nothing else.
     *
     * **No double crashes** (§15.3 names them for SCN-A, SCN-B, SCN-F and SCN-I) and **no §15.7
     * mutant**: MC-11 is the mutant §15.7 detects with this scenario, and it needs a native seam —
     * one-time keys in the bundle — that no statement rewrite, envelope decorator or transaction
     * split can reach. §22.22 records both.
     */
    fun scnC(): DmScenario = DmScenario(
        name = "SCN-C",
        liveness = "alice" to "bob",
        noLoss = true,
        expectedFailures = setOf(C_LOST),
        setup = { world ->
            world.node("alice", 0x41)
            world.node("bob", 0x51)
            world.node("carol", 0x61)
            DmScripts.activate(world)
            world.relay.modes = setOf(ModelDmRelay.Mode.WITHHOLD_NEWEST_BUNDLE)
            val own = requireNotNull(world["bob"].device.crypto.ownCard(0)) { "bob has no card" }
            val now = world.nodes().maxOf { it.clock.now }
            val week = Math.floorDiv(now - DmWorld.WEEK_ORIGIN, DmWorld.WEEK)
            val nextPublication = weekStart(week + 1) + own.publicationOffsetSeconds
            // The premise of part two: bob's next publication leaves the first bundle valid long
            // enough to be fetched (§5.4: until `start(w + 2)`). A fixed function of bob's card,
            // so this either holds in every run or fails here, loudly, in every run.
            check(weekStart(week + 2) - nextPublication >= 2 * DmWorld.HOUR) {
                "SCN-C: bob publishes at ${own.publicationOffsetSeconds} s into the week, too late " +
                    "for his first bundle to be fetched before it expires"
            }
            world.notes[C_WEEK] = week
            world.notes[C_PART_TWO] = nextPublication
            world.notes[C_BUNDLE_NS] = own.bundleNamespace.hex()
            world.notes[C_GENERATION] = currentGeneration(world, "bob") ?: error("bob has no generation")
        },
        steps = listOf(
            step("alice scans bob's card and writes; the first window") { w ->
                ensurePartOne(w)
                attemptWindow(w)
            },
            step("the second window, six hours on") { w ->
                ensurePartOne(w)
                nextDecision(w)
            },
            step("the third window") { w ->
                ensurePartOne(w)
                nextDecision(w)
            },
            step("the budget is spent: unreachable, and no fourth window") { w ->
                finishPartOne(w)
                theBudgetIsSpent(w)
            },
            cStep("bob's next weekly publication supersedes the first generation", stage = 1),
            // Two rounds with a pass before the pump: the fetch and `BUNDLE` in the first,
            // `EST-READY` two minutes later, the flush, and bob's `RECV` in the second.
            cStep("alice writes again and carol scans bob's card and writes", stage = 2, fetchRounds = 2),
            cStep("alice's second intro message", stage = 3),
            cStep("bob accepts alice's request and answers", stage = 4),
            cStep("alice writes in pair mode", stage = 5),
            cStep("bob writes in pair mode", stage = 6),
            cStep("settle", stage = C_STAGES, settle = true),
            cStep("the settling a crash cost the step above, if it did", stage = C_STAGES, settle = true),
        ),
        alwaysChecks = { world ->
            if (world.notes[C_BUDGET_CHECKED] != true) {
                dmViolation("SCN-C: part one never reached its end, so the spent budget was never checked")
            }
            if (world.contacts["bob->alice"] == null) {
                dmViolation("SCN-C: bob never accepted alice's request, so no reply was ever possible")
            }
            // `c0` failed with the budget (checked where it happened, [theBudgetIsSpent]) and
            // nothing may deliver it later. Its row is usually **gone** by now: the conversation
            // keeps the default seven-day timer, and bob's next publication falls days after that
            // (§10.6 deletes a FAILED message at its expiry like any other). So what holds in every
            // run is that it is not on alice's screen in any other state, and not on bob's at all.
            val lost = DmScripts.outgoingState(world, "alice", C_LOST)
            if (lost != null && lost != org.ghost.messaging.api.MessageState.FAILED) {
                dmViolation("SCN-C: $C_LOST is $lost — a spent budget fails the pending items (§21.7 point 5)")
            }
            if (C_LOST in DmScripts.everyInboundText(world["bob"])) {
                dmViolation("SCN-C: bob rendered $C_LOST, which the spent budget had failed")
            }
            val partTwo = world.notes[C_PART_TWO] as Long
            checkWindows(world, "alice", 0L, partTwo, "before bob's second publication")
            checkWindows(world, "alice", partTwo, Long.MAX_VALUE, "after she wrote again")
            checkWindows(world, "carol", partTwo, Long.MAX_VALUE, "")
            val g1 = world.notes[C_GENERATION] as Long
            val week = world.notes[C_WEEK] as Long
            for ((node, key) in listOf("alice" to "alice->bob", "carol" to "carol->bob")) {
                val gen = sessionColumn(world, node, key, "peer_gen_id")
                if (gen != g1) {
                    dmViolation(
                        "SCN-C: $node's session names generation $gen, not bob's first ($g1) — " +
                            "the newest bundle reached her, or no fetch built a session",
                    )
                }
                val seen = contactColumn(world, node, key, "bundle_week_seen")
                if (seen != week) {
                    dmViolation("SCN-C: $node saw a bundle of week $seen; the relay only ever listed week $week's")
                }
            }
            // bob kept the superseded generation and opened both first flights on it (§5.4; the
            // fallback key is reusable, which is what MC-11's one-time keys would break).
            val superseded = DmScripts.count(
                world, "bob",
                "SELECT count(*) FROM olm_prekey_gen WHERE gen_id = $g1 AND superseded_day IS NOT NULL",
            )
            if (superseded != 1L) {
                dmViolation("SCN-C: bob's first generation is not held as a superseded one ($superseded rows)")
            }
            val flights = DmScripts.count(world, "bob", "SELECT count(*) FROM olm_prekey_used WHERE gen_id = $g1")
            if (flights != 2L) {
                dmViolation("SCN-C: bob opened $flights first flights on generation $g1, expected alice's and carol's")
            }
            // A provisional reply, then pair mode on both sides, each opened by the other side.
            if (sessionColumn(world, "bob", "bob->alice", "prov_anchor_minute") == null) {
                dmViolation("SCN-C: bob's session towards alice never sealed a provisional envelope (§6.7)")
            }
            for ((node, key) in listOf("alice" to "alice->bob", "bob" to "bob->alice")) {
                if (sessionColumn(world, node, key, "pair_sent") != 1L) {
                    dmViolation("SCN-C: $node never sealed a pair envelope on its current session (§6.3)")
                }
                val acknowledged = DmScripts.count(
                    world, node,
                    "SELECT count(*) FROM dm_pair_offer WHERE acknowledged = 1 " +
                        "AND contact_id = X'${contactBytes(world, key).hex()}'",
                )
                if (acknowledged == 0L) {
                    dmViolation("SCN-C: no pair envelope under $node's root ever opened on the other side")
                }
            }
        },
        finalChecks = { world ->
            val partTwo = world.notes[C_PART_TWO] as Long
            val windows = listOf(
                listingWindows(world, "alice", 0L, partTwo).size,
                listingWindows(world, "alice", partTwo, Long.MAX_VALUE).size,
                listingWindows(world, "carol", partTwo, Long.MAX_VALUE).size,
            )
            if (windows != listOf(3, 1, 1)) {
                dmViolation(
                    "SCN-C fault-free: attempt windows (alice before, alice after, carol) were " +
                        "$windows, expected [3, 1, 1]",
                )
            }
            if (world.relay.withheldNewest != 3) {
                dmViolation(
                    "SCN-C fault-free: the relay kept back ${world.relay.withheldNewest} (bundle, " +
                        "listener) pairs, expected 3 — the first bundle from alice, the second " +
                        "from alice and from carol",
                )
            }
            @Suppress("UNCHECKED_CAST")
            val beforeAccept = world.notes[C_BEFORE_ACCEPT] as List<String>?
            if (beforeAccept == null || !beforeAccept.containsAll(listOf("c1", "c2"))) {
                dmViolation(
                    "SCN-C fault-free: bob's request held $beforeAccept when he accepted — c1 and c2 " +
                        "were not both intro PreKey messages",
                )
            }
            if ("d1" !in DmScripts.everyInboundText(world["bob"])) {
                dmViolation("SCN-C fault-free: carol's first flight on the same bundle never opened")
            }
        },
    )

    /** The part-one user actions: alice scans bob's card and writes `c0`, each done again if lost. */
    private fun ensurePartOne(w: DmCrashWorld) {
        ensureCard(w, "alice", "alice->bob")
        ensureWritten(w, "alice", "alice->bob", C_LOST)
    }

    /** [from] scans bob's card, unless its list already holds him — the user's own evidence. */
    private fun ensureCard(w: DmCrashWorld, from: String, key: String) {
        if (w.contacts[key] != null) return
        val engine = w[from].device.engine
        when (val added = engine.addContact(w["bob"].device.card(), CardSource.QR_IN_PERSON)) {
            // `ALREADY_KNOWN`: a crash lost only the moment the id was recorded, not the card.
            AddContactResult.ADDED, AddContactResult.ALREADY_KNOWN ->
                w.contacts[key] = engine.contacts().single().id
            else -> dmViolation("SCN-C: $from could not add bob's card: $added")
        }
    }

    /** Whether [from]'s conversation under [key] shows [text] as its own message. */
    private fun written(w: DmCrashWorld, from: String, key: String, text: String): Boolean {
        val contact = w.contacts[key] ?: return false
        return w[from].device.engine.conversation(contact, 50, null).any { it.outgoing && it.text == text }
    }

    /**
     * [from] writes [text] unless its conversation already shows it: judged from the screen and
     * never from a note written after the call returned, since a send that committed and died at
     * its post-commit event never returns (§22.19 item 9).
     */
    private fun ensureWritten(w: DmCrashWorld, from: String, key: String, text: String) {
        val contact = w.contacts[key] ?: return
        if (written(w, from, key, text)) return
        w[from].device.engine.send(contact, text, null)
    }

    /**
     * One SCN-C fetch round: a time-triggered pass **before** the pump, so a window whose end has
     * passed is closed by the pass a device runs at a relay session start and is not listed once
     * more by the harness's own ordering; then the pump, the pass it hints, and three minutes —
     * more than `EST-READY`'s two.
     */
    private fun cRound(w: DmCrashWorld) {
        w.passes()
        w.pump()
        w.passes()
        w.advanceBy(3 * DmWorld.MINUTE)
    }

    /** One delivery once no window is open: the pump, the pass that consumes what it brought. */
    private fun deliver(w: DmCrashWorld) {
        w.pump()
        w.passes()
        w.advanceBy(3 * DmWorld.MINUTE)
    }

    /**
     * Sixteen minutes of an open window of alice's: two list events eight minutes apart, then her
     * pass that finds the window's end (`ceil_minute(start + 15 min)`) behind it and runs
     * `EST-END`. Only alice's passes in part one: bob and carol have nothing to do there, and
     * their passes would add crash points in SWEEP and KEEPER on idle devices and nothing else.
     */
    private fun attemptWindow(w: DmCrashWorld) {
        repeat(2) {
            w.pump()
            w.advanceBy(8 * DmWorld.MINUTE)
        }
        w.pass("alice")
    }

    /**
     * alice's establishment for bob one decision further, from wherever it stands: an overdue pass
     * first; then, between windows, the clock to the engine's own decision minute — "the first
     * relay session start at least 6 h later" (§21.7 point 5) — and the pass that opens the next
     * window; then the window.
     */
    private fun nextDecision(w: DmCrashWorld) {
        w.pass("alice")
        val fetch = fetchState(w, "alice", "alice->bob") ?: return
        if (fetch.establishment != "fetching") return
        if (!fetch.listening) {
            val now = w.nodes().maxOf { it.clock.now }
            val until = fetch.until ?: return
            if (until > now) w.advanceBy(until - now + DmWorld.MINUTE)
            w.pass("alice")
        }
        attemptWindow(w)
    }

    /**
     * Part one driven to its end, however many of its steps a crash cost — and nothing once its
     * end was checked: `c0` is then FAILED, or already deleted at its expiry, and redoing it would
     * write a message the user never wrote twice.
     */
    private fun finishPartOne(w: DmCrashWorld) {
        if (w.notes[C_BUDGET_CHECKED] == true) return
        ensurePartOne(w)
        for (attempt in 0 until C_MAX_DECISIONS) {
            val fetch = fetchState(w, "alice", "alice->bob") ?: return
            if (fetch.establishment != "fetching") return
            nextDecision(w)
        }
    }

    /**
     * §21.7 point 5, checked the moment part one is over, in every run: three attempts, the contact
     * `unreachable`, its pending item FAILED, `P_bob` no longer listened — and, seven hours later
     * (past the six-hour spacing), still no fourth window, from the engine's side and from the
     * relay's. Done once; later steps call it again and it returns.
     */
    private fun theBudgetIsSpent(w: DmCrashWorld) {
        if (w.notes[C_BUDGET_CHECKED] == true) return
        val fetch = fetchState(w, "alice", "alice->bob")
            ?: dmViolation("SCN-C: alice holds no contact for bob at the end of part one")
        if (fetch.establishment != "unreachable" || fetch.attempts != C_MAX_ATTEMPTS.toLong()) {
            dmViolation(
                "SCN-C: after its windows alice's establishment is ${fetch.establishment} with " +
                    "${fetch.attempts} attempts — §21.7 point 5 ends it unreachable after the third",
            )
        }
        if (fetch.listening) dmViolation("SCN-C: an unreachable contact's bundle namespace is still listened")
        val lost = DmScripts.outgoingState(w, "alice", C_LOST)
        if (lost != org.ghost.messaging.api.MessageState.FAILED) {
            dmViolation("SCN-C: the spent budget left $C_LOST $lost, not FAILED (§21.7 point 5)")
        }
        val partTwo = w.notes[C_PART_TWO] as Long
        val before = listingWindows(w, "alice", 0L, partTwo)
        val listed = w.relay.bundleListings.size
        w.advanceBy(7 * DmWorld.HOUR)
        w.pass("alice")
        w.pump()
        w.pass("alice")
        val after = fetchState(w, "alice", "alice->bob")
        if (after == null || after.establishment != "unreachable" || after.listening) {
            dmViolation("SCN-C: a fourth attempt started without a user action (${after?.establishment})")
        }
        if (w.relay.bundleListings.size != listed) {
            dmViolation("SCN-C: bob's bundle namespace was listed after the budget was spent")
        }
        if (before.size > C_MAX_ATTEMPTS) {
            dmViolation("SCN-C: alice listed bob's bundle namespace in ${before.size} windows before the budget ran out")
        }
        w.notes[C_BUDGET_CHECKED] = true
    }

    /**
     * One step of part two: part one finished and checked (a no-op once done), then every action
     * of the stages **before** [stage] that a crash may have lost, then this stage's own, then
     * [fetchRounds] fetch rounds ([cRound]) or one delivery. With [settle], every stage is passed
     * again around a settled world, so an answer whose trigger arrives while settling is written;
     * each pass costs no event when there is nothing left to do.
     */
    private fun cStep(label: String, stage: Int, fetchRounds: Int = 0, settle: Boolean = false): DmScenario.Step =
        step(label) { w ->
            finishPartOne(w)
            theBudgetIsSpent(w)
            for (s in 1..stage) cStage(w, s)
            if (settle) {
                repeat(C_SETTLE_PASSES) {
                    untilSettled(w)
                    for (s in 1..stage) cStage(w, s)
                }
                untilSettled(w)
            } else if (fetchRounds > 0) {
                repeat(fetchRounds) { cRound(w) }
            } else {
                deliver(w)
            }
        }

    /** The user actions of part two, by stage; each idempotent and judged from the screen. */
    private fun cStage(w: DmCrashWorld, stage: Int) {
        when (stage) {
            1 -> ensureBobPublished(w)
            2 -> {
                ensureWritten(w, "alice", "alice->bob", "c1")
                ensureCard(w, "carol", "carol->bob")
                ensureWritten(w, "carol", "carol->bob", "d1")
            }
            // alice writes `c2` once she sees `c1` go out — not merely once it is written. The
            // difference is the point: a send is itself a user action that restarts an
            // establishment (`userRetry`), so a `c2` written while `c1` is stuck would repair the
            // very stall this scenario must see, which is how S10b's review found its stranded-send
            // mutant passing every crash point of SCN-I.
            3 -> if (DmScripts.outgoingState(w, "alice", "c1") == org.ghost.messaging.api.MessageState.SENT) {
                ensureWritten(w, "alice", "alice->bob", "c2")
            }
            4 -> acceptAliceAndAnswer(w)
            5 -> {
                val toBob = w.contacts["alice->bob"] ?: return
                if ("c-ack" in DmScripts.inboundTextsWith(w, "alice", toBob)) {
                    ensureWritten(w, "alice", "alice->bob", "c3")
                }
            }
            6 -> {
                val toAlice = w.contacts["bob->alice"] ?: return
                if ("c3" in DmScripts.inboundTextsWith(w, "bob", toAlice)) {
                    ensureWritten(w, "bob", "bob->alice", "c4")
                }
            }
        }
    }

    /**
     * bob's weekly publication of the week after his activation: the clock to `t_pub(w + 1)` and
     * the time-triggered pass OWNER-WEEK runs in (§5.4). Not a user action — any later pass
     * publishes it — but the part-two steps start from it, so they make sure of it first. Part one
     * must be over before the jump, and it is: nothing is in flight by then ([untilSettled]).
     */
    private fun ensureBobPublished(w: DmCrashWorld) {
        val next = (w.notes[C_WEEK] as Long) + 1
        var published = -1L
        w["bob"].raw.query("SELECT bundle_week FROM dm_self") { if (!it.isNull(0)) published = it.long(0) }
        if (published >= next) return
        untilSettled(w)
        val now = w.nodes().maxOf { it.clock.now }
        val due = w.notes[C_PART_TWO] as Long
        if (now < due) w.advanceBy(due - now + DmWorld.MINUTE)
        w.passes()
    }

    /**
     * bob accepts the request that carries alice's messages — the one whose conversation shows
     * `c1` or `c2`, which is how the user tells two requests apart — and answers `c-ack`. The
     * acceptance is judged from his contact list and the answer from his conversation.
     */
    private fun acceptAliceAndAnswer(w: DmCrashWorld) {
        val bob = w["bob"].device.engine
        val fromAlice = bob.contacts().firstOrNull { contact ->
            bob.conversation(contact.id, 50, null).any { !it.outgoing && (it.text == "c1" || it.text == "c2") }
        } ?: return
        if (fromAlice.trust == TrustState.REQUEST) {
            // What the request held when bob answered it: fault-free, both intro messages.
            w.notes[C_BEFORE_ACCEPT] = bob.conversation(fromAlice.id, 50, null)
                .filter { !it.outgoing }.mapNotNull { it.text }
            if (!bob.acceptRequest(fromAlice.id)) dmViolation("SCN-C: bob could not accept alice's request")
        }
        w.contacts["bob->alice"] = fromAlice.id
        ensureWritten(w, "bob", "bob->alice", "c-ack")
    }

    /** alice's (or carol's) establishment for bob, read on the raw connection: no event. */
    private class Fetch(val establishment: String, val attempts: Long, val until: Long?, val listening: Boolean)

    private fun fetchState(w: DmCrashWorld, node: String, key: String): Fetch? {
        val contact = w.contacts[key] ?: return null
        var fetch: Fetch? = null
        w[node].raw.query(
            "SELECT establishment, fetch_attempts, fetch_listen_until_minute FROM dm_contact " +
                "WHERE contact_id = ?",
            listOf(contact.toByteArray()),
        ) {
            fetch = Fetch(it.string(0), it.long(1), if (it.isNull(2)) null else it.long(2), false)
        }
        val found = fetch ?: return null
        var listening = false
        w[node].raw.query(
            "SELECT listening FROM sync_namespace WHERE lower(hex(namespace_id)) = ?",
            listOf(w.notes[C_BUNDLE_NS] as String),
        ) { listening = it.long(0) == 1L }
        return Fetch(found.establishment, found.attempts, found.until, listening)
    }

    /**
     * [node]'s attempt windows **as the relay sees them**: its list events of bob's `P_0` in
     * [from, to), a new window wherever two are more than an hour apart (windows are fifteen
     * minutes long and six hours apart, §21.7 point 5).
     */
    private fun listingWindows(w: DmCrashWorld, node: String, from: Long, to: Long): List<LongArray> {
        val namespace = w.notes[C_BUNDLE_NS] as String
        val out = ArrayList<LongArray>()
        w.relay.bundleListings
            .filter { it.node == node && it.namespace == namespace && it.at >= from && it.at < to }
            .map { it.at }
            .sorted()
            .forEach { at ->
                val last = out.lastOrNull()
                if (last != null && at - last[1] <= DmWorld.HOUR) last[1] = at else out += longArrayOf(at, at)
            }
        return out
    }

    /**
     * The relay-side bound of §21.7 points 5 and 6 over [node]'s listings in [from, to): at most
     * three windows for the one establishment the range holds, none listed for longer than a
     * window, and each at least six hours after the one before.
     */
    private fun checkWindows(w: DmCrashWorld, node: String, from: Long, to: Long, what: String) {
        val windows = listingWindows(w, node, from, to)
        val label = if (what.isEmpty()) node else "$node $what"
        if (windows.size > C_MAX_ATTEMPTS) {
            dmViolation(
                "SCN-C: $label listed bob's bundle namespace in ${windows.size} attempt windows — " +
                    "§21.7 point 5 bounds an establishment at $C_MAX_ATTEMPTS",
            )
        }
        for (window in windows) {
            val span = window[1] - window[0]
            if (span > C_WINDOW_LISTING_SPAN) {
                dmViolation("SCN-C: $label listed bob's bundle namespace for ${span / 60} minutes in one window")
            }
        }
        for ((a, b) in windows.zipWithNext()) {
            if (b[0] - a[0] < C_NEXT_ATTEMPT) {
                dmViolation(
                    "SCN-C: $label opened two attempt windows ${(b[0] - a[0]) / 60} minutes apart; " +
                        "§21.7 point 5 spaces them at least six hours",
                )
            }
        }
    }

    private fun sessionColumn(w: DmCrashWorld, node: String, key: String, column: String): Long? {
        var out: Long? = null
        w[node].raw.query(
            "SELECT $column FROM olm_session WHERE contact_id = ? AND slot = 'current'",
            listOf(contactBytes(w, key)),
        ) { if (!it.isNull(0)) out = it.long(0) }
        return out
    }

    private fun contactColumn(w: DmCrashWorld, node: String, key: String, column: String): Long? {
        var out: Long? = null
        w[node].raw.query(
            "SELECT $column FROM dm_contact WHERE contact_id = ?",
            listOf(contactBytes(w, key)),
        ) { if (!it.isNull(0)) out = it.long(0) }
        return out
    }

    private fun weekStart(week: Long): Long = DmWorld.WEEK_ORIGIN + week * DmWorld.WEEK

    /** The message the spent budget fails: SCN-C's one expected failure. */
    private const val C_LOST: String = "c0"

    /** Part two's stages ([cStage]); the settle steps run all of them. */
    private const val C_STAGES: Int = 6

    /** §21.7 point 5: three windows per establishment (`EstablishmentSteps.MAX_FETCH_ATTEMPTS`). */
    private const val C_MAX_ATTEMPTS: Int = 3

    /** Decisions [finishPartOne] may drive: three windows, with one spare for a lost step. */
    private const val C_MAX_DECISIONS: Int = 4

    /** §21.7 point 5's spacing between attempts, which L7-D6 declares. */
    private const val C_NEXT_ATTEMPT: Long = 6 * DmWorld.HOUR

    /**
     * The longest a window may be listed: its fifteen minutes (`FETCH_WINDOW_SECONDS`), the
     * minute `ceil_minute` can add, and one quiescence step — the runner's quiescence loop pumps
     * before its pass, so a window whose end falls between two of its steps is listed once more
     * before the pass that closes it. SCN-C's own rounds run the pass first and never need the
     * step; the fault-free run lists each window for eight minutes.
     */
    private const val C_WINDOW_LISTING_SPAN: Long = 21 * DmWorld.MINUTE

    /** How often a settle step settles the world and passes every stage again. */
    private const val C_SETTLE_PASSES: Int = 3

    private const val C_WEEK = "cWeek"
    private const val C_PART_TWO = "cPartTwo"
    private const val C_BUNDLE_NS = "cBundleNs"
    private const val C_GENERATION = "cGeneration"
    private const val C_BUDGET_CHECKED = "cBudgetChecked"
    private const val C_BEFORE_ACCEPT = "cBeforeAccept"

    // ------------------------------------------------------------------ SCN-D key change

    /**
     * **SCN-D — key change**, with the forged variant.
     *
     * §8.3: B's Olm identity changes under a binding valid for B's *pinned* Ed25519 key, so A moves
     * the contact to `changed`, refuses to send, and **holds** what arrives instead of showing it.
     * A third client that does not hold B's Ed25519 secret produces a **forgery**, and §8.3's E-1
     * says a forgery is dropped with *no state change at all* — which is the half a crash run can
     * break most easily, because "no state change" is a statement about a transaction.
     *
     * The key-change device is `DmWorld`'s `reincarnation`: the same `ghost1` seed under a
     * different MESSAGING branch, which is the only shape §8.3 says a key change can take. The
     * forger is an ordinary third node, which by construction holds neither.
     *
     * **All four of §15.3's SCN-D clauses are here**: "A holds and moves to `changed`, A's send
     * refused; acknowledge → HELD replays; a block variant; a forged variant". The middle two were
     * missing and §22.15's deferral list did not name them, which is worse than the gap itself —
     * a scenario that silently covers half of its row is a row nobody will re-read.
     *
     * **No liveness probe and no no-loss oracle here**, and both for the same reason: this scenario
     * ends with the contact **blocked**, so a send is refused by design and a message A queued for
     * the changed identity is held rather than delivered. Demanding liveness of a scenario whose
     * subject is refusal would be demanding the opposite of what it asserts.
     */
    fun scnD(): DmScenario = DmScenario(
        name = "SCN-D",
        setup = { world ->
            world.node("alice", 0x41)
            world.node("bob", 0x51)
            // The same `ghost1` identity seed (0x52) under a different MESSAGING branch: §8.3's
            // "the holder of that Ed25519 secret signed another Olm identity".
            world.node("bob2", 0x61, identityBranch = 0x52)
            world.node("mallory", 0x71)
            DmScripts.activate(world)
            DmScripts.establishBothWays(world, "alice", "bob")
        },
        steps = listOf(
            step("bob2 introduces itself under bob's identity") { w ->
                // A minute first, so bob2's message does not share an author minute with the last
                // message bob sent during the establishment. `minute_index` is per author *device*
                // and two devices of one identity write into one conversation after a key change,
                // so without this the two collide at `(sort_minute, minute_index)` — which the
                // harness's CS-2 proxy reads as "one position holds two messages" and §7.7 settles
                // with its `message_id` tie-break. See `DmCrashRunner.displayedAtMostOnce`.
                w.advanceBy(DmWorld.MINUTE)
                // bob2 has to know alice to write to her: it scans alice's card as any device
                // would, and its envelope then names alice's namespace with a binding valid under
                // the Ed25519 key alice already pinned for bob.
                w["bob2"].device.engine.addContact(w["alice"].device.card(), CardSource.QR_IN_PERSON)
                val toAlice = w["bob2"].device.engine.contacts().single().id
                w["bob2"].device.engine.send(toAlice, "it is still me", null)
                w.pump()
                w["bob2"].device.timeTriggeredPass()
                w.advanceBy(3 * DmWorld.MINUTE)
                w["bob2"].device.timeTriggeredPass()
            },
            step("alice receives the changed identity") { w -> w.pump(); w.passes() },
            step("mallory forges") { w ->
                w["mallory"].device.engine.addContact(w["alice"].device.card(), CardSource.QR_IN_PERSON)
                val toAlice = w["mallory"].device.engine.contacts().single().id
                w["mallory"].device.engine.send(toAlice, "forged", null)
                w.pump()
                w["mallory"].device.timeTriggeredPass()
                w.advanceBy(3 * DmWorld.MINUTE)
                w["mallory"].device.timeTriggeredPass()
            },
            step("alice receives the forgery") { w -> w.pump(); w.passes() },
            step("what holds before the acknowledgement") { w ->
                // Recorded rather than asserted, because a crash may have lost the key change
                // itself and a step is not a `finalCheck`. The assertions are below, fault-free.
                val alice = w["alice"].device
                val changed = alice.engine.contacts().filter { it.trust == TrustState.CHANGED }
                w.notes["changedCount"] = changed.size
                if (changed.size == 1) {
                    w.contacts["alice->changed"] = changed.single().id
                    w.notes["refused"] = alice.engine.send(changed.single().id, "should not go", null)
                    w.notes["heldBefore"] =
                        DmScripts.count(w, "alice", "SELECT count(*) FROM dm_held")
                    w.notes["shownBefore"] = alice.engine.conversation(changed.single().id, 50, null)
                        .any { it.text == "it is still me" }
                }
            },
            step("alice acknowledges the key change and HELD replays") { w ->
                // §8.3's other half, and §15.3's "acknowledge → HELD replays": the held row is not
                // a copy of the message, it is the message, and the acknowledgement is the only
                // thing that turns it into one. A crash between the two is what this step puts
                // under the enumeration.
                val id = w.contacts["alice->changed"] ?: return@step
                w.notes["acknowledged"] = w["alice"].device.engine.acknowledgeKeyChange(id)
                w.passes()
                w.pump()
                w.passes()
                w.notes["heldAfter"] = DmScripts.count(w, "alice", "SELECT count(*) FROM dm_held")
                w.notes["shownAfter"] = w["alice"].device.engine.conversation(id, 50, null)
                    .any { it.text == "it is still me" }
            },
            step("the block variant") { w ->
                // §15.3 names "a block variant" beside the acknowledge one, and §12.4 is what it
                // means: the contact is blocked, its sessions go, and a send is refused. The
                // structural invariant "no session row on a revoked or blocked contact" is what
                // says the rows really went, at every crash point of this step.
                val id = w.contacts["alice->changed"] ?: return@step
                w.notes["blocked"] = w["alice"].device.engine.block(id)
                w.passes()
                w.notes["afterBlock"] = w["alice"].device.engine.send(id, "nor this", null)
            },
        ),
        alwaysChecks = { world ->
            // E-1 in the shape a crash run can break: the forgery never becomes a key change of the
            // *existing* contact. Mallory may legitimately raise a **request** of her own — she is
            // an unknown card holder, and §12.3 says that is what happens — but bob's contact must
            // never carry Mallory's identity as a pending one.
            var pendingOnBob = 0L
            world["alice"].raw.query(
                "SELECT count(*) FROM dm_contact WHERE pending_identity IS NOT NULL " +
                    "AND trust_state <> 'changed'",
            ) { pendingOnBob = it.long(0) }
            if (pendingOnBob != 0L) {
                dmViolation("SCN-D: a pending identity on a contact that is not 'changed'")
            }
            // Held rows only ever belong to `changed` contacts — the structural invariant, checked
            // here again because this is the one scenario that creates them.
            DmStructuralInvariants.check(world["alice"], "SCN-D always")
        },
        finalChecks = { world ->
            val alice = world["alice"].device
            if (world.notes["changedCount"] != 1) {
                dmViolation(
                    "SCN-D: expected exactly one 'changed' contact, got " +
                        alice.engine.contacts().map { it.trust },
                )
            }
            // CS-5: no encrypt to a `changed` contact — the facade refuses before any ratchet call.
            if (world.notes["refused"] != SendResult.KEY_CHANGED) {
                dmViolation("SCN-D: a send to a 'changed' contact returned ${world.notes["refused"]}")
            }
            // And the held content is not displayed before the acknowledgement (§8.3).
            if (world.notes["heldBefore"] == 0L) dmViolation("SCN-D: the new-key message was not held")
            if (world.notes["shownBefore"] != false) {
                dmViolation("SCN-D: held content was displayed before KEYDEC (CS-5)")
            }
            // §15.3's "acknowledge → HELD replays": afterwards the hold is empty and the content is
            // there. A hold that stayed full would be a message the user can never see, and one
            // that emptied without the content appearing would be a message the acknowledgement ate.
            if (world.notes["acknowledged"] != true) {
                dmViolation("SCN-D: acknowledgeKeyChange refused the changed contact")
            }
            if (world.notes["heldAfter"] != 0L) {
                dmViolation("SCN-D: ${world.notes["heldAfter"]} rows still held after KEYDEC")
            }
            if (world.notes["shownAfter"] != true) {
                dmViolation("SCN-D: HELD did not replay after the acknowledgement")
            }
            // §15.3's "a block variant" (§12.4).
            if (world.notes["blocked"] != true) dmViolation("SCN-D: the contact could not be blocked")
            if (world.notes["afterBlock"] != SendResult.BLOCKED) {
                dmViolation("SCN-D: a send to a blocked contact returned ${world.notes["afterBlock"]}")
            }
        },
    )

    // ------------------------------------------------------------------ SCN-F ephemeral

    /**
     * **SCN-F — ephemeral.** A 5-minute timer, a displayed message, a sweep, and a wall clock
     * stepped back.
     *
     * The property is T25's: once a message's `delete_at_minute` has passed, the row is gone at the
     * next sweep and the plaintext is gone from the `-wal` with it — at **every** crash point,
     * because a crash between the delete and the checkpoint is exactly the window R-K1 exists to
     * close. [DmStructuralInvariants.afterSweep] is the assertion; a reboot runs R-K1 on the way
     * in, so a run that crashed between SWEEP and the checkpoint still has to end with a 0-byte
     * log.
     *
     * The clock step back is §10.7's and mutant ME-17's ("a wall-clock back step delays deletion"):
     * a deadline already reached is not un-reached by a clock that moves backwards.
     *
     * **No no-loss oracle and no liveness probe**, and both because the scenario's subject is
     * deletion. A message here is sent, delivered, displayed and then *gone by design*, so "a
     * message the sender called sent was rendered somewhere" is false at the end of a correct run;
     * and a liveness probe under a five-minute timer would be racing the same deadline. This is the
     * one scenario where a crash can leave a run with **more** rendered messages than the
     * fault-free run had — the crash delays the delivery past the deadline that deleted it — which
     * is why `DmCrashRunner`'s cross-run order comparison is over the positions two runs have in
     * common rather than a subsequence.
     */
    fun scnF(): DmScenario = DmScenario(
        name = "SCN-F",
        doubles = true,
        setup = { world ->
            world.node("alice", 0x41)
            world.node("bob", 0x51)
            DmScripts.activate(world)
            DmScripts.establishBothWays(world, "alice", "bob")
        },
        steps = listOf(
            step("five-minute timer") { w ->
                w["alice"].device.engine.setTimer(DmScripts.contact(w, "alice", "bob"), Timer.MIN_5)
                w.pump()
                w.passes()
            },
            step("an ephemeral message") { w ->
                w["alice"].device.engine.send(DmScripts.contact(w, "alice", "bob"), "vanishing", null)
                w.pump()
                w.passes()
            },
            step("bob displays it") { w ->
                val contact = w["bob"].device.engine.contacts().first().id
                val ids = w["bob"].device.engine.conversation(contact, 50, null).map { it.id }
                w["bob"].device.engine.markDisplayed(ids)
            },
            step("the clock steps back an hour") { w -> w.stepClockBack("bob", DmWorld.HOUR) },
            step("and then past the deadline") { w ->
                w.advanceBy(2 * DmWorld.HOUR)
                w.passes()
            },
        ),
        alwaysChecks = { world ->
            // T25 at every crash point: SWEEP leaves nothing past its deadline, and R-K1 at the
            // next open leaves nothing in the log — "after SWEEP and R-K1", in that order.
            for (node in world.nodes()) {
                node.device.timeTriggeredPass()
                DmStructuralInvariants.afterSweep(node, node.clock.now, "SCN-F always")
                DmStructuralInvariants.walEmptyAfterReboot(node, "SCN-F always")
                DmStructuralInvariants.check(node, "SCN-F after R-K1")
            }
        },
        finalChecks = { world ->
            val texts = DmScripts.inboundTexts(world, "bob")
            if (texts.contains("vanishing")) {
                dmViolation("SCN-F fault-free: the ephemeral message outlived its deadline")
            }
        },
    )

    // ------------------------------------------------------------------ SCN-G outcomes

    /**
     * **SCN-G — outcomes and resend.** An ambiguous store becomes INDETERMINATE and is resent with
     * **identical bytes**, at most twice (G-7, C-15); a relay that refuses everything makes the
     * item FAILED and the user retry re-encrypts.
     *
     * Mutant MC-3 is "INDETERMINATE resend re-encrypted instead of identical bytes", and what kills
     * it is that the recipient dedups at D1 (same blob hash) rather than at D3 (same message id
     * under new bytes): a re-encryption costs a ratchet step and a second hash. [rememberItemBlobs]
     * is that check, taken at every round and compared against the round before.
     *
     * No liveness probe: the scenario's last step leaves a relay that refuses **everything**, which
     * is what it is for, and a probe through it would be asking whether the relay is honest rather
     * than whether the session is alive.
     */
    fun scnG(): DmScenario = DmScenario(
        name = "SCN-G",
        noLoss = true,
        // The two outcomes this scenario exists to produce; any other message given up is not.
        expectedFailures = setOf("ambiguous", "refused"),
        setup = { world ->
            world.node("alice", 0x41)
            world.node("bob", 0x51)
            DmScripts.activate(world)
            DmScripts.establishBothWays(world, "alice", "bob")
        },
        steps = listOf(
            step("an ambiguous store") { w ->
                w.relay.outcomeFor = { "indeterminate" }
                w["alice"].device.engine.send(DmScripts.contact(w, "alice", "bob"), "ambiguous", null)
                rememberItemBlobs(w)
                w.pump()
                w.passes()
            },
            step("the first resend") { w -> w.pump(); w.passes(); rememberItemBlobs(w) },
            step("the second resend") { w -> w.pump(); w.passes(); rememberItemBlobs(w) },
            step("and one more round, past the bound") { w ->
                w.pump()
                w.passes()
                rememberItemBlobs(w)
            },
            step("a relay that refuses") { w ->
                w.relay.outcomeFor = { "failed" }
                w["alice"].device.engine.send(DmScripts.contact(w, "alice", "bob"), "refused", null)
                w.pump()
                w.passes()
            },
        ),
        alwaysChecks = { world ->
            // The bound of §7.5 and G-7: at most two resends, whatever the crash did.
            val over = DmScripts.count(
                world, "alice", "SELECT count(*) FROM dm_outbound_op WHERE resend_count > 2",
            )
            if (over != 0L) dmViolation("SCN-G: $over ops past the resend bound of 2")
        },
        finalChecks = { world ->
            val states = DmScripts.outboundStates(world, "alice")
            if (!states.contains("INDETERMINATE")) {
                dmViolation("SCN-G: the ambiguous store never became INDETERMINATE: $states")
            }
            if (!states.contains("FAILED")) {
                dmViolation("SCN-G: the refused store never became FAILED: $states")
            }
            // §21.8 point 1: a FAILED item keeps its L0 for the user retry; the others do not.
            val keptL0 = DmScripts.count(
                world, "alice",
                "SELECT count(*) FROM dm_outbound_item WHERE l0_env IS NOT NULL AND state = 'failed'",
            )
            if (keptL0 == 0L) dmViolation("SCN-G: a FAILED item dropped the L0 the retry needs")
        },
    )

    /**
     * The MC-3 oracle, which until now was written and never read: `w.notes["bytes"]` was assigned
     * once and nothing ever compared it, so "the check below is the hash, taken before and after
     * the resend" described a check that did not exist.
     *
     * What it does now: every time it runs it takes the retained bytes of each item op that still
     * carries them and **checks them against what the same item carried before**. §7.5's resend is
     * the retained bytes or it is not a resend — a re-encryption costs a ratchet step and moves the
     * recipient's dedup from D1's hash to D3's tag, which is exactly the defect MC-3 names — so an
     * item whose blob changed between two rounds has been re-encrypted, and that is a finding
     * whether or not the run was faulted. It is an `alwaysCheck` in effect, because it is asserted
     * inside the steps.
     */
    @Suppress("UNCHECKED_CAST")
    private fun rememberItemBlobs(world: DmCrashWorld) {
        val known = world.notes.getOrPut("bytes") { HashMap<String, String>() }
            as HashMap<String, String>
        world["alice"].raw.query(
            "SELECT hex(item_id), hex(blob) FROM dm_outbound_op " +
                "WHERE purpose = 'item' AND blob IS NOT NULL ORDER BY operation_id",
        ) { row ->
            val item = row.string(0)
            val blob = row.string(1)
            val before = known[item]
            if (before != null && before != blob) {
                dmViolation(
                    "SCN-G: item $item was re-encrypted between resends — §7.5 says the bytes are " +
                        "the retained ones (MC-3)",
                )
            }
            known[item] = blob
        }
    }

    // ------------------------------------------------------------------ SCN-G's week-boundary retry

    /**
     * **SCN-G's week-boundary FAILED retry** (§15.3's SCN-G row, §22.8.5 rule 1; slice S10b).
     *
     * > a default-timer FAILED retry across a week boundary …: no bundle fetch, no PreKey message,
     * > displayed once (§22.8.5)
     *
     * It is its own scenario rather than more steps of [scnG], so that SCN-G's line and its MC-16
     * kill stay what S10 measured; the report prints it as `SCN-G-week`.
     *
     * Every relay refuses alice's message, so it is FAILED; the ISO week turns and SWEEP runs; the
     * user retries. A retry keeps its author minute and R9 at the peer requires the pair key's week
     * to equal the author's week, so the retry is sealable in pair mode only if SWEEP **kept** the
     * out key of the author's week for the live retryable item — §22.8.5 rule 1, and the whole of
     * mutant MC-33. Without that key the retry has no pair key, the session has already sealed a
     * pair envelope so provisional mode is closed to it, and the item falls to `NO_SEAL_KEY`: a
     * re-establishment through a bundle fetch and a PreKey message, which is exactly the
     * relay-visible event §22.8.5 exists to avoid. The message is still displayed once — which is
     * why no-loss and liveness cannot see MC-33, and why the check that does is "alice's session is
     * the one she had before the week turned", asserted **in every run**: nothing a crash does to
     * this script can legitimately re-establish the session, since a retry lost to a crash leaves
     * the item FAILED and a retry that ran seals under the kept key or rolls back whole.
     *
     * The user retries again when a crash lost the retry (the message still shows FAILED), and
     * does it before the item's deadline. Both oracles are on. §15.3's second half of the same
     * clause — the retry after the peer's `prov_erase_minute` — is not here (§22.19).
     */
    fun scnGWeek(): DmScenario = DmScenario(
        name = "SCN-G-week",
        liveness = "alice" to "bob",
        noLoss = true,
        setup = { world ->
            world.node("alice", 0x41)
            world.node("bob", 0x51)
            DmScripts.activate(world)
            DmScripts.establishBothWays(world, "alice", "bob")
            world.notes["sessionBefore"] = currentSessionHex(world, "alice", "alice->bob")
                ?: error("alice has no session for bob")
        },
        steps = listOf(
            step("every relay refuses the store") { w ->
                w.relay.outcomeFor = { "failed" }
                w["alice"].device.engine.send(DmScripts.contact(w, "alice", "bob"), "g-week", null)
                round(w)
            },
            step("the ISO week turns and SWEEP runs") { w ->
                w.relay.outcomeFor = { "sent" }
                val now = w.nodes().maxOf { it.clock.now }
                val nextWeek = DmWorld.WEEK_ORIGIN +
                    (Math.floorDiv(now - DmWorld.WEEK_ORIGIN, DmWorld.WEEK) + 1) * DmWorld.WEEK
                // An hour into the new week: past the boundary, well inside the item's seven days.
                w.advanceBy(nextWeek - now + DmWorld.HOUR)
                round(w)
            },
            step("the user retries") { w -> retryTheFailedMessage(w) },
            step("settle") { w ->
                retryTheFailedMessage(w)
                round(w)
            },
        ),
        alwaysChecks = { world ->
            val now = currentSessionHex(world, "alice", "alice->bob")
            if (now != world.notes["sessionBefore"]) {
                dmViolation(
                    "SCN-G-week: a FAILED retry across a week boundary re-established the session " +
                        "(§22.8.5 rule 1: no bundle fetch, no PreKey message)",
                )
            }
            val shown = DmScripts.inboundTexts(world, "bob").count { it == "g-week" }
            if (shown > 1) dmViolation("SCN-G-week: bob displayed the retried message $shown times")
        },
        finalChecks = { world ->
            if (world.notes["retried"] != SendResult.QUEUED) {
                dmViolation("SCN-G-week fault-free: the retry returned ${world.notes["retried"]}")
            }
            val shown = DmScripts.inboundTexts(world, "bob").count { it == "g-week" }
            if (shown != 1) dmViolation("SCN-G-week fault-free: bob displayed the retry $shown times")
        },
    )

    /**
     * The user's retry of the FAILED message, done again while it still shows FAILED — a retry a
     * crash interrupted rolled back whole, so the message is FAILED again and the user sees it.
     *
     * **The check is here, right after the call returns, and not only at quiescence.** A retry
     * that found no pair key for its author week demotes `current` in its own transaction (R-SS0)
     * and asks for an establishment, so the moment the call returns the session is already not the
     * one it was — which is the whole of §22.8.5's "no bundle fetch, no PreKey message", decided
     * where it happens. Checked only at the end, the same defect surfaced first as a *different*
     * failure: the model relay never re-serves a bundle the recipient already consumed once (see
     * §22.19), so the re-establishment stalled with only a `previous` row and the structural clause
     * "exactly one `current` whenever any exists" fired instead — a kill for a reason that is the
     * harness's. Sound in every run: the call either committed its seal, and then nothing else
     * touched the session in between, or it rolled back whole and the step died with it.
     */
    private fun retryTheFailedMessage(w: DmCrashWorld) {
        val alice = w["alice"].device.engine
        val failed = alice.conversation(DmScripts.contact(w, "alice", "bob"), 20, null)
            .firstOrNull { it.text == "g-week" && it.state == org.ghost.messaging.api.MessageState.FAILED }
            ?: return
        w.notes["retried"] = alice.retry(failed.id)
        if (currentSessionHex(w, "alice", "alice->bob") != w.notes["sessionBefore"]) {
            dmViolation(
                "SCN-G-week: a FAILED retry across a week boundary re-established the session " +
                    "(§22.8.5 rule 1: no bundle fetch, no PreKey message)",
            )
        }
        round(w)
    }

    // ------------------------------------------------------------------ SCN-J faults

    /**
     * **SCN-J — faults.** `SQLITE_FULL` at every statement, and the native crash during RECV.
     *
     * The two halves are different in kind and the scenario keeps them apart. `SQLITE_FULL` is a
     * **typed** failure the engine must survive: the transaction rolls back, the pass reports it,
     * and the next pass does the work again. A `SimulatedNativeCrash` is a **death**: the blob that
     * caused it is re-offered alone, and at the fourth offer it is consumed as poison — a declared
     * loss, and the only thing that keeps one malformed blob from stopping an inbox for ever
     * (mutant MC-12, "offers ignored").
     *
     * The script here is the SEND/RECV traffic; [DmCrashRunner.enumerateStorageFull] is what walks
     * the statements, and `DmPoisonTest` is where the four offers are counted, because that count
     * is a property of one blob and not of an enumeration.
     */
    fun scnJ(): DmScenario = DmScenario(
        name = "SCN-J",
        // §15.3's own sentence about this scenario is "**single and double** SQL crashes never
        // reach the threshold", and the double half was simply not run: `doubles` was false.
        doubles = true,
        liveness = "alice" to "bob",
        noLoss = true,
        setup = { world ->
            world.node("alice", 0x41)
            world.node("bob", 0x51)
            DmScripts.activate(world)
            DmScripts.establishBothWays(world, "alice", "bob")
        },
        steps = listOf(
            step("send under a full disk") { w ->
                w["alice"].device.engine.send(DmScripts.contact(w, "alice", "bob"), "j1", null)
            },
            step("receive under a full disk") { w -> w.pump(); w.passes() },
            step("sweep under a full disk") { w ->
                w.advanceBy(DmWorld.HOUR)
                w.passes()
            },
        ),
        alwaysChecks = { world ->
            // The premise of the whole scenario: a full disk never leaves a half-applied RECV.
            // Everything else is the structural invariants, which the runner already checked.
            val orphaned = DmScripts.count(
                world, "bob",
                "SELECT count(*) FROM dm_message m WHERE m.direction = 'in' AND NOT EXISTS " +
                    "(SELECT 1 FROM dm_conversation c WHERE c.conversation_id = m.conversation_id)",
            )
            if (orphaned != 0L) dmViolation("SCN-J: $orphaned inbound messages with no conversation")
            // §15.3's other sentence about SCN-J: "single and double SQL crashes **never reach the
            // threshold**". The poison guard is for a blob that kills RECV, not for a transaction
            // that rolled back, and a guard that counted SQL failures as offers would throw away
            // every message a full disk interrupted. Nothing asserted it until now.
            for (node in world.nodes()) {
                val poisoned = node.device.engine.status().poisoned
                if (poisoned != 0) {
                    dmViolation(
                        "SCN-J: ${node.name} poisoned $poisoned blobs — a SQL crash reached the " +
                            "poison threshold",
                    )
                }
            }
        },
        finalChecks = { world ->
            if (!DmScripts.inboundTexts(world, "bob").contains("j1")) {
                dmViolation("SCN-J fault-free: j1 never arrived")
            }
        },
    )

    // ------------------------------------------------------------------ SCN-K revocation

    /**
     * **SCN-K — revocation** (§15.3, §8.5; slice S10b).
     *
     * > A notifies its revocation (scheduled); B drops the sessions, refuses sending, drops later
     * > blobs
     *
     * alice issues a revocation certificate v2 for her own identity and schedules the notice; it
     * goes out at its drawn minute inside U[0, 24 h] from a **time-triggered** pass, inside E2E, as
     * a CONTROL; bob's RECV verifies it under alice's **pinned** key and, in that one transaction,
     * moves the contact to the terminal `revoked`, deleting its sessions, pair keys, held rows and
     * scheduled controls and failing its pending sends. A crash anywhere in it must leave all of
     * that or none of it, and the structural invariant "no session row on a revoked contact" is
     * what reads the answer at every reboot.
     *
     * **The oracles.** **Liveness is off, and has to be:** after a revocation the pair cannot talk
     * by design, so "one more message each way decrypts" is the opposite of what §8.5 asserts. Its
     * place is taken by the liveness property of *this* scenario, checked in every run: **the
     * revocation took effect** — at quiescence bob's contact is `revoked`, nothing of it is left
     * (sessions, pair keys, held rows, scheduled controls, pending sends) and a send is refused. A
     * crash that left a notice that never goes out, or a half-applied revocation, fails there.
     * **No-loss is on**, with one declared loss (`declaredLoss`): alice's `k-after`, and only when
     * the run actually sent it **after** bob's contact was observed `revoked` — that is §8.5's
     * "drops later blobs", a message its sender calls `SENT` and its recipient refuses by design.
     * `k1`, sent before, must be rendered, and in a faulted run bob's own send, when the revocation
     * has not reached him yet, is an ordinary message and must be rendered too.
     *
     * **What proves the drop, and where** (S10b review). The declaration alone says only that the
     * send was *attempted* after the revocation reached bob, and "not rendered" alone would also
     * hold for a `k-after` that never reached him for any reason. So, fault-free: `k-after` is
     * `SENT` on alice, and bob consumed exactly one blob he could not open **after** the revocation
     * took effect and before anything else was sent to him — which is `k-after`. It is counted as
     * `unknown_seal`, not as the `blocked` a revoked contact's blob gets when it still names the
     * contact: the revocation deleted bob's in-direction pair keys for alice, so her pair-sealed
     * later blob names no key he holds and he cannot even tell whose it was — the strongest form of
     * "drops later blobs" there is, measured rather than assumed (the review expected `blocked`).
     * `drops["revoked"]` counts the revocation being applied, a different event. In every run the
     * runner's "nothing owed" oracle adds that no blob is left unconsumed and the relay owes bob
     * nothing, so a `SENT` `k-after` that was not rendered was consumed and refused.
     *
     * **Not here:** the FAILED revocation that is rescheduled (§21.8 point 7, "SCN-K gains a FAILED
     * revocation that is rescheduled"), which needs the reschedule §22.13 item 9 defers in the
     * engine; and a revocation that reaches a contact while it is re-establishing (bob is `ready`
     * when the notice lands here), which §22.19 records.
     *
     * **The revocation is done again when a crash interrupted it**: "I lost my phone" is a tap
     * whose call never returned when a crash lands inside it, and the user taps it again. The redo
     * is decided from what is visible — a scheduled notice or none — and only before any pass could
     * have sent the notice, which is what makes it exact (`ensureRevocationNotified`). The three
     * sends (`k1`, `k-refused`, `k-after`) are **not** redone: a crash loses them with their step,
     * which is S10's rule, and the checks above are written for either outcome.
     */
    fun scnK(): DmScenario = DmScenario(
        name = "SCN-K",
        noLoss = true,
        declaredLoss = { world ->
            if (world.notes["afterSent"] == true) setOf("k-after") else emptySet()
        },
        setup = { world ->
            world.node("alice", 0x41)
            world.node("bob", 0x51)
            DmScripts.activate(world)
            DmScripts.establishBothWays(world, "alice", "bob")
        },
        steps = listOf(
            step("traffic before the revocation") { w ->
                w["alice"].device.engine.send(DmScripts.contact(w, "alice", "bob"), "k1", null)
                w.pump()
                w.passes()
            },
            step("A issues its revocation and schedules the notice") { w -> ensureRevocationNotified(w) },
            step("the notice falls due") { w ->
                ensureRevocationNotified(w)
                // §8.5's spread is U[0, 24 h]; one control per time-triggered pass.
                w.advanceBy(25 * DmWorld.HOUR)
                w.passes()
                w.pump()
                w.passes()
            },
            step("B refuses to send") { w ->
                ensureRevocationNotified(w)
                // Only once the revocation has reached bob: before that his send is an ordinary
                // message, which a faulted run may legitimately produce and deliver.
                if (revokedOnBob(w)) {
                    w.notes["refused"] =
                        w["bob"].device.engine.send(DmScripts.contact(w, "bob", "alice"), "k-refused", null)
                }
            },
            step("later blobs are dropped") { w ->
                ensureRevocationNotified(w)
                if (revokedOnBob(w)) {
                    // The declaration comes **before** the call, and the gate-scale enumeration is
                    // what put it there: at crash@1073 the send committed and the process died at
                    // its post-commit event, so the call never returned, a note written after it
                    // was never written, and the relay then delivered a `SENT` message bob rightly
                    // dropped — charged to the engine. What the declaration states is "k-after, if
                    // it exists, was written after the revocation reached bob", which is decided
                    // here; a send a crash rolled back leaves nothing for it to excuse.
                    w.notes["afterSent"] = true
                    // bob's unopenable count before the one blob sent to him from here on.
                    w.notes["unopenableBefore"] =
                        w["bob"].device.engine.status().drops["unknown_seal"] ?: 0
                    w["alice"].device.engine.send(DmScripts.contact(w, "alice", "bob"), "k-after", null)
                }
                w.pump()
                w.passes()
            },
        ),
        alwaysChecks = { world ->
            // The liveness property of this scenario: the revocation took effect, whole.
            if (!revokedOnBob(world)) {
                dmViolation(
                    "SCN-K: the revocation never took effect — bob's contact is " +
                        trustOf(world, "bob", "bob->alice"),
                )
            }
            val contact = contactBytes(world, "bob->alice")
            for ((what, table) in REVOCATION_RESIDUE) {
                var left = 0L
                world["bob"].raw.query(
                    "SELECT count(*) FROM $table WHERE contact_id = ?",
                    listOf(contact),
                ) { left = it.long(0) }
                if (left != 0L) dmViolation("SCN-K: $left $what left on the revoked contact (§8.5)")
            }
            val refused = world["bob"].device.engine.send(DmScripts.contact(world, "bob", "alice"), "never", null)
            if (refused != SendResult.REVOKED) {
                dmViolation("SCN-K: a send to a revoked contact returned $refused")
            }
            if (world.notes["afterSent"] == true && "k-after" in DmScripts.inboundTexts(world, "bob")) {
                dmViolation("SCN-K: bob rendered a message alice sent after her revocation took effect")
            }
        },
        finalChecks = { world ->
            if (world.notes["notified"] != 1) {
                dmViolation("SCN-K fault-free: the notice was scheduled for ${world.notes["notified"]} contacts")
            }
            if (world.notes["refused"] != SendResult.REVOKED) {
                dmViolation("SCN-K fault-free: bob's send after the revocation returned ${world.notes["refused"]}")
            }
            if (world.notes["afterSent"] != true) {
                dmViolation("SCN-K fault-free: the later message was never sent, so its drop proved nothing")
            }
            // "Drops later blobs", proved rather than inferred: alice's copy went out and bob
            // received it and refused it as a revoked contact's.
            val afterState = DmScripts.outgoingState(world, "alice", "k-after")
            if (afterState != org.ghost.messaging.api.MessageState.SENT) {
                dmViolation("SCN-K fault-free: alice's later message is $afterState, not SENT")
            }
            val drops = world["bob"].device.engine.status().drops
            val refused = (drops["unknown_seal"] ?: 0) - (world.notes["unopenableBefore"] as Int)
            if (refused != 1) {
                dmViolation(
                    "SCN-K fault-free: bob consumed $refused unopenable blobs after the revocation, " +
                        "expected exactly alice's later message: $drops",
                )
            }
            val revoked = drops["revoked"]
            if (revoked != 1) dmViolation("SCN-K fault-free: bob counted $revoked revocations")
        },
    )

    /**
     * alice's "I lost my phone", done again when a crash interrupted it.
     *
     * Exact because of **when** it runs: every caller runs it before its own first pass, and only
     * a pass can send the notice and retire its row. So while `notified` is unset — the call never
     * returned — no pass has run since the call began, and "no scheduled row" means "the schedule
     * never committed" rather than "it committed and went out". A committed schedule whose return a
     * crash lost is recognised by its row, and the redo is skipped.
     */
    private fun ensureRevocationNotified(w: DmCrashWorld) {
        if (w.notes["notified"] != null) return
        val scheduled = DmScripts.count(
            w, "alice", "SELECT count(*) FROM dm_scheduled WHERE what = 'revocation'",
        )
        if (scheduled > 0L) {
            w.notes["notified"] = scheduled.toInt()
            return
        }
        val alice = w["alice"].device.engine
        val certificate = alice.issueRevocation(RevocationReason.DEVICE_LOST)
            ?: dmViolation("SCN-K: alice could not issue a revocation certificate")
        w.notes["notified"] = alice.notifyContactsOfRevocation(certificate)
    }

    private fun revokedOnBob(w: DmCrashWorld): Boolean = trustOf(w, "bob", "bob->alice") == "revoked"

    /** §8.5's "sessions, pair keys, held rows and pending sends", and the scheduled controls. */
    private val REVOCATION_RESIDUE = listOf(
        "session rows" to "olm_session",
        "pair keys" to "dm_pair_key",
        "held rows" to "dm_held",
        "scheduled controls" to "dm_scheduled",
        "pending sends" to "dm_pending_send",
    )

    // ------------------------------------------------------------------ SCN-L migration

    /**
     * **SCN-L — migration safety**, the DM-specific pass §15.3 asks for.
     *
     * `Migration5Test` and `SchemaAndMigrationTest` already prove that a v3 database with a live
     * outbox and inbox reaches v5 with its rows and triggers intact. What they do not do is run DM
     * traffic **afterwards** on the migrated file, which is the half SCN-L names ("then SCN-A
     * traffic") and the half that catches mutant MC-17, "the outbox rebuild loses a rowid or a
     * trigger": a lost trigger is invisible until something writes through it.
     *
     * So the setup here migrates a **file** from empty to v5 through the real runner, boots a node
     * on it, and then runs SCN-A's script. Reaching v5 from v3 specifically is `Migration5Test`'s;
     * what this adds is the traffic.
     */
    fun scnL(): DmScenario = DmScenario(
        name = "SCN-L",
        liveness = "alice" to "bob",
        noLoss = true,
        setup = { world ->
            world.node("alice", 0x41)
            world.node("bob", 0x51)
            // Every node booted through `DmNode.boot`, which is migrate + verifyIntegrity + R-K1.
            for (node in world.nodes()) {
                if (node.boots != 1) dmViolation("SCN-L: ${node.name} booted ${node.boots} times")
            }
            DmScripts.activate(world)
            DmScripts.establishBothWays(world, "alice", "bob")
        },
        steps = listOf(
            step("traffic on the migrated file") { w ->
                w["alice"].device.engine.send(DmScripts.contact(w, "alice", "bob"), "l1", null)
                w.pump()
                w.passes()
            },
            step("a reboot re-migrates and re-verifies") { w ->
                w["bob"].reboot()
                // §15.3 says "reboot … check the structural invariants", without an exception for
                // reboots a scenario performs itself. This one had none, so the one scripted reboot
                // in the suite was the only one in the harness that proved nothing.
                DmStructuralInvariants.check(w["bob"], "SCN-L scripted reboot")
                DmStructuralInvariants.checkpointEmptiedTheLog(w["bob"], "SCN-L scripted reboot")
                w["alice"].device.engine.send(DmScripts.contact(w, "alice", "bob"), "l2", null)
                w.pump()
                w.passes()
            },
        ),
        alwaysChecks = { world ->
            // Every trigger the schema expects is still there after the traffic and the reboot:
            // `verifyIntegrity` is what says so, and `DmStructuralInvariants.check` runs it.
            for (node in world.nodes()) DmStructuralInvariants.check(node, "SCN-L always")
        },
        finalChecks = { world ->
            val seen = DmScripts.inboundTexts(world, "bob").filter { it.startsWith("l") }
            if (seen != listOf("l1", "l2")) dmViolation("SCN-L fault-free: bob saw $seen")
        },
    )

    // ------------------------------------------------------------------ SCN-H bundle generations

    /**
     * **SCN-H — bundle generations** (§15.3, §5.4; slice S10b), in part.
     *
     * > weekly publication across 13 weeks; a PreKey message accepted at the 91-day generation
     * > boundary and refused after; a replayed first flight (D2b); a generation kept past its
     * > boundary while a held row references it
     *
     * **What is here.** Sixteen ISO weeks of world time in which bob's OWNER-WEEK publishes a new
     * generation **at every step** — each superseded by the next and erased at `superseded_day +
     * 91` (§5.4). That is not the clause's "weekly publication across 13 weeks", and is not claimed
     * as it: the steps are a week apart up to day 55 and **fourteen days apart after it** (days 69,
     * 83, 97, 111), a clock jump runs no pass, so bob publishes nothing in at least four of the
     * seventeen ISO weeks; nothing checks publication week by week (the fault-free run checks the
     * last week only); and the world never approaches the "at most 14 generations" bound of the
     * structural invariants. §22.19 defers the weekly clause by name. Inside the sixteen weeks, the one case in
     * which a generation's retention decides whether a message opens: a **late first flight**.
     * alice scans bob's card and writes; every relay refuses her (REFUSE_ONE_SENDER), so her
     * session exists and bob has never heard of it. Twenty-six days later she writes again on the
     * same unanswered session — inside `UNACK_MAX`, so it is still a PreKey message naming the
     * generation she fetched in the first week — and the relay holds it back for 28 days
     * (DELAY_RELEASE; the conversation's timer is off, so its TTL is 30). It reaches bob 40 to 47
     * days after that generation was superseded: inside the 91 days (7 + 28 + 45, rounded), fresh
     * (`FRESH(30 d)` is 43 days), and the only thing that can open it is the superseded
     * generation's secrets. bob gets a request carrying it, accepts, answers, and the pair is live.
     *
     * **The oracles.** No-loss (the late flight is `SENT` and must be rendered) and liveness (alice
     * ↔ bob once bob has accepted). And one of the scenario's own, in every run: **no generation
     * disappears before `superseded_day + 91`** — every step observes bob's generations on the raw
     * connection and a generation gone early is a finding at once, whatever the crash did. That is
     * mutant MC-28's direct oracle; the late flight is its consequence.
     *
     * **The user actions the case depends on are done again when a crash interrupted them**, each
     * judged from what the user can see: alice's timer change (the conversation's timer), the late
     * flight (her conversation; a redo past `UNACK_MAX` re-establishes on a newer generation, which
     * is still correct and only means that run no longer tests the late one — `finalChecks` pins
     * that the fault-free run does), bob's acceptance (his contact list) and his answer (his
     * conversation). `h1` is not redone: a crash loses it with its step, S10's rule.
     *
     * **What the relay's refusal leaves given up, declared:** `h1` and alice's timer change are
     * refused by every relay and end FAILED — the case's premise, and the only two outgoing rows
     * the runner's "nothing owed, nothing given up" oracle accepts in that state. A week jump over
     * a send a crash stranded would fail it at its deadline, and that oracle now sees it.
     *
     * **Not here, and §22.19 says why:** weekly publication across 13 weeks (above), "refused after" (a relay cannot hold a blob past its
     * 30-day TTL, and R9's freshness refuses such a message first — the boundary's far side needs a
     * RESURRECTing relay), the replayed first flight (D2b is MC-7′'s, killed in the CB replay), and
     * the generation kept alive by a held row (a key-change hold taken near the end of a
     * generation's window, which needs SCN-D's device inside this sixteen-week world).
     */
    fun scnH(): DmScenario = DmScenario(
        name = "SCN-H",
        liveness = "alice" to "bob",
        noLoss = true,
        expectedFailures = setOf("h1", DmScenario.TIMER_ROW),
        tailRounds = 12,
        setup = { world ->
            world.node("alice", 0x41)
            world.node("bob", 0x51)
            DmScripts.activate(world)
            val added = world["alice"].device.engine
                .addContact(world["bob"].device.card(), CardSource.QR_IN_PERSON)
            check(added == AddContactResult.ADDED) { "alice could not add bob's card: $added" }
            world.contacts["alice->bob"] = world["alice"].device.engine.contacts().single().id
            world.notes["t0"] = world.nodes().maxOf { it.clock.now }
            world.notes["g"] = currentGeneration(world, "bob") ?: error("bob has no generation")
            world.notes["generations"] = HashMap<Long, Long?>()
            observeGenerations(world)
        },
        steps = buildList {
            add(
                step("alice writes first and every relay refuses her") { w ->
                    w.relay.refusing = setOf("alice")
                    val toBob = DmScripts.contact(w, "alice", "bob")
                    w["alice"].device.engine.setTimer(toBob, Timer.OFF)
                    w["alice"].device.engine.send(toBob, "h1", null)
                    repeat(3) { round(w) }
                    untilSettled(w)
                },
            )
            for (day in listOf(7L, 14L, 21L)) add(generationStep("day $day", day))
            add(
                generationStep("alice writes again and the relay holds it for 28 days", 26) { w ->
                    w.relay.refusing = emptySet()
                    val now = w.nodes().maxOf { it.clock.now }
                    w.relay.releaseNotBefore = mapOf("alice" to now + HOLD_SECONDS)
                    sendTheLateFlight(w)
                },
            )
            for (day in listOf(33L, 40L, 47L)) add(generationStep("day $day", day))
            add(
                generationStep("the relay releases the late flight", 54) { w ->
                    // Six rounds, eighteen minutes: the late flight is chain index 2 of a session
                    // whose first two messages bob never saw, so §7.7 point 2's gap hold keeps it
                    // back for its first pass before RECV decides.
                    repeat(6) { round(w) }
                    recordTheLateDelivery(w)
                },
            )
            add(generationStep("bob accepts and answers", 55) { w -> acceptAndAnswer(w) })
            for (day in listOf(69L, 83L, 97L, 111L)) add(generationStep("day $day", day))
        },
        alwaysChecks = { world ->
            // The last observation, after the tail: a generation erased during quiescence is held
            // to the same rule as one erased in a step.
            observeGenerations(world)
        },
        finalChecks = { world ->
            if (world.notes["lateGen"] != world.notes["g"]) {
                dmViolation(
                    "SCN-H fault-free: alice's session named generation ${world.notes["lateGen"]}, " +
                        "not the first week's ${world.notes["g"]}, so the late flight tested nothing",
                )
            }
            val age = world.notes["lateAgeDays"] as Long?
            if (age == null || age < LATE_AGE_DAYS) {
                dmViolation(
                    "SCN-H fault-free: the late flight reached bob $age days after its generation " +
                        "was superseded, not the $LATE_AGE_DAYS or more the case is about",
                )
            }
            if ("h-late" !in DmScripts.everyInboundText(world["bob"])) {
                dmViolation(
                    "SCN-H: the late first flight did not open on a generation still inside its 91 days",
                )
            }
            val g = world.notes["g"] as Long
            val left =
                DmScripts.count(world, "bob", "SELECT count(*) FROM olm_prekey_gen WHERE gen_id = $g") +
                DmScripts.count(world, "bob", "SELECT count(*) FROM olm_prekey_used WHERE gen_id = $g")
            if (left != 0L) dmViolation("SCN-H fault-free: generation $g outlived its 91 days")
            if ((world.notes["erasures"] as Int? ?: 0) < 1) {
                dmViolation(
                    "SCN-H fault-free: no generation was erased in 16 weeks; the retention oracle saw nothing",
                )
            }
            var published = -1L
            world["bob"].raw.query("SELECT bundle_published_week FROM dm_self") {
                if (!it.isNull(0)) published = it.long(0)
            }
            val week = Math.floorDiv(world["bob"].clock.now - DmWorld.WEEK_ORIGIN, DmWorld.WEEK)
            if (published != week) {
                dmViolation("SCN-H fault-free: bob's last publication is of week $published in week $week")
            }
        },
    )

    /**
     * One step of SCN-H: the retention oracle and the user's redos first, then the world settled
     * **at the time it is**, then the clock to [day] days after the setup, then [body], a round,
     * and the world settled again.
     *
     * **Why it settles before it moves the clock.** A device runs time-triggered passes all the
     * time; this world runs them only where a step does, and then jumps a week. Work a crash left
     * owed — a pending send whose `EST-START` died with the process, an establishment inside
     * `EST-READY`'s two minutes — would otherwise wait out the jump and reach its R-T5 deadline
     * there, which models a device switched off for a week and not the crash the run injected. The
     * enumeration found both at crash@27 (the TIMER_SET's establishment never started, and the redo
     * of the late flight then failed at its deadline mid-establishment). Settling ([untilSettled])
     * is a bounded loop of [round]s that ends as soon as nothing is in flight ([settled]) and
     * costs no event at all when nothing is.
     */
    private fun generationStep(
        label: String,
        day: Long,
        body: (DmCrashWorld) -> Unit = {},
    ): DmScenario.Step = step(label) { w ->
        observeGenerations(w)
        // alice's timer change, if a crash lost it: the late flight's 30-day TTL depends on it, and
        // under the default seven days the relay would drop a held blob long before its release.
        ensureTimerOff(w)
        if (day > 26 && !theLateFlightWasWritten(w)) {
            // A crash lost alice's second message — it is not in her conversation, which is what
            // she sees — and she writes it again. Stop holding her blobs first: the hold is the
            // case's, a redo is not the case.
            w.relay.refusing = emptySet()
            w.relay.releaseNotBefore = emptyMap()
            sendTheLateFlight(w)
        }
        // bob accepts a request as soon as a step finds one — in the fault-free run that is the
        // step after the release; in a run whose redo sent the late flight unheld it can be weeks
        // earlier, and a request is deleted with its message after `REQUEST_DAYS` (§12.3). The
        // enumeration found that at crash@4889: the redo's request expired unanswered and the
        // no-loss oracle charged §12.3's own rule to the engine.
        acceptAndAnswer(w)
        untilSettled(w)
        // And again once the world has settled: a redo's late flight is delivered by the settling
        // itself, and a request left for after the jump would be past its seven days — the
        // replay of crash@3966 showed exactly that, a request created at day 26 and swept at 33.
        acceptAndAnswer(w)
        untilSettled(w)
        val target = (w.notes["t0"] as Long) + day * DmWorld.DAY
        val now = w.nodes().maxOf { it.clock.now }
        if (target > now) w.advanceBy(target - now)
        body(w)
        round(w)
        untilSettled(w)
    }

    /** Rounds until nothing is in flight ([settled]), at most [SETTLE_ROUNDS]. */
    private fun untilSettled(w: DmCrashWorld) {
        for (attempt in 0 until SETTLE_ROUNDS) {
            if (settled(w)) return
            round(w)
        }
    }

    /**
     * MC-28's direct oracle: every generation bob has held is either still there or went no
     * earlier than `superseded_day + 91` (§5.4). Read on the raw connection, so it is no event.
     */
    @Suppress("UNCHECKED_CAST")
    private fun observeGenerations(w: DmCrashWorld) {
        val known = w.notes["generations"] as HashMap<Long, Long?>
        val now = HashMap<Long, Long?>()
        w["bob"].raw.query("SELECT gen_id, superseded_day FROM olm_prekey_gen") {
            now[it.long(0)] = if (it.isNull(1)) null else it.long(1)
        }
        val today = Math.floorDiv(w["bob"].clock.now, DmWorld.DAY)
        for ((gen, superseded) in known) {
            if (gen in now) continue
            if (superseded == null || today < superseded + GENERATION_RETENTION_DAYS) {
                dmViolation(
                    "SCN-H: generation $gen was erased before superseded_day + 91 " +
                        "(superseded on day $superseded, gone by day $today)",
                )
            }
            w.notes["erasures"] = (w.notes["erasures"] as Int? ?: 0) + 1
        }
        known.clear()
        known.putAll(now)
    }

    private fun ensureTimerOff(w: DmCrashWorld) {
        var code = -1L
        w["alice"].raw.query(
            "SELECT timer_code FROM dm_conversation WHERE contact_id = ?",
            listOf(contactBytes(w, "alice->bob")),
        ) { code = it.long(0) }
        if (code == 0L) return
        w["alice"].device.engine.setTimer(DmScripts.contact(w, "alice", "bob"), Timer.OFF)
    }

    private fun sendTheLateFlight(w: DmCrashWorld) {
        val alice = w["alice"].device.engine
        val toBob = DmScripts.contact(w, "alice", "bob")
        var peerGen: Long? = null
        w["alice"].raw.query("SELECT peer_gen_id FROM olm_session WHERE slot = 'current'") {
            if (!it.isNull(0)) peerGen = it.long(0)
        }
        w.notes["lateGen"] = peerGen ?: -1L
        alice.send(toBob, "h-late", null)
    }

    /**
     * Whether alice's conversation shows the late flight — the user's own evidence, and not a note
     * written after the call returned: a send that committed and then died at its post-commit event
     * never returns, and a note-based redo would write the message a second time.
     */
    private fun theLateFlightWasWritten(w: DmCrashWorld): Boolean =
        w["alice"].device.engine.conversation(DmScripts.contact(w, "alice", "bob"), 50, null)
            .any { it.outgoing && it.text == "h-late" }

    private fun recordTheLateDelivery(w: DmCrashWorld) {
        val g = w.notes["g"] as Long
        var superseded: Long? = null
        w["bob"].raw.query("SELECT superseded_day FROM olm_prekey_gen WHERE gen_id = $g") {
            if (!it.isNull(0)) superseded = it.long(0)
        }
        val today = Math.floorDiv(w["bob"].clock.now, DmWorld.DAY)
        val day = superseded ?: return
        if ("h-late" in DmScripts.everyInboundText(w["bob"])) w.notes["lateAgeDays"] = today - day
    }

    /**
     * bob accepts alice's request once it is there, and answers; each done again if a crash lost
     * it, judged from what bob sees — alice in his contact list, his answer in the conversation —
     * and never from a note written after a call returned: `acceptRequest` or the send may commit
     * and then die at their post-commit event, and a redo decided from a note would then accept a
     * second time or answer twice.
     */
    private fun acceptAndAnswer(w: DmCrashWorld) {
        // Once the answer has been **seen** in bob's conversation it is never sent again, even if
        // a timer later deletes the row.
        if (w.notes["answered"] == true) return
        val bob = w["bob"].device.engine
        val request = bob.contacts().firstOrNull { it.trust == TrustState.REQUEST }
        val accepted = bob.contacts().firstOrNull {
            it.trust == TrustState.UNVERIFIED || it.trust == TrustState.VERIFIED
        }
        val contact = when {
            accepted != null -> accepted.id
            request != null && bob.acceptRequest(request.id) -> request.id
            else -> return
        }
        w.contacts["bob->alice"] = contact
        if (bob.conversation(contact, 50, null).any { it.outgoing && it.text == "h-ack" }) {
            w.notes["answered"] = true
            return
        }
        bob.send(contact, "h-ack", null)
    }

    private fun currentGeneration(w: DmCrashWorld, node: String): Long? {
        var out: Long? = null
        w[node].raw.query("SELECT gen_id FROM olm_prekey_gen WHERE superseded_day IS NULL") {
            out = it.long(0)
        }
        return out
    }

    /** §5.4: `delete_after_day = superseded_day + 91`. */
    private const val GENERATION_RETENTION_DAYS: Long = 91

    /**
     * DELAY_RELEASE's hold: 28 days, inside the 30-day TTL of a timer-off message with a day to
     * spare. The first version held 29 and released the blob at the very second its TTL ran out,
     * so the relay dropped it instead — the model relay's `storedAt + ttl <= now` is exact, as a
     * real relay's hour-rounded expiry is not.
     */
    private const val HOLD_SECONDS: Long = 28 * DmWorld.DAY

    /**
     * How long after its generation's supersession the late flight must arrive for the fault-free
     * run to count: five weeks, which is past any retention that forgot `FRESH` (7 + 28 = 35 days)
     * and inside the real one. The run reaches 40 to 47 days, depending on whether bob's weekly
     * pass fell before or after `t_pub` in the week after the setup.
     */
    private const val LATE_AGE_DAYS: Long = 35

    // ------------------------------------------------------------------ SCN-I restore

    /**
     * **SCN-I — restore** (§15.3, §8.6, §21.3; slice S10b).
     *
     * > B restores from seed: pre-restore pair, provisional and intro envelopes counted
     * > (`unknown_seal`, `unknown_generation`), no request created; B re-adds A's card and
     * > reconnects (a scheduled reset waiting for A's bundle, §21.8); A creates a new session under
     * > R-SS1 without a key-change warning and drops its out keys for B; later pair envelopes open
     * > in both directions (§21.3)
     *
     * **The world.** bob (B) scans alice's (A's) card and writes first, so the one-scan flow of
     * §21.3 point 1 puts all three envelope kinds on the relay for bob: alice's answer is a
     * **provisional** envelope (she is the responder and has not yet received bob's root), and her
     * timer change and `i-pre` are **pair** envelopes. The first version had alice write first,
     * which sends provisional envelopes only towards alice, so the restored device never received
     * one and §15.3's "provisional … counted" was checked by a sum that could not tell (S10b
     * review). It also makes alice's pre-restore `current` a **responder** session, which is the
     * case in which R-SS1's age guard (§22.8.4) is evaluated when the restored device's first
     * flight arrives. carol, a card holder bob never accepted, writes to him once, so bob holds a
     * request and the relay holds an **intro** envelope built on bob's lost generation. Then bob's phone is
     * lost — [DmCrashWorld.retire]: the node leaves the world, the relay keeps every blob it had
     * for bob — and `bob-restored` is built: the **same** MESSAGING branch and `ghost1` seed on a
     * fresh file, with its own random stream (see [DmNode]'s `streamOffset`). carol's part ends
     * with the setup and she is retired with bob. All of that is unfaulted setup; the armed phase is
     * the restore itself.
     *
     * **What is checked, and where.** In every run (`alwaysChecks`): the restored device renders
     * **nothing** authored before the restore (the lost device's pair, provisional and intro
     * envelopes all reach it through the relay and all stay unopenable), it holds **no request**
     * (carol's intro names a generation whose secrets were random and are gone), alice's contact is
     * never `changed` (the same Olm identity is a renewal, not a key change) and she holds nothing,
     * **alice renewed** (her `current` is no longer the pre-restore session) and **the world reached
     * the retire day** (the 47-day jump happened — without it `retiredSessionsGone` has nothing to
     * see, and MC-26 would pass that run). Fault-free (`finalChecks`): the counts §15.3 names, **per
     * kind** — `unknown_seal` exactly 3 on the restored device (alice's provisional answer and her
     * two pair envelopes) and `unknown_generation` exactly 1 (carol's intro, which therefore was
     * delivered) — `session_renewed` on alice, the reconnect's texts in both directions and —
     * §21.3's "later pair envelopes open in both directions" — `pair_sent` on **both** current
     * sessions beside the text that was sealed under it.
     *
     * **The oracles, all three on.** No-loss: every message a device calls `SENT` was rendered — by
     * a live device, or by the lost one before it was lost ([DmCrashWorld.retiredRendered]).
     * Liveness: one more message each way between the restored device and alice, **at the same
     * time**, as in every scenario — a probe alice seals before she has renewed would be sealed
     * under the lost device's keys and fail, which is the point: the every-run renewal check above
     * says the same thing in its own words. The S10b version let the restored device speak first,
     * and the review measured it as a loosening no run needed: that probe is a user send, which
     * re-establishes, so it repaired a stalled restore instead of failing it. Nothing owed: the
     * runner's third oracle, and the one the review's stranded-reconnect mutant could not pass.
     * alice's two answers are sent **only once alice has renewed**: a message she sealed before
     * learning of the restore is sealed under the lost device's keys, which is §8.6's declared
     * residue and not the engine's loss. The conversation's timer is off (set in the setup, carried
     * to the restored device by R-T9), so the 47 days do not sweep the messages the oracle reads,
     * and the jump waits for a settled world ([jumpToTheRetireDayOnceSettled]) — letting time run
     * to whatever is next due, as a device's clock would, so that a crash which cost a step its
     * clock advance cannot leave the reconnect scheduled past the jump.
     *
     * **The restore's three user actions are done again when a crash interrupted them.** The
     * restore, the re-added card and the reconnect are each a user action whose call never
     * returned when a crash lands inside it, and the user of a phone that died mid-tap does it
     * again: every later step first re-does whichever of them is visibly missing
     * (`ensureRestoreFlow`). Without that, a crash inside the one `addContact` of the run would
     * leave nothing for the liveness oracle to probe. What is checked is that the redo works on
     * whatever the crash left, which is an atomicity property of those three calls. The sends
     * (`i-welcome`, `i-back`, `i-pair`) are **not** redone: a crash loses them with their step,
     * S10's rule.
     *
     * **MC-18 and MC-26.** The renewal's deletion of alice's out keys (§21.3 point 2) is what lets
     * bob's new root in and what keeps alice from sealing her answer under the lost device's root;
     * without it the answer never opens (MC-18). The renewal demotes alice's pre-restore session to
     * `previous`, and the last step takes the world past its `retire_day`, where SWEEP must delete
     * it (MC-26, checked by [DmStructuralInvariants.retiredSessionsGone] at the end of every run).
     *
     * **Not here, and §22.19 names each:** the variant in which A resets from its side after B
     * published a new bundle, and the three §22.8.4 variants in which B's pre-restore first flight,
     * PreKey re-sends or normal replies reach A after B's reconnect intro (MC-32's subject, which
     * §22.15 item 8 records as needing a step seam).
     */
    fun scnI(): DmScenario = DmScenario(
        name = "SCN-I",
        doubles = true,
        liveness = RESTORED to "alice",
        noLoss = true,
        setup = { world ->
            world.node("alice", 0x41)
            world.node("bob", 0x51)
            world.node("carol", 0x61)
            DmScripts.activate(world)
            // bob writes first: alice's answer is then a provisional envelope **to bob** (see the
            // KDoc), and alice's `current` a responder session.
            DmScripts.establishBothWays(world, "bob", "alice")
            // The timer off, so the conversation outlives the last step's 47 days: under the
            // default seven-day timer every message of the scenario — sender's copy and
            // recipient's — is swept long before the run ends, and the no-loss oracle would then
            // be checking an empty conversation. R-T9 carries the new version to the restored
            // device with alice's first answer, so its own later messages are timer-off too.
            world["alice"].device.engine.setTimer(DmScripts.contact(world, "alice", "bob"), Timer.OFF)
            settle(world)
            // A pair envelope before the restore: the lost device reads it, the restored one must
            // not be able to.
            world["alice"].device.engine.send(DmScripts.contact(world, "alice", "bob"), "i-pre", null)
            settle(world)
            check("i-pre" in DmScripts.inboundTexts(world, "bob")) {
                "the pre-restore pair message never arrived"
            }
            // An intro envelope on the lost device's generation: carol scans bob's card and writes.
            world["carol"].device.engine.addContact(world["bob"].device.card(), CardSource.QR_IN_PERSON)
            val toBob = world["carol"].device.engine.contacts().single().id
            world["carol"].device.engine.send(toBob, "i-carol", null)
            settle(world)
            check(world["bob"].device.engine.contacts().any { it.trust == TrustState.REQUEST }) {
                "carol's intro never reached the device that is about to be lost"
            }
            // What the renewal has to replace, recorded before anything is lost.
            world.notes["aliceSessionBefore"] = currentSessionHex(world, "alice", "alice->bob")
                ?: error("alice has no session for bob before the restore")
            world.notes["trustBefore"] = trustOf(world, "alice", "alice->bob") ?: "none"
            // How the restored device's re-added card is found again after a crash lost the id.
            world.notes["aliceIdentity"] = identityOf(world, "bob", "bob->alice")
            // alice's contact for bob is the contact for the restored device too: the identity is
            // the same, and a restore is exactly the event that must not make it a new one.
            world.contacts["alice->$RESTORED"] = DmScripts.contact(world, "alice", "bob")
            world.retire("bob")
            world.retire("carol")
            // The same MESSAGING branch and `ghost1` seed on a new file: a restore from the seed.
            world.node(RESTORED, 0x51, identityBranch = 0x52, streamOffset = RESTORED_STREAM)
        },
        steps = listOf(
            step("B restores from seed") { w ->
                w[RESTORED].device.engine.onRestored()
                w.notes["restored"] = true
                // The relay serves the restored inbox everything it holds for the lost one.
                w.pump()
                w.passes()
            },
            step("B re-adds A's card") { w -> ensureRestoreFlow(w, reconnect = false) },
            step("B reconnects") { w -> ensureRestoreFlow(w, reconnect = true) },
            step("the notice falls due and waits for A's bundle") { w ->
                ensureRestoreFlow(w, reconnect = true)
                // §8.6's spread is U[0, 48 h]; the control then finds no session, starts the
                // establishment and waits for alice's bundle (§21.8) and EST-READY's two minutes.
                w.advanceBy(49 * DmWorld.HOUR)
                w.passes()
                w.pump()
                w.passes()
                w.advanceBy(3 * DmWorld.MINUTE)
                w.passes()
                w.pump()
                w.passes()
            },
            // Every later step moves the clock a few minutes per round, as time does: a crash that
            // cost the step above its rounds must not leave EST-READY's two minutes unelapsed until
            // the 47-day jump fails the waiting control at its deadline. The first version of this
            // scenario did exactly that at crash@626, and the run then measured the harness.
            step("A renews and answers on the new session") { w ->
                ensureRestoreFlow(w, reconnect = true)
                round(w)
                round(w)
                sendOnceRenewed(w, "i-welcome")
                round(w)
            },
            step("B answers, carrying its new root") { w ->
                ensureRestoreFlow(w, reconnect = true)
                w[RESTORED].device.engine.send(DmScripts.contact(w, RESTORED, "alice"), "i-back", null)
                round(w)
                round(w)
            },
            step("A writes in pair mode") { w ->
                ensureRestoreFlow(w, reconnect = true)
                round(w)
                sendOnceRenewed(w, "i-pair")
                round(w)
            },
            step("the world settles and the demoted session reaches its retire day") { w ->
                ensureRestoreFlow(w, reconnect = true)
                jumpToTheRetireDayOnceSettled(w)
            },
            step("the jump a crash cost the step above, if it did") { w ->
                ensureRestoreFlow(w, reconnect = true)
                jumpToTheRetireDayOnceSettled(w)
            },
        ),
        alwaysChecks = { world ->
            // The two things every single run needs for its other checks to mean anything, in
            // every run (S10b review): the retire day was reached — the only way MC-26 can be seen
            // — and alice renewed, without which the restore stalled and nothing after it tested
            // the renewal. The first was a `finalCheck`, so a stalled restore in a faulted run
            // skipped the jump and the retire-day clause silently had nothing to look at.
            if (world.notes["jumped"] != true) {
                dmViolation("SCN-I: the world never settled, so the retire day was never reached")
            }
            if (currentSessionHex(world, "alice", "alice->bob") == world.notes["aliceSessionBefore"]) {
                dmViolation("SCN-I: alice never renewed — her current session is the pre-restore one")
            }
            val restored = DmScripts.everyInboundText(world[RESTORED])
            val stale = restored.filter { it in PRE_RESTORE_TEXTS }
            if (stale.isNotEmpty()) {
                dmViolation("SCN-I: the restored device rendered pre-restore content $stale (§8.6)")
            }
            if (world[RESTORED].device.engine.contacts().any { it.trust == TrustState.REQUEST }) {
                dmViolation("SCN-I: a pre-restore intro envelope created a request on the restored device")
            }
            if (trustOf(world, "alice", "alice->bob") == "changed") {
                dmViolation("SCN-I: a restore under the same Olm identity became a key change on alice")
            }
            val held = DmScripts.count(world, "alice", "SELECT count(*) FROM dm_held")
            if (held != 0L) dmViolation("SCN-I: alice holds $held rows after a same-identity restore")
        },
        finalChecks = { world ->
            val renewed = world["alice"].device.engine.status().drops["session_renewed"]
            if (renewed != 1) dmViolation("SCN-I fault-free: alice counted $renewed session renewals")
            if (trustOf(world, "alice", "alice->bob") != world.notes["trustBefore"]) {
                dmViolation(
                    "SCN-I fault-free: alice's contact moved from ${world.notes["trustBefore"]} to " +
                        trustOf(world, "alice", "alice->bob"),
                )
            }
            val onRestored = DmScripts.inboundTexts(world, RESTORED).filter { it.startsWith("i-") }
            if (onRestored != listOf("i-welcome", "i-pair")) {
                dmViolation(
                    "SCN-I: pair envelopes from alice did not open on the restored device — it " +
                        "rendered $onRestored, expected [i-welcome, i-pair] (§21.3 point 2)",
                )
            }
            if ("i-back" !in DmScripts.inboundTexts(world, "alice")) {
                dmViolation("SCN-I fault-free: alice never rendered the restored device's answer")
            }
            // §21.3's "later pair envelopes open in both directions": a pair envelope was sealed on
            // each side's current session, and the text sealed under it was rendered above.
            for ((node, key) in listOf("alice" to "alice->bob", RESTORED to "$RESTORED->alice")) {
                if (!pairSentOnCurrent(world, node, key)) {
                    dmViolation("SCN-I fault-free: $node never sealed a pair envelope after the reconnect")
                }
            }
            // §15.3's "pre-restore pair, provisional and intro envelopes counted", kind by kind.
            // The seal of a pair or a provisional envelope names a key the restored device never
            // had (`unknown_seal`): alice's provisional answer and her two pair envelopes, the
            // timer change and `i-pre`. The intro names a generation whose secrets were random and
            // are gone (`unknown_generation`): carol's, the only one. A sum of the two, which this
            // was, passed with any one of them delivered — and with carol's intro never delivered.
            // Exact, so it also says that nothing sent **after** the restore was unopenable; last,
            // because the checks above name that failure more precisely when it happens.
            val drops = world[RESTORED].device.engine.status().drops
            if (drops["unknown_seal"] != PRE_RESTORE_SEALED ||
                drops["unknown_generation"] != PRE_RESTORE_INTROS
            ) {
                dmViolation(
                    "SCN-I fault-free: the restored device counted $drops, expected " +
                        "unknown_seal=$PRE_RESTORE_SEALED (one provisional and two pair envelopes) " +
                        "and unknown_generation=$PRE_RESTORE_INTROS (carol's intro)",
                )
            }
        },
    )

    /**
     * The three user actions of a restore, each done again when a crash interrupted it: the restore
     * itself, the re-added card, and (from the reconnect step on) the reconnect.
     *
     * Each is judged from what the **user** can see — the app is restored or it is not, bob is in
     * the contact list or he is not, a reconnect is scheduled or a session exists or neither — never
     * from a note a crash could have prevented, except where the note is the only record of a call
     * that returned. `ALREADY_KNOWN` from a re-added card is a crash that lost only the moment the
     * id was recorded, and the id is then looked up by the identity the card carries.
     */
    private fun ensureRestoreFlow(w: DmCrashWorld, reconnect: Boolean) {
        val device = w[RESTORED].device
        // "Restored" is the `dm_self` row, not the card: the card is a pure function of the seed
        // and `myCard()` answers it before ACTIVATE has run, which is exactly the state a crash
        // inside `onRestored` leaves.
        if (DmScripts.count(w, RESTORED, "SELECT count(*) FROM dm_self") == 0L) {
            device.engine.onRestored()
        }
        if (w.contacts["$RESTORED->alice"] == null) {
            when (val added = device.engine.addContact(w["alice"].device.card(), CardSource.QR_IN_PERSON)) {
                AddContactResult.ADDED, AddContactResult.ALREADY_KNOWN -> {
                    w.contacts["$RESTORED->alice"] =
                        contactByIdentity(w, RESTORED, w.notes["aliceIdentity"] as String)
                }
                else -> dmViolation("SCN-I: the restored device could not re-add alice's card: $added")
            }
        }
        if (!reconnect || w.notes["reconnected"] != null) return
        val contact = DmScripts.contact(w, RESTORED, "alice")
        val scheduled = DmScripts.count(w, RESTORED, "SELECT count(*) FROM dm_scheduled")
        val sessions = DmScripts.count(w, RESTORED, "SELECT count(*) FROM olm_session")
        if (scheduled == 0L && sessions == 0L) {
            w.notes["reconnected"] = device.engine.reconnect(listOf(contact))
        } else {
            w.notes["reconnected"] = scheduled.toInt()
        }
    }

    /** alice sends [text] to the restored device, but only once she has renewed (see [scnI]). */
    private fun sendOnceRenewed(w: DmCrashWorld, text: String) {
        val now = currentSessionHex(w, "alice", "alice->bob")
        if (now == null || now == w.notes["aliceSessionBefore"]) return
        w["alice"].device.engine.send(DmScripts.contact(w, "alice", "bob"), text, null)
    }

    /**
     * §8.7: 47 days, once — past the `retire_day` of the session the renewal demoted — but only
     * over a **settled** world.
     *
     * Settled means nothing is in flight: no store an outbox still holds for the relay, no live
     * blob the relay still owes a listener, no blob an inbox has not consumed, no pending send and
     * no scheduled control. A jump over anything in flight would model both devices offline for
     * the 47 days, and the model relay would then do two things the scenario is not about: drop
     * the owed blob at its TTL (RS2's declared loss, charged by the no-loss oracle to the engine)
     * and store a held op past its `deadline_hour`, which the Phase 7 engine it stands in for
     * refuses (R-T4). The first enumeration found the first of them at crash@3264+3: `i-back`
     * released `sent` a moment before the second death, then expired at the relay across the jump.
     *
     * **Settling lets time run to the next thing due** (S10b review), up to [RECONNECT_SPREAD]: a
     * device's clock moves whether or not a step advances it, and the scheduled reconnect is drawn
     * inside U[0, 48 h]. The first version only ran three-minute rounds, so a run whose crash cost
     * the reconnect step its 49-hour advance — the redo then drew a new minute up to two days out —
     * never settled, never jumped, and passed without its retire-day check having anything to see.
     *
     * A crash inside the settling rounds loses the jump with the rest of its step, and the next
     * step — which runs this again — is what makes the jump happen; the note is written the moment
     * the clock moves, so a crash in the passes after the jump does not make the next step jump
     * twice. A world that still does not settle is not jumped, and `alwaysChecks` refuses it.
     */
    private fun jumpToTheRetireDayOnceSettled(w: DmCrashWorld) {
        if (w.notes["jumped"] == true) return
        for (attempt in 0 until RESTORE_SETTLE_ROUNDS) {
            if (settled(w)) break
            val now = w.nodes().maxOf { it.clock.now }
            val due = w.nodes().mapNotNull { DmStructuralInvariants.nextDueMinute(it, now) }.minOrNull()
            if (due != null && due - now <= RECONNECT_SPREAD) w.advanceBy(due - now + DmWorld.MINUTE)
            round(w)
        }
        if (!settled(w)) return
        w.advanceBy(RETIRE_JUMP_SECONDS)
        w.notes["jumped"] = true
        w.passes()
        w.pump()
        w.passes()
    }

    /** Nothing in flight anywhere in the world; read on the raw connections, so no event. */
    private fun settled(w: DmCrashWorld): Boolean {
        val now = w.nodes().maxOf { it.clock.now }
        if (w.relay.owed(w.nodes(), now) != 0) return false
        return w.nodes().all { node ->
            listOf(
                "SELECT count(*) FROM outbox_op WHERE outcome = 'pending' AND ciphertext IS NOT NULL",
                "SELECT count(*) FROM inbox_blob WHERE state <> 'done'",
                "SELECT count(*) FROM dm_pending_send",
                "SELECT count(*) FROM dm_scheduled",
            ).all { query -> DmScripts.count(w, node.name, query) == 0L }
        }
    }

    /** At most this many rounds are spent settling before a week jump (SCN-H). */
    private const val SETTLE_ROUNDS: Int = 8

    /** SCN-I's settling before the retire-day jump: a clock move, an establishment and a delivery. */
    private const val RESTORE_SETTLE_ROUNDS: Int = 12

    /** §8.6's reconnect spread, U[0, 48 h], and an hour: the furthest SCN-I's settling moves time. */
    private const val RECONNECT_SPREAD: Long = 49 * DmWorld.HOUR

    /** §8.7's `RETIRE_DAYS` (46) and one more. */
    private const val RETIRE_JUMP_SECONDS: Long = 47 * DmWorld.DAY

    /** One relay round, a pass, three minutes, a pass: EST-READY's wait fits inside one. */
    private fun round(w: DmCrashWorld) {
        w.pump()
        w.passes()
        w.advanceBy(3 * DmWorld.MINUTE)
        w.passes()
    }

    /** One round and the second one EST-READY and a hint pass need, unfaulted (setup only). */
    private fun settle(world: DmCrashWorld) {
        repeat(3) {
            world.pump()
            world.passes()
            world.advanceBy(3 * DmWorld.MINUTE)
        }
        world.pump()
        world.passes()
    }

    private fun contactBytes(w: DmCrashWorld, key: String): ByteArray =
        requireNotNull(w.contacts[key]) { "no contact $key" }.toByteArray()

    private fun currentSessionHex(w: DmCrashWorld, node: String, key: String): String? {
        var out: String? = null
        w[node].raw.query(
            "SELECT hex(session_id) FROM olm_session WHERE contact_id = ? AND slot = 'current'",
            listOf(contactBytes(w, key)),
        ) { out = it.string(0) }
        return out
    }

    private fun pairSentOnCurrent(w: DmCrashWorld, node: String, key: String): Boolean {
        var sent = false
        w[node].raw.query(
            "SELECT pair_sent FROM olm_session WHERE contact_id = ? AND slot = 'current'",
            listOf(contactBytes(w, key)),
        ) { sent = it.long(0) == 1L }
        return sent
    }

    private fun trustOf(w: DmCrashWorld, node: String, key: String): String? {
        var out: String? = null
        w[node].raw.query(
            "SELECT trust_state FROM dm_contact WHERE contact_id = ?",
            listOf(contactBytes(w, key)),
        ) { out = it.string(0) }
        return out
    }

    private fun identityOf(w: DmCrashWorld, node: String, key: String): String {
        var out: String? = null
        w[node].raw.query(
            "SELECT hex(identity_pk) FROM dm_contact WHERE contact_id = ?",
            listOf(contactBytes(w, key)),
        ) { out = it.string(0) }
        return requireNotNull(out) { "$node has no contact $key" }
    }

    private fun contactByIdentity(w: DmCrashWorld, node: String, identityHex: String): ContactId {
        var id: ByteArray? = null
        w[node].raw.query(
            "SELECT contact_id FROM dm_contact WHERE hex(identity_pk) = ?",
            listOf(identityHex),
        ) { id = it.blob(0) }
        return ContactId(requireNotNull(id) { "$node has no contact with identity $identityHex" })
    }

    private const val RESTORED: String = "bob-restored"

    /** The restored node's random stream (see [DmNode]'s `streamOffset`). */
    private const val RESTORED_STREAM: Int = 1_000

    /** Every text authored before the restore, none of which the restored device may render. */
    private val PRE_RESTORE_TEXTS = setOf("hello", "hi back", "pair now", "i-pre", "i-carol")

    /** alice's pre-restore envelopes to bob: "hi back" (provisional), the timer change and `i-pre`. */
    private const val PRE_RESTORE_SEALED: Int = 3

    /** carol's intro to bob, the one intro envelope the restored device is served. */
    private const val PRE_RESTORE_INTROS: Int = 1

    /** Every scenario this slice implements, in the order the report prints them. */
    fun all(): List<DmScenario> =
        listOf(scnA(), scnB(), scnC(), scnD(), scnF(), scnG(), scnGWeek(), scnH(), scnI(), scnJ(), scnK(), scnL())
}
