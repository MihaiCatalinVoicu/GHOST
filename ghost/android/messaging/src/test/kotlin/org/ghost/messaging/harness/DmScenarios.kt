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
 * The named crash scenarios of Phase 9 design §15.3, as far as slices S10 and S10b implement them.
 *
 * Implemented here: **SCN-A** (send), **SCN-B** (receive and reorder), **SCN-D** (key change,
 * including the forged-binding case), **SCN-F** (ephemeral), **SCN-G** (outcomes and resend),
 * **SCN-J** (faults) and **SCN-L** (migration safety), from S10; **SCN-H** (bundle generations,
 * in part), **SCN-I** (restore), **SCN-K** (revocation) and SCN-G's week-boundary retry as
 * `SCN-G-week`, from S10b. SCN-C and SCN-E are not here; §22.15 of the design records what each
 * one still owes and §22.19 what S10b left of the rest.
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
     * **User actions a crash interrupted are done again**, as in SCN-I: "I lost my phone" is a tap
     * whose call never returned when a crash lands inside it, and the user taps it again. The redo
     * is decided from what is visible — a scheduled notice or none — and only before any pass could
     * have sent the notice, which is what makes it exact (`ensureRevocationNotified`).
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
            val revoked = world["bob"].device.engine.status().drops["revoked"]
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
     * **What is here.** Sixteen ISO weeks of bob's OWNER-WEEK — a new generation at every weekly
     * publication the world's passes reach, each superseded by the next and erased at
     * `superseded_day + 91` (§5.4), never more than fourteen alive. Inside them, the one case in
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
     * **User actions a crash interrupted are done again**: the second message, if a crash lost it
     * (a redo past `UNACK_MAX` re-establishes on a newer generation, which is still correct and
     * only means that run no longer tests the late one — `finalChecks` pins that the fault-free run
     * does), and bob's acceptance.
     *
     * **Not here, and §22.19 says why:** "refused after" (a relay cannot hold a blob past its
     * 30-day TTL, and R9's freshness refuses such a message first — the boundary's far side needs a
     * RESURRECTing relay), the replayed first flight (D2b is MC-7′'s, killed in the CB replay), and
     * the generation kept alive by a held row (a key-change hold taken near the end of a
     * generation's window, which needs SCN-D's device inside this sixteen-week world).
     */
    fun scnH(): DmScenario = DmScenario(
        name = "SCN-H",
        liveness = "alice" to "bob",
        noLoss = true,
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

    /** bob accepts alice's request once it is there, and answers; done again if a crash lost it. */
    private fun acceptAndAnswer(w: DmCrashWorld) {
        if (w.contacts["bob->alice"] != null) return
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
     * **The world.** alice (A) and bob (B) are established both ways and exchange a pair-sealed
     * message; carol, a card holder bob never accepted, writes to him once, so bob holds a request
     * and the relay holds an **intro** envelope built on bob's lost generation. Then bob's phone is
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
     * never `changed` (the same Olm identity is a renewal, not a key change) and she holds nothing.
     * Fault-free (`finalChecks`): the counts §15.3 names (`unknown_seal` + `unknown_generation` on
     * the restored device, `session_renewed` on alice), the reconnect's texts in both directions
     * and — §21.3's "later pair envelopes open in both directions" — `pair_sent` on **both**
     * current sessions beside the text that was sealed under it.
     *
     * **The oracles, both on.** No-loss: every message a device calls `SENT` was rendered — by a
     * live device, or by the lost one before it was lost ([DmCrashWorld.retiredRendered]). Liveness:
     * one more message each way between the restored device and alice, **in turn** — the restored
     * device first (`livenessInTurn`, whose KDoc says why that is §15.3's sentence and not a
     * loosening of it). alice's two answers are sent **only once alice has renewed** (her current
     * session is no longer the pre-restore one), for the same reason: a message she sealed before
     * learning of the restore is sealed under the lost device's keys, which is §8.6's declared
     * residue and not the engine's loss, and a scenario that sent it anyway would make the no-loss
     * oracle charge a declared loss to the engine. The conversation's timer is off (set in the
     * setup, carried to the restored device by R-T9), so the 47 days do not sweep the messages the
     * oracle reads, and the jump waits for a settled world ([jumpToTheRetireDayOnceSettled]).
     *
     * **User actions a crash interrupted are done again.** The restore, the re-added card and the
     * reconnect are each a user action whose call never returned when a crash lands inside it, and
     * the user of a phone that died mid-tap does it again: every later step first re-does whichever
     * of them is visibly missing (`ensureRestoreFlow`). Without that, a crash inside the one
     * `addContact` of the run would leave nothing for the liveness oracle to probe — which used to
     * pass silently (`sessionIsStillLive` returned on a missing id) and now fails. What is checked is
     * that the redo works on whatever the crash left, which is an atomicity property of those three
     * calls: a half-committed restore, card or schedule that refused the redo would fail here.
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
        // The restored device speaks first: see `DmScenario.livenessInTurn`.
        livenessInTurn = true,
        noLoss = true,
        setup = { world ->
            world.node("alice", 0x41)
            world.node("bob", 0x51)
            world.node("carol", 0x61)
            DmScripts.activate(world)
            DmScripts.establishBothWays(world, "alice", "bob")
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
            if (world.notes["jumped"] != true) {
                dmViolation("SCN-I fault-free: the world never settled, so the retire day was never reached")
            }
            val restored = world[RESTORED].device
            val drops = restored.engine.status().drops
            val unopenable = (drops["unknown_seal"] ?: 0) + (drops["unknown_generation"] ?: 0)
            if (unopenable == 0) {
                dmViolation("SCN-I fault-free: no pre-restore envelope was counted as unopenable: $drops")
            }
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
     * A crash inside the settling rounds loses the jump with the rest of its step, and the next
     * step — which runs this again — is what makes the jump happen in every single-crash run; the
     * note is written the moment the clock moves, so a crash in the passes after the jump does not
     * make the next step jump twice. A world that never settles is not jumped at all, and the
     * fault-free run asserts it did.
     */
    private fun jumpToTheRetireDayOnceSettled(w: DmCrashWorld) {
        if (w.notes["jumped"] == true) return
        for (attempt in 0 until SETTLE_ROUNDS) {
            if (settled(w)) break
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

    /** At most this many rounds are spent settling before the jump. */
    private const val SETTLE_ROUNDS: Int = 8

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

    /** Every scenario this slice implements, in the order the report prints them. */
    fun all(): List<DmScenario> =
        listOf(scnA(), scnB(), scnD(), scnF(), scnG(), scnGWeek(), scnH(), scnI(), scnJ(), scnK(), scnL())
}
