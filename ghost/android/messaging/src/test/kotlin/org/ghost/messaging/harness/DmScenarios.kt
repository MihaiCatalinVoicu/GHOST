package org.ghost.messaging.harness

import org.ghost.messaging.DmWorld
import org.ghost.messaging.api.CardSource
import org.ghost.messaging.api.SendResult
import org.ghost.messaging.api.Timer
import org.ghost.messaging.api.TrustState

/**
 * The named crash scenarios of Phase 9 design §15.3, as far as slice S10 implements them.
 *
 * Implemented here: **SCN-A** (send), **SCN-B** (receive and reorder), **SCN-D** (key change,
 * including the forged-binding case), **SCN-F** (ephemeral), **SCN-G** (outcomes and resend),
 * **SCN-J** (faults) and **SCN-L** (migration safety). SCN-C, SCN-E, SCN-H, SCN-I and SCN-K are
 * not here; §22.15 of the design records exactly what each one still owes.
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

    /** Every scenario this slice implements, in the order the report prints them. */
    fun all(): List<DmScenario> = listOf(scnA(), scnB(), scnD(), scnF(), scnG(), scnJ(), scnL())
}
