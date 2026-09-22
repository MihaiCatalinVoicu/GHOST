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
 * the invariants check, and the refusal half is modelled by [ModelDmRelay.outcomeFor]. The second
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
     * mutation that splits the transaction, and SCN-A is what kills it.
     */
    fun scnA(): DmScenario = DmScenario(
        name = "SCN-A",
        doubles = true,
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
     * MC-10 ("arrival-order display") is what it kills. REPEATS puts the same bytes in twice, which
     * is D1's job.
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
            val changed = alice.engine.contacts().filter { it.trust == TrustState.CHANGED }
            if (changed.size != 1) {
                dmViolation(
                    "SCN-D: expected exactly one 'changed' contact, got " +
                        alice.engine.contacts().map { it.trust },
                )
            }
            // CS-5: no encrypt to a `changed` contact — the facade refuses before any ratchet call.
            val refused = alice.engine.send(changed.single().id, "should not go", null)
            if (refused != SendResult.KEY_CHANGED) {
                dmViolation("SCN-D: a send to a 'changed' contact returned $refused")
            }
            // And the held content is not displayed before the acknowledgement (§8.3).
            val held = DmScripts.count(world, "alice", "SELECT count(*) FROM dm_held")
            if (held == 0L) dmViolation("SCN-D: the new-key message was not held")
            if (alice.engine.conversation(changed.single().id, 50, null)
                    .any { it.text == "it is still me" }
            ) {
                dmViolation("SCN-D: held content was displayed before KEYDEC (CS-5)")
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
     * under new bytes): a re-encryption costs a ratchet step and a second hash. The check below is
     * the hash, taken before and after the resend.
     */
    fun scnG(): DmScenario = DmScenario(
        name = "SCN-G",
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
                w.notes["bytes"] = itemBlobs(w, "alice")
                w.pump()
                w.passes()
            },
            step("the first resend") { w -> w.pump(); w.passes() },
            step("the second resend") { w -> w.pump(); w.passes() },
            step("and one more round, past the bound") { w -> w.pump(); w.passes() },
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

    /** The bytes of every item op that still carries them: the MC-3 oracle. */
    private fun itemBlobs(world: DmCrashWorld, node: String): List<String> {
        val out = ArrayList<String>()
        world[node].raw.query(
            "SELECT hex(blob) FROM dm_outbound_op WHERE purpose = 'item' AND blob IS NOT NULL " +
                "ORDER BY operation_id",
        ) { out += it.string(0) }
        return out
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
