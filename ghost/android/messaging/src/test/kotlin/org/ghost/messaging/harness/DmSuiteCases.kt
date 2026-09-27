package org.ghost.messaging.harness

import org.ghost.crypto.bridge.DmContent
import org.ghost.crypto.bridge.DmEquivalence
import org.ghost.messaging.DmWorld
import org.ghost.messaging.api.AddContactResult
import org.ghost.messaging.api.CardSource
import org.ghost.messaging.api.ContactId
import org.ghost.messaging.api.MessageState
import org.ghost.messaging.api.SendResult
import org.ghost.messaging.api.Timer
import org.ghost.messaging.api.TrustState
import org.ghost.messaging.engine.DmTime
import org.ghost.messaging.engine.DmTimers
import org.ghost.messaging.port.DmEnvelopes

/**
 * Named sub-cases of the functional suites of Phase 9 design §15.5, written as [DmScenario]s so
 * they run under the crash enumeration and under a mutation with the same code.
 *
 * Four are here, and each is a case §15.5 names. Three of them are the **only** case that kills a
 * mutant this slice registers:
 *  - **RP6** "re-encryption after a wrongly reported FAILED" — the one path that reaches D3, and so
 *    the one that can detect MC-5;
 *  - the §12.3 rejected-request replay — the one that reaches D2b, and so MC-7′;
 *  - **EP** "a read path ignores expiry", the behavioural half of the DAO lint, and so ME-16.
 *
 * The fourth, **RP9**, is here for a different reason: it is what makes the model relay's TRUNCATE
 * mode something the engine is measured against rather than a capability of the harness nobody
 * drives. Its own doc comment says why **RP3** is not beside it.
 *
 * Three more since the suite cases of §22.27. Two are each the only case that kills the mutant it
 * makes reachable: **KC12** (a requester sending two identities: no crash, no state change) kills
 * MC-24, and **RS2** (a client offline 60 days: pair envelopes open after the absence) kills
 * MC-21. The third, **RP7** (an old L0 re-sealed under a later week key — built narrower, as a
 * back-dated L0 sealed by its sender, which its KDoc declares), had no registered mutant — §15.7's
 * MC-9 was out of every mechanism's reach — and its check was shown able to fail by a control in
 * `DmHarnessSelfTest` instead. §22.38 registers MC-9 on RECV's freshness policy, and RP7 kills it.
 *
 * The rest of RO, RS, RP, KC, CB, RE, EP, OS and RK is not here. §22.15 lists them by sub-case,
 * and §22.27 says which of them were looked at for this slice and why they stayed out.
 */
internal object DmSuiteCases {

    /**
     * **RP6 — re-encryption after a wrongly reported FAILED** (§15.5, CS-7).
     *
     * The relay stores the blob and tells the sender it failed. The user retries, which
     * re-encrypts: new bytes, a new hash, a new ratchet step — so D1's tombstone does not match and
     * D2's structural bindings do not either. What is left is D3, the `dm_seen` tag over the
     * message's own id.
     *
     * **D3 is not the only thing between the recipient and a second row, and saying so was wrong.**
     * Under mutant MC-5 — D3 off — the copy reaches RECV as a *new* message and `dm_message`'s
     * replace guard (§13.6, "dm_message rows are never replaced") refuses the insert with
     * `SQLITE_CONSTRAINT_TRIGGER`; the pass dies there and the runner reports it, before the
     * `seen > 1` check below can see anything. So what D3 uniquely provides is that the copy is a
     * **duplicate** — silently dropped, the message rendered once — rather than an error that ends
     * a pass. The `seen > 1` check stays, because it is the property CS-2 states and a future
     * schema without that trigger would need it; §22.15 item 14 records that no run exercises it
     * today.
     *
     * **Since the phase review (ENG-3)** RECV no longer reaches the guard: a peer could re-use an
     * id on purpose and abort three passes per blob, so the row is written by an insert that selects
     * nothing when the id is taken and the message is dropped as `id_taken`. A copy that D3 lets
     * through is therefore dropped quietly too, and the check that kills MC-5 is the one below: no
     * copy RP6 retries may reach the message row at all (`id_taken` stays 0), which is D3's own
     * property — with the tag written, the copy is a `duplicate` at R10.
     */
    fun rp6ReEncryptionAfterAWronglyReportedFailure(): DmScenario = DmScenario(
        name = "RP6",
        liveness = "alice" to "bob",
        noLoss = true,
        // The relay's lie makes it FAILED, which is the case's premise; a crash that cost the
        // retry step leaves it so.
        expectedFailures = setOf("only once"),
        setup = { world ->
            world.node("alice", 0x41)
            world.node("bob", 0x51)
            DmScripts.activate(world)
            DmScripts.establishBothWays(world, "alice", "bob")
        },
        steps = listOf(
            step("the relay lies") { w ->
                w.relay.modes = setOf(ModelDmRelay.Mode.LIE_FAILED)
                w["alice"].device.engine.send(DmScripts.contact(w, "alice", "bob"), "only once", null)
                w.pump()
                w.passes()
            },
            step("the user retries") { w ->
                w.relay.modes = emptySet()
                val contact = DmScripts.contact(w, "alice", "bob")
                val failed = w["alice"].device.engine.conversation(contact, 20, null)
                    .firstOrNull { it.state == MessageState.FAILED && it.text == "only once" }
                if (failed != null) {
                    w.notes["retried"] = w["alice"].device.engine.retry(failed.id) == SendResult.QUEUED
                }
                w.pump()
                w.passes()
            },
            step("settle") { w -> w.pump(); w.passes() },
        ),
        alwaysChecks = { world ->
            val seen = DmScripts.inboundTexts(world, "bob").count { it == "only once" }
            if (seen > 1) {
                dmViolation("RP6: bob rendered the retried message $seen times (D3 is off)")
            }
            // Phase review ENG-3: a copy D3 did not drop now reaches the message row, which drops
            // it quietly as `id_taken` where the replace guard used to abort the pass. The copy
            // RP6 retries must never get that far: D3's tag over its `message_id` drops it first.
            val taken = world["bob"].device.engine.status().drops["id_taken"] ?: 0
            if (taken > 0) {
                dmViolation("RP6: the retried copy passed D3 and reached the message row, which already held its id")
            }
        },
        finalChecks = { world ->
            if (world.notes["retried"] != true) {
                dmViolation("RP6: the lie never produced a FAILED message to retry")
            }
            val seen = DmScripts.inboundTexts(world, "bob").count { it == "only once" }
            if (seen != 1) dmViolation("RP6: bob rendered the message $seen times, expected once")
        },
    )

    /**
     * **The §12.3 rejected-request replay** (CB, and RP4/RP5's reuse tuple).
     *
     * A rejected request leaves nothing behind, and the requester cannot re-create it by re-sending
     * the **same** unacknowledged session: the second envelope is another PreKey message of the
     * session the first one started, so its `session_id` is already in `olm_prekey_used` and D2b
     * refuses it. GHOST publishes no one-time keys (§5.6), so vodozemac consumes nothing when the
     * inbound session is built and that row is the only thing that stops a second one.
     */
    fun cbRejectedRequestStaysRejected(): DmScenario = DmScenario(
        name = "CB-reject-replay",
        setup = { world ->
            world.node("alice", 0x41)
            world.node("bob", 0x51)
            DmScripts.activate(world)
            world["alice"].device.engine.addContact(
                world["bob"].device.card(), CardSource.QR_IN_PERSON,
            )
            val contactB = world["alice"].device.engine.contacts().single().id
            world.contacts["alice->bob"] = contactB
            world["alice"].device.engine.send(contactB, "hello", null)
            world.pump()
            world["alice"].device.timeTriggeredPass()
            world.advanceBy(3 * DmWorld.MINUTE)
            world["alice"].device.timeTriggeredPass()
            world.pump()
            world["bob"].device.hintPass()
            val request = world["bob"].device.engine.contacts().single()
            check(world["bob"].device.engine.rejectRequest(request.id)) { "bob could not reject" }
            check(world["bob"].device.engine.contacts().isEmpty()) { "a rejected request lingered" }
        },
        steps = listOf(
            step("the requester re-sends the same session") { w ->
                w["alice"].device.engine.send(DmScripts.contact(w, "alice", "bob"), "again", null)
                w.pump()
                w.hint("bob")
            },
            step("past the gap hold") { w ->
                // The re-sent envelope is chain index 1 of a session B no longer has, so the gap
                // hold of §7.7 point 2 keeps it back for its first pass rather than showing a chain
                // out of order. D2b decides only once the hold is over.
                w.advanceBy(13 * DmWorld.MINUTE)
                w.pump()
                w.hint("bob")
                if (w["bob"].device.engine.contacts().isNotEmpty()) {
                    dmViolation("CB: a rejected request came back as a second one (D2b is off)")
                }
            },
        ),
        alwaysChecks = { world ->
            if (world["bob"].device.engine.contacts().isNotEmpty()) {
                dmViolation("CB: a rejected request came back as a second one (D2b is off)")
            }
        },
        finalChecks = { world ->
            if (world["bob"].device.engine.status().drops["replay"] == null) {
                dmViolation("CB: the re-sent first flight was not counted as a replay")
            }
        },
    )

    /**
     * **EP — no read path returns a row past its `delete_at_minute`** (§10.6, T25).
     *
     * SWEEP is deliberately not run: what is under test is the **read**, which must hide an expired
     * row the moment its deadline passes and not wait for the sweep that removes it. That gap is
     * exactly where mutant ME-16 lives, and the static half of the same rule is
     * `DmExpiredRowLint`'s over `DmDaoQueries`.
     */
    fun epExpiredRowsAreNotReadable(): DmScenario = DmScenario(
        name = "EP-read-expiry",
        setup = { world ->
            world.node("alice", 0x41)
            world.node("bob", 0x51)
            DmScripts.activate(world)
            DmScripts.establishBothWays(world, "alice", "bob")
        },
        steps = listOf(
            step("a five-minute message") { w ->
                w["alice"].device.engine.setTimer(DmScripts.contact(w, "alice", "bob"), Timer.MIN_5)
                w.pump()
                w.passes()
                w["alice"].device.engine.send(DmScripts.contact(w, "alice", "bob"), "brief", null)
                w.pump()
                w.passes()
                w.notes["arrived"] = DmScripts.inboundTexts(w, "bob").contains("brief")
            },
            step("past the unread deadline, with no sweep") { w ->
                // §10.3 caps an unread message at `min(E, consume + bucket + 1 h)`, so two hours is
                // past it for the five-minute bucket. No pass runs, and the check is **inside** the
                // step: the runner's quiescence tail would sweep the row away, and a check taken
                // after that would pass whether or not the read path honours the deadline.
                w.advanceBy(2 * DmWorld.HOUR)
                if (w.notes["arrived"] == true &&
                    DmScripts.inboundTexts(w, "bob").contains("brief")
                ) {
                    dmViolation("EP: an expired row is still readable before SWEEP (ME-16)")
                }
            },
        ),
        finalChecks = { world ->
            if (world.notes["arrived"] != true) {
                dmViolation("EP: the message never arrived, so its expiry proved nothing")
            }
        },
    )

    /**
     * **RP9 — a blob with a flipped byte** (§15.5, CS-7).
     *
     * It does not open, and — the half that is easy to lose — the recipient produces **no traffic
     * of any kind** in answer: a decryption-error message or an automatic session reset is mutant
     * PM-6 and an oracle for whoever flipped the byte. So the case asserts both that nothing is
     * rendered and that the item-op count does not move.
     *
     * **RP3 is not here, and it is not constructible in this world.** §15.5 states it as
     * COPY_NAMESPACE — "a blob of contact A presented as contact B's" — and R-S3 is the rule it
     * checks ("a relay that copies the blob into another namespace … produces something that does
     * not open"). But a device has exactly **one** DM inbox namespace per card index (§5.1, §3.3),
     * and after `EST-END` that is the only namespace it listens on, so "another namespace the
     * recipient owns" does not exist for it. The relay's first version of this case therefore fell
     * back to the blob's own namespace and the message opened — correctly, and the case failed for
     * a reason that was the harness's, not the engine's. §22.15 records what RP3 needs: the second
     * card index of §3.3, which no slice has exercised yet. The namespace binding itself is covered
     * by the `dm_seal.txt` vectors of §15.2.
     */
    fun rp9FlippedBytesDoNotOpenAndAnswerNothing(): DmScenario = DmScenario(
        name = "RP9",
        setup = { world ->
            world.node("alice", 0x41)
            world.node("bob", 0x51)
            DmScripts.activate(world)
            DmScripts.establishBothWays(world, "alice", "bob")
            world.notes["rendered"] = DmScripts.inboundTexts(world, "bob").size
            // Item ops, not every op: a weekly bundle publication is time-triggered and would
            // legitimately move a count over `outbox_op`, which would make this case fail for a
            // reason that has nothing to do with the blob it is about.
            world.notes["stores"] = DmScripts.count(
                world, "bob", "SELECT count(*) FROM dm_outbound_op WHERE purpose = 'item'",
            )
        },
        steps = listOf(
            step("a blob with a flipped byte") { w ->
                w.relay.modes = setOf(ModelDmRelay.Mode.TRUNCATE)
                w["alice"].device.engine.send(DmScripts.contact(w, "alice", "bob"), "flipped", null)
                w.pump()
                w.passes()
            },
            step("and another") { w ->
                w["alice"].device.engine.send(DmScripts.contact(w, "alice", "bob"), "flipped2", null)
                w.pump()
                w.passes()
            },
        ),
        alwaysChecks = { world ->
            val texts = DmScripts.inboundTexts(world, "bob")
            if (texts.any { it.startsWith("flipped") }) {
                dmViolation("RP9: a blob with a flipped byte opened")
            }
            // **In every run, faulted or not.** A recipient that stored anything in answer to a
            // blob it could not open would be an oracle for whoever corrupted it (PM-6, T28), and
            // that is a property of the recipient's own transactions — so a crash is exactly when
            // it might break. It was a `finalCheck`, which meant no faulted run ever asserted the
            // half of RP9 that the case is named for. Bob never sends in this scenario and its
            // establishment is finished in the unfaulted setup, so a store here is always an
            // answer and never a scenario step.
            val stores = DmScripts.count(
                world, "bob", "SELECT count(*) FROM dm_outbound_op WHERE purpose = 'item'",
            )
            val before = world.notes["stores"] as Long
            if (stores != before) {
                dmViolation("RP9: bob answered an unopenable blob with ${stores - before} stores")
            }
            if (world.notes["rendered"] != texts.size) {
                dmViolation("RP9: bob rendered something from an unopenable blob")
            }
        },
        finalChecks = { world ->
            // §15.5's RP9 is "TRUNCATE **and** byte flips", and the mode did only the second for as
            // long as nothing counted. A short blob fails the length check before any AEAD runs and
            // a flipped one fails the AEAD; two refusal paths, and a case that drove one of them
            // and claimed both.
            if (world.relay.truncated == 0 || world.relay.flipped == 0) {
                dmViolation(
                    "RP9: the relay served ${world.relay.truncated} short blobs and " +
                        "${world.relay.flipped} flipped ones — both shapes have to be driven",
                )
            }
        },
    )

    // ------------------------------------------------------------------ KC12 (§22.27)

    /**
     * **KC12 — a requester sending two identities: no crash, no state change** (§15.5 KC, §21.4
     * point 5; the suite cases of §22.27).
     *
     * > For `trust_state = request`, a PreKey L1 with `OI′ ≠ pinned` under a valid binding is
     * > `drop(request_key_mismatch)` with no state change; a `request → changed` transition does not
     * > exist.
     *
     * alice writes to bob first, so bob holds a **request** pinned to alice's Olm identity. Then
     * alice's second device — the same `ghost1` seed under another MESSAGING branch, SCN-D's `bob2`
     * shape and `KeyChangeTest`'s reincarnation: a genuine binding, under the Ed25519 key the request
     * carries, for a **second** Olm identity — scans bob's card and writes. A request has not been
     * accepted, so there is nothing to block and nothing for the user to decide: bob drops the first
     * flight and nothing moves. Only then does bob accept alice's request, and the two talk.
     * `KeyChangeTest.aRequestThatChangesItsIdentityIsDroppedAndNotHeld` is the same property outside
     * the enumeration; this is it under every crash point, with the runner's three oracles on.
     *
     * **Checked in every run** (raw reads, so no check is an event of the run it checks): **no
     * crash** — no pass of any device threw, and a throw that carries the schema's own "illegal trust
     * transition" is named as what it is, the `request → changed` attempt of mutant MC-24; **the
     * parts of "no state change" that hold whatever a crash interrupted** — bob holds one contact for
     * alice's identity, never `changed`, never with a pending identity, still pinned to her first
     * Olm identity, and no held row; and bob never rendered the second identity's message.
     * **Fault-free:** **no state change, whole** — every row of bob's DM state that a contact's
     * messages can touch ([KC12_STATE_TABLES]: the contact row with every column, its conversation,
     * messages, held rows, dedup tags, pair keys and offers, PQ keys, sessions, reuse tuples,
     * outbound items, pending sends, scheduled controls and bundle candidates) is byte for byte what
     * it was at the end of the setup, right after the pass that took the second identity's first
     * flight (only the inbox's own bookkeeping, the outbox, the counters and `dm_self` are outside
     * it) — the review showed that the fixed list above lets a pass that extends the request's
     * `request_until_day` or moves its `card_index` through; the contact was still a `request`
     * pinned to the first identity, the drop was counted as `request_key_mismatch` (exactly one)
     * with nothing poisoned, the second identity's message was `SENT` — so it did reach bob — and
     * bob accepted.
     *
     * **The oracles, all three on.** No-loss, with one declared loss: the second identity's message
     * is `SENT` and dropped **by design** (§21.4 point 5), declared only once the run has put it
     * there — bob's decision found it written, `SENT`, owed by no relay and consumed while the
     * contact was still a request ([DmScenario.declaredLoss]'s rule) — and every fate of it other
     * than "dropped while a request" is refused elsewhere (held: the trust check; rendered: the
     * render check; stranded: "nothing owed"), and the fault-free run measures the drop itself.
     * Liveness: alice ↔ bob, once bob has accepted. Nothing owed.
     *
     * **The user actions the case depends on are done again when a crash interrupted them**
     * (§22.19 item 6's rule), each judged from rows read raw: the second device's write (its
     * contact list and its outgoing message) and bob's acceptance (his contact's trust state). The
     * acceptance is taken **only once the second identity's first flight has been consumed**: after
     * an acceptance the same flight is a key change and §8.3 holds it, which is correct and is
     * SCN-D's subject, not this one — so the decision waits until the flight is stored, served and
     * consumed, and a world in which it never is fails with that message rather than testing the
     * other case. bob's welcome and alice's answer are not redone (S10's rule).
     *
     * **The mark MC-24's kill starts from** is bob's first pass after the second device wrote: the
     * step records its event count ([KC12_MARK]), and the kill rule of §22.27 crashes the mutant
     * inside the first transaction after it that the mutation changes — the RECV of the second
     * identity's first flight.
     */
    fun kc12ARequestSendingTwoIdentities(
        /**
         * The `ghost1` seed branch of the second device: alice's own (0x42) in the case, another
         * identity only in `DmHarnessSelfTest`'s control that shows the contact-count check can fail.
         */
        secondIdentityBranch: Int = 0x42,
    ): DmScenario = DmScenario(
        name = "KC12",
        liveness = "alice" to "bob",
        noLoss = true,
        declaredLoss = { world -> if (world.notes[KC12_DROPPED_AS_REQUEST] == true) setOf(KC12_SECOND_TEXT) else emptySet() },
        setup = { world ->
            world.node("alice", 0x41)
            world.node("bob", 0x51)
            // The same `ghost1` seed as alice (0x42) under another MESSAGING branch: a second Olm
            // identity whose binding verifies under the Ed25519 key bob's request pinned.
            world.node(KC12_SECOND_DEVICE, 0x63, identityBranch = secondIdentityBranch)
            DmScripts.activate(world)
            val alice = world["alice"].device
            val bob = world["bob"].device
            check(alice.engine.addContact(bob.card(), CardSource.QR_IN_PERSON) == AddContactResult.ADDED) {
                "alice could not add bob's card"
            }
            val toBob = alice.engine.contacts().single().id
            check(alice.engine.send(toBob, "hello", null) == SendResult.QUEUED)
            world.pump()
            alice.timeTriggeredPass()
            // `EST-READY` waits two minutes for a better bundle candidate (§21.7 point 4).
            world.advanceBy(3 * DmWorld.MINUTE)
            alice.timeTriggeredPass()
            world.pump()
            bob.hintPass()
            val request = bob.engine.contacts().single()
            check(request.trust == TrustState.REQUEST) { "bob does not hold alice's request: ${request.trust}" }
            world.contacts["alice->bob"] = toBob
            world.contacts["bob->alice"] = request.id
            world.notes[KC12_PINNED] = requireNotNull(pinnedHex(world, "bob", "bob->alice")) {
                "bob's request pins no identity"
            }
            // bob's whole DM state as the request left it, for the fault-free "no state change".
            world.notes[KC12_STATE] = stateOf(world, "bob", KC12_STATE_TABLES)
        },
        steps = listOf(
            step("alice's second device writes under the same identity") { w ->
                ensureSecondIdentityWritten(w)
                w.pump()
                w.pass(KC12_SECOND_DEVICE)
                w.advanceBy(3 * DmWorld.MINUTE)
                w.pass(KC12_SECOND_DEVICE)
                w.pump()
            },
            step("bob's device takes it while the request is undecided") { w ->
                // The first pass of bob's that can take the second identity's first flight: the
                // mark MC-24's kill looks for its first changed transaction after (§22.27).
                w.notes.putIfAbsent(KC12_MARK, w.bus.count)
                ensureSecondIdentityWritten(w)
                w.pump()
                w.hint("bob")
                // Fault-free this is the moment the drop happened; read raw, so no event.
                w.notes[KC12_STILL_REQUEST] = trustOf(w, "bob", "bob->alice") == "request" &&
                    pinnedHex(w, "bob", "bob->alice") == w.notes[KC12_PINNED]
                w.notes[KC12_MISMATCHES] =
                    w["bob"].device.engine.status().drops["request_key_mismatch"] ?: 0
                @Suppress("UNCHECKED_CAST")
                val before = w.notes[KC12_STATE] as Map<String, List<String>>
                val after = stateOf(w, "bob", KC12_STATE_TABLES)
                w.notes[KC12_STATE_CHANGED] = KC12_STATE_TABLES.filter { before[it] != after[it] }
            },
            step("bob accepts alice's request and answers") { w ->
                ensureAccepted(w)
                if (trustOf(w, "bob", "bob->alice") == "unverified") {
                    w["bob"].device.engine.send(DmScripts.contact(w, "bob", "alice"), KC12_WELCOME, null)
                }
                round(w)
            },
            step("the conversation goes on") { w ->
                ensureAccepted(w)
                round(w)
                if (KC12_WELCOME in DmScripts.inboundTexts(w, "alice")) {
                    w["alice"].device.engine.send(DmScripts.contact(w, "alice", "bob"), KC12_PAIR, null)
                }
                round(w)
                round(w)
            },
        ),
        alwaysChecks = { world ->
            noPassThrew(world)
            // No state change on bob's contact for alice, whatever the crash did: one contact for
            // her identity, never `changed`, no pending identity, still pinned to her first identity.
            val contacts = rawCount(world, "bob", "SELECT count(*) FROM dm_contact")
            if (contacts != 1L) dmViolation("KC12: bob holds $contacts contacts, expected alice's one")
            val trust = trustOf(world, "bob", "bob->alice")
            if (trust != "request" && trust != "unverified") {
                dmViolation("KC12: bob's contact for alice is '$trust' — the second identity moved it (§21.4 point 5)")
            }
            if (rawCount(world, "bob", "SELECT count(*) FROM dm_contact WHERE pending_identity IS NOT NULL") != 0L) {
                dmViolation("KC12: bob's contact for alice carries a pending identity (§21.4 point 5)")
            }
            if (pinnedHex(world, "bob", "bob->alice") != world.notes[KC12_PINNED]) {
                dmViolation("KC12: bob's contact for alice now pins another Olm identity")
            }
            val held = rawCount(world, "bob", "SELECT count(*) FROM dm_held")
            if (held != 0L) dmViolation("KC12: bob holds $held rows for a contact that was a request")
            if (KC12_SECOND_TEXT in DmScripts.everyInboundText(world["bob"])) {
                dmViolation("KC12: bob rendered the second identity's message")
            }
        },
        finalChecks = { world ->
            val changed = world.notes[KC12_STATE_CHANGED] as? List<*>
                ?: dmViolation("KC12 fault-free: bob's pass that took the second identity's first flight never ran")
            if (changed.isNotEmpty()) {
                dmViolation(
                    "KC12 fault-free: bob's pass that took the second identity's first flight changed his " +
                        "state — rows of $changed differ from the setup's (§21.4 point 5: no state change)",
                )
            }
            if (world.notes[KC12_STILL_REQUEST] != true) {
                dmViolation(
                    "KC12 fault-free: after bob's pass took the second identity's first flight his " +
                        "contact for alice was not a request pinned to her first identity",
                )
            }
            if (world.notes[KC12_MISMATCHES] != 1) {
                dmViolation(
                    "KC12 fault-free: bob counted ${world.notes[KC12_MISMATCHES]} request_key_mismatch " +
                        "drops when he took the second identity's first flight, expected exactly one",
                )
            }
            val status = world["bob"].device.engine.status()
            if (status.poisoned != 0) dmViolation("KC12 fault-free: bob consumed ${status.poisoned} blobs as poison")
            val second = DmScripts.outgoingState(world, KC12_SECOND_DEVICE, KC12_SECOND_TEXT)
            if (second != MessageState.SENT) {
                dmViolation("KC12 fault-free: the second identity's message is $second, not SENT, so its drop proved nothing")
            }
            if (trustOf(world, "bob", "bob->alice") != "unverified") {
                dmViolation("KC12 fault-free: bob never accepted alice's request")
            }
            val rendered = DmScripts.inboundTexts(world, "bob")
            if ("hello" !in rendered || KC12_PAIR !in rendered) {
                dmViolation("KC12 fault-free: bob rendered $rendered, expected hello and $KC12_PAIR")
            }
        },
    )

    /**
     * The second device's write, done again when a crash interrupted it: judged from its contact
     * list and its outgoing message, both read raw (the text is sealed in the row, so "its one
     * outgoing text message" is what identifies it — the device writes nothing else).
     */
    private fun ensureSecondIdentityWritten(w: DmCrashWorld) {
        val second = w[KC12_SECOND_DEVICE]
        if (rawCount(w, KC12_SECOND_DEVICE, "SELECT count(*) FROM dm_contact") == 0L) {
            when (val added = second.device.engine.addContact(w["bob"].device.card(), CardSource.QR_IN_PERSON)) {
                AddContactResult.ADDED, AddContactResult.ALREADY_KNOWN -> Unit
                else -> dmViolation("KC12: alice's second device could not add bob's card: $added")
            }
        }
        if (rawCount(w, KC12_SECOND_DEVICE, "SELECT count(*) FROM dm_message WHERE direction = 'out' AND kind = 1") == 0L) {
            var contact: ByteArray? = null
            second.raw.query("SELECT contact_id FROM dm_contact") { contact = it.blob(0) }
            second.device.engine.send(ContactId(requireNotNull(contact)), KC12_SECOND_TEXT, null)
        }
    }

    /**
     * bob's acceptance, done again when a crash interrupted it — and taken only once the second
     * identity's first flight is out of the way: written and `SENT`, owed to bob by no relay, and
     * consumed by his inbox. After an acceptance the same flight would be a key change (§8.3), which
     * is SCN-D's subject; so a world in which it never settles fails here rather than testing that.
     * The rounds only move what is in flight; the "no crash" check runs first, so a flight that
     * cannot settle because bob's passes throw on it is named for that.
     */
    private fun ensureAccepted(w: DmCrashWorld) {
        if (trustOf(w, "bob", "bob->alice") != "request") return
        var rounds = 0
        while (!secondIdentitySettled(w)) {
            noPassThrew(w)
            if (rounds++ >= KC12_DRAIN_ROUNDS) {
                dmViolation(
                    "KC12: the second identity's first flight was still in flight after $KC12_DRAIN_ROUNDS " +
                        "rounds, so bob's decision would come before it",
                )
            }
            ensureSecondIdentityWritten(w)
            w.pump()
            w.pass(KC12_SECOND_DEVICE)
            w.advanceBy(3 * DmWorld.MINUTE)
            w.pass(KC12_SECOND_DEVICE)
            w.pump()
            w.hint("bob")
        }
        noPassThrew(w)
        // The run has now put the second identity's message where it is lost by design: written,
        // `SENT`, owed by no relay and consumed by bob while his contact was still a request. The
        // declaration of the loss is made here and nowhere earlier ([DmScenario.declaredLoss]).
        w.notes[KC12_DROPPED_AS_REQUEST] = true
        w["bob"].device.engine.acceptRequest(DmScripts.contact(w, "bob", "alice"))
    }

    /** The second identity's message is `SENT`, the relay owes bob nothing and his inbox is empty; raw. */
    private fun secondIdentitySettled(w: DmCrashWorld): Boolean {
        val sent = rawCount(
            w, KC12_SECOND_DEVICE,
            "SELECT count(*) FROM dm_message WHERE direction = 'out' AND kind = 1 AND state = 'sent'",
        ) == 1L
        val now = w.nodes().maxOf { it.clock.now }
        return sent &&
            w.relay.owed(listOf(w["bob"]), now) == 0 &&
            rawCount(w, "bob", "SELECT count(*) FROM inbox_blob WHERE state <> 'done'") == 0L
    }

    /**
     * KC12's "no crash": nothing any device's pass threw. The actor thread swallows a throw
     * ([DmCrashWorld.swallowed]) and the runner refuses it at the very end of a run; this names it
     * at once, and names the one throw §21.4 point 5 is about by the schema's own words.
     */
    private fun noPassThrew(w: DmCrashWorld) {
        for (thrown in w.swallowed) {
            val message = generateSequence(thrown) { it.cause }.mapNotNull { it.message }.joinToString(" | ")
            if ("illegal trust transition" in message) {
                dmViolation(
                    "KC12: bob's RECV attempted request → changed on the second identity's first flight " +
                        "and the schema refused it (illegal trust transition) — a pass that throws at " +
                        "every offer of one blob (§21.4 point 5)",
                )
            }
            dmViolation("KC12: a pass threw ${thrown::class.simpleName}: $message")
        }
    }

    // ------------------------------------------------------------------ RS2 (§22.27)

    /**
     * **RS2 — a client offline 60 days** (§15.5 RS, §21.3 point 5, CR-13; the suite cases of
     * §22.27).
     *
     * > RS2 a client offline 60 days (blobs past TTL lost and declared, no duplicates, sessions
     * > usable or reset by the user; pair envelopes open after the absence, §21.3 point 5)
     *
     * alice and bob talk in pair mode with the conversation's timer off (so the absence sweeps no
     * message the oracles read, and a stored blob waits its 30 days at the relay). Then bob's phone
     * is **off** — no pass and no relay session of his for **61** days; only the clock, which is the
     * world's, moves — while alice's is on: a pass and a relay session of hers every five days, so
     * her pair keys ratchet week by week as a phone in use does. alice writes into the absence at
     * once; the relay stores it for its 30-day TTL and it is gone long before bob is back. She writes
     * again on day 40, which the relay still holds when bob returns and which is sealed under a week
     * key whose window is still open then. bob comes back: his first pass is SWEEP, which must
     * **ratchet** his in-keys from the newest one he holds — **nine week-indices** behind the week he
     * returns in, and past its own window — to that week, keeping every key whose window is still
     * open, **then** erase. The day-40 message opens under its week's key; alice writes again, sealed
     * under the return week's key; bob answers. `TrustFlowTest.aRecipientBackAfterSixtyDays
     * StillOpensPairEnvelopes` is the ratchet half outside the enumeration; this is RS2 whole, under
     * every crash point, with the runner's three oracles.
     *
     * **Why 61 days and not 60** (§22.27's review). The world starts on a Wednesday, and 60 days from
     * there is a gap of **eight** week-indices, where the engine with S9's defect — the catch-up cap
     * at eight weeks, §22.14 item 15(d), the regression this case exists to catch — is byte for byte
     * the clean one: the review set the cap back to eight and RS2 passed, fault-free and at every
     * crash point. Sixty-one days is nine, the far side of that cliff, as `TrustFlowTest` chose; and
     * the gap is a check (below), not a comment, so a later change to the world's start cannot move
     * the case back under the cliff without failing it. §15.5's "offline 60 days" is met: the
     * absence is at least 60 days.
     *
     * **Checked in every run** (raw reads): the absence began and ended, lasted the 61 days, and put
     * the return at least nine week-indices past bob's newest in-key; bob holds an in-key of the
     * generation the conversation was sealed under before the absence **for the week he came back
     * in** — derived by his first SWEEP after the return and kept for 45 days, so a crash anywhere
     * cannot take it away, and without the ratchet-before-erasure order nothing can put it there
     * (mutant MC-21); and **for every week in between whose window is still open** at the check's
     * own `now_e` (§21.3 point 5: "`K_w` for every week up to `week(now)`") — a key no sweep could
     * have erased yet, so its absence is a ratchet that stored too little (the review's mutant kept
     * only the newest derived week and passed the return-week check alone). **Fault-free:** the
     * message written into the absence is `SENT`, never rendered, and the relay let it expire
     * unserved (measured, not assumed: exactly one blob); the day-40 message, the message after the
     * absence and the answer are rendered ("blobs past TTL lost", and the ones within it delivered);
     * bob dropped nothing as `unknown_seal`; neither device listed a bundle namespace from the moment
     * the absence began, and both kept the `current` session they had — so what opened was a **pair
     * envelope of the old conversation**, not a re-establishment ("sessions usable").
     *
     * **The oracles, all three on.** No-loss, with one declared loss: the message written into the
     * absence — "blobs past TTL lost and declared", RS2's own words — declared before the send is
     * called (§22.19 item 9's rule) and measured fault-free as above; the day-40 message is not
     * declared, so a run in which it is `SENT` and never rendered fails. CS-2 ("no duplicates") is
     * the runner's. Liveness: alice ↔ bob after the return ("sessions usable"). Nothing owed.
     *
     * **Time is idempotent here, not a step's side effect**: every step moves the clock **to** its
     * point of the absence rather than **by** an amount, so a crash that cost one step its clock
     * move does not shorten the absence — the next step makes it, and the return step (redone by
     * every later step, judged from the note written the moment the clock reached the return) makes
     * the 60 days whatever was lost. alice's two messages and bob's answer are not redone (S10's
     * rule; the checks are written for either outcome).
     *
     * **The mark MC-21's kill starts from** is bob's return, before his first pass: the step records
     * its event count ([RS2_MARK]), and the kill rule of §22.27 crashes the mutant inside the first
     * transaction after it that the mutation changes — bob's first SWEEP after the absence.
     */
    fun rs2AClientOfflineSixtyDays(
        /** The absence in days: [RS2_ABSENCE_DAYS] in the case, sixty only in `DmHarnessSelfTest`'s control of the gap check. */
        absenceDays: Long = RS2_ABSENCE_DAYS,
    ): DmScenario = DmScenario(
        name = "RS2",
        liveness = "alice" to "bob",
        noLoss = true,
        declaredLoss = { world -> if (world.notes[RS2_AWAY_SENT] == true) setOf(RS2_LOST) else emptySet() },
        setup = { world ->
            world.node("alice", 0x41)
            world.node("bob", 0x51)
            DmScripts.activate(world)
            DmScripts.establishBothWays(world, "alice", "bob")
            // The timer off: under the default seven days every message of the scenario is swept
            // long before the absence is over, and a TTL of 30 days is what makes the message
            // written into the absence outlive nothing (SCN-I and SCN-E do the same).
            world["alice"].device.engine.setTimer(DmScripts.contact(world, "alice", "bob"), Timer.OFF)
            world.notes[RS2_ABSENCE] = absenceDays * DmWorld.DAY
            settle(world)
            val generation = requireNotNull(acknowledgedInGeneration(world)) {
                "bob holds no in-key of an acknowledged generation after the establishment"
            }
            world.notes[RS2_GENERATION] = generation
            world.notes[RS2_NEWEST_WEEK] = requireNotNull(newestInKeyWeek(world, generation)) {
                "bob holds no in-key of generation $generation"
            }
            world.notes[RS2_SESSIONS] = listOf(
                currentSessionHex(world, "alice", "alice->bob"),
                currentSessionHex(world, "bob", "bob->alice"),
            )
        },
        steps = buildList {
            add(
                step("bob's phone goes off; alice writes into the absence") { w ->
                    w.notes[RS2_AWAY] = now(w)
                    // Declared before the call (§22.19 item 9): "rs2-away, if it exists, was written
                    // while bob's phone was off", which is decided here.
                    w.notes[RS2_AWAY_SENT] = true
                    w["alice"].device.engine.send(DmScripts.contact(w, "alice", "bob"), RS2_LOST, null)
                    aliceAlone(w)
                },
            )
            for (k in 1 until RS2_ABSENCE_STEPS) {
                val day = k * RS2_STEP_DAYS
                add(
                    step("alice alone, day $day") { w ->
                        advanceTo(w, (w.notes[RS2_AWAY] as Long) + day * DmWorld.DAY)
                        if (day == RS2_MID_DAY) {
                            // A message the absence must not lose: stored for 30 days from here, so
                            // still held when bob returns on day 61, and sealed under this week's
                            // key, whose window is still open then. Her pass first, so the key of
                            // this week exists (SEND seals under the author week's key, rule 2).
                            w.pass("alice")
                            w["alice"].device.engine.send(DmScripts.contact(w, "alice", "bob"), RS2_MID, null)
                        }
                        aliceAlone(w)
                    },
                )
            }
            add(step("bob's phone comes back after sixty-one days") { w -> ensureBack(w) })
            add(
                step("alice writes after the absence") { w ->
                    ensureBack(w)
                    round(w)
                    w["alice"].device.engine.send(DmScripts.contact(w, "alice", "bob"), RS2_AFTER, null)
                    // §7.7 point 2's gap hold: the message written into the absence never arrives,
                    // so this one is a chain index ahead and waits up to twelve minutes.
                    repeat(RS2_GAP_ROUNDS) { round(w) }
                },
            )
            add(
                step("bob answers") { w ->
                    ensureBack(w)
                    w["bob"].device.engine.send(DmScripts.contact(w, "bob", "alice"), RS2_ANSWER, null)
                    repeat(RS2_GAP_ROUNDS) { round(w) }
                },
            )
        },
        alwaysChecks = { world ->
            val away = world.notes[RS2_AWAY] as? Long ?: dmViolation("RS2: bob's absence never began")
            val back = world.notes[RS2_BACK] as? Long
                ?: dmViolation("RS2: bob never came back, so nothing after the absence was tested")
            val absence = world.notes[RS2_ABSENCE] as Long
            if (back - away < absence) {
                dmViolation("RS2: bob was away ${(back - away) / DmWorld.DAY} days, not ${absence / DmWorld.DAY}")
            }
            val generation = world.notes[RS2_GENERATION] as Int
            val newest = world.notes[RS2_NEWEST_WEEK] as Long
            val week = DmTime.week(back)
            if (week - newest < RS2_MIN_GAP_WEEKS) {
                dmViolation(
                    "RS2: bob came back in week $week, ${week - newest} week-indices after his newest in-key " +
                        "(week $newest) — not the $RS2_MIN_GAP_WEEKS that clear S9's catch-up cap of eight " +
                        "(§22.14 item 15(d)), so the absence tests nothing that cap broke",
                )
            }
            if (!holdsInKey(world, generation, week)) {
                dmViolation(
                    "RS2: after ${(back - away) / DmWorld.DAY} days away bob holds no in-key of generation " +
                        "$generation for week $week, the week he came back in — the ratchet did not run " +
                        "before the erasure (§21.3 point 5, CR-13)",
                )
            }
            // Every week in between whose window is still open at bob's own `now_e` now: no sweep
            // can have erased it (a sweep erases K_w only at `now_e >= start(w + 1) + FRESH`, and
            // `now_e` never goes back), and the return's sweep had to derive it.
            val nowE = expiryClockOf(world, "bob")
            for (w in (newest + 1) until week) {
                if (nowE >= DmTime.weekStart(w + 1) + DmTimers.FRESH_SECONDS) continue
                if (!holdsInKey(world, generation, w)) {
                    dmViolation(
                        "RS2: bob holds no in-key of generation $generation for week $w, whose window is " +
                            "still open — SWEEP did not keep K_w for every week up to week(now) " +
                            "(§21.3 point 5)",
                    )
                }
            }
        },
        finalChecks = { world ->
            val now = world.nodes().maxOf { it.clock.now }
            if (DmScripts.outgoingState(world, "alice", RS2_LOST) != MessageState.SENT) {
                dmViolation("RS2 fault-free: the message written into the absence is not SENT, so its loss proved nothing")
            }
            if (RS2_LOST in DmScripts.everyInboundText(world["bob"])) {
                dmViolation("RS2 fault-free: bob rendered a message whose blob had outlived its TTL")
            }
            val expired = world.relay.expiredUnserved(world["bob"], now)
            if (expired != 1) {
                dmViolation("RS2 fault-free: the relay let $expired of alice's blobs expire unserved to bob, expected the one written into the absence")
            }
            if (RS2_MID !in DmScripts.inboundTexts(world, "bob")) {
                dmViolation("RS2 fault-free: bob never rendered alice's day-$RS2_MID_DAY message, which the relay still held when he returned")
            }
            if (RS2_AFTER !in DmScripts.inboundTexts(world, "bob")) {
                dmViolation("RS2 fault-free: bob never rendered alice's message after the absence (§21.3 point 5)")
            }
            if (RS2_ANSWER !in DmScripts.inboundTexts(world, "alice")) {
                dmViolation("RS2 fault-free: alice never rendered bob's answer after the absence")
            }
            val unopenable = world["bob"].device.engine.status().drops["unknown_seal"] ?: 0
            if (unopenable != 0) dmViolation("RS2 fault-free: bob dropped $unopenable blobs as unknown_seal")
            val away = world.notes[RS2_AWAY] as Long
            val listed = world.relay.bundleListings.filter { it.at >= away }.map { it.node }
            if (listed.isNotEmpty()) {
                dmViolation("RS2 fault-free: $listed listed a bundle namespace after the absence began — a re-establishment, not the old conversation")
            }
            val sessions = listOf(
                currentSessionHex(world, "alice", "alice->bob"),
                currentSessionHex(world, "bob", "bob->alice"),
            )
            if (sessions != world.notes[RS2_SESSIONS]) {
                dmViolation("RS2 fault-free: a current session changed across the absence — the conversation was re-established, not resumed")
            }
        },
    )

    /** bob's return, done again by every later step until it happened: judged from the note written the moment the clock reached it. */
    private fun ensureBack(w: DmCrashWorld) {
        if (w.notes[RS2_BACK] != null) return
        advanceTo(w, (w.notes[RS2_AWAY] as Long) + (w.notes[RS2_ABSENCE] as Long))
        w.notes[RS2_BACK] = now(w)
        // MC-21's mark: bob's first pass after the return is its SWEEP, the transaction it changes.
        w.notes.putIfAbsent(RS2_MARK, w.bus.count)
        // A phone that starts again runs a time-triggered pass (a database open, §21.9 rule 1)
        // before it opens a relay session.
        w.pass("bob")
        w.pump()
        w.passes()
    }

    /** One of alice's relay sessions with bob's phone off: her pass, her stores and listings only, her pass. */
    private fun aliceAlone(w: DmCrashWorld) {
        w.pass("alice")
        w.relay.pump(listOf(w["alice"]))
        w.pass("alice")
    }

    /**
     * bob's newest in-generation whose offer alice acknowledged: the generation she seals the
     * conversation under before the absence. Raw.
     */
    private fun acknowledgedInGeneration(w: DmCrashWorld): Int? {
        var generation: Int? = null
        w["bob"].raw.query(
            "SELECT max(k.root_gen) FROM dm_pair_key k JOIN dm_pair_offer o " +
                "ON o.contact_id = k.contact_id AND o.root_gen = k.root_gen " +
                "WHERE k.contact_id = ? AND k.direction = 'in' AND o.acknowledged = 1",
            listOf(contactBytes(w, "bob->alice")),
        ) { if (!it.isNull(0)) generation = it.long(0).toInt() }
        return generation
    }

    /** The newest week of bob's in-keys of [generation]; raw. */
    private fun newestInKeyWeek(w: DmCrashWorld, generation: Int): Long? {
        var week: Long? = null
        w["bob"].raw.query(
            "SELECT max(week) FROM dm_pair_key WHERE contact_id = ? AND direction = 'in' AND root_gen = ?",
            listOf(contactBytes(w, "bob->alice"), generation.toLong()),
        ) { if (!it.isNull(0)) week = it.long(0) }
        return week
    }

    /**
     * [node]'s `now_e` as its sweep computes it (R-T7): `max(floor_minute(wall), expiry_clock_minute)`,
     * in seconds; raw.
     */
    private fun expiryClockOf(w: DmCrashWorld, node: String): Long {
        var stored = 0L
        w[node].raw.query("SELECT expiry_clock_minute FROM dm_self") { stored = it.long(0) }
        return maxOf(DmTime.floorMinute(w[node].clock.now), stored)
    }

    private fun holdsInKey(w: DmCrashWorld, generation: Int, week: Long): Boolean =
        rawCount(
            w, "bob",
            "SELECT count(*) FROM dm_pair_key WHERE contact_id = ? AND direction = 'in' " +
                "AND root_gen = ? AND week = ?",
            listOf(contactBytes(w, "bob->alice"), generation.toLong(), week),
        ) == 1L

    // ------------------------------------------------------------------ RP7 (§22.27)

    /**
     * **RP7 — an old L0 re-sealed under a later week key** (§15.5 RP, §7.6 binding B1; the suite
     * cases of §22.27).
     *
     * §7.6's table, row B1: "pair mode: `week(author_minute)` = the key's week (R9)", which defeats
     * "an old L0 re-sealed under a later week key".
     *
     * **What is built is narrower than §15.5's sentence, and says so** (§22.27's review). Sealing
     * under a pair key needs only the key and an L1's bytes (`sealPair` takes `openEnv` and `l1`,
     * nothing of the Olm session), so the literal RP7 party is anyone holding `K_w` and `K_{w+1}` —
     * a seized recipient, or the sender itself — who opens an undelivered week-`w` envelope and
     * re-seals its L1 under `K_{w+1}`. What is built is the **sender-side construction**: alice's
     * device is given a `DmEnvelopes` decorator (installed in the unfaulted setup, re-installed at
     * every boot, like `DmPoisonTest`'s) that encodes one **fresh** message's L0 with an author
     * minute in the ISO week **before** the one alice's row and the key are of, and changes nothing
     * else: SEND picks the pair key by the row's author minute (rule 2), so the envelope is sealed
     * under this week's key around a back-dated L0 with a new message id. At bob, up to and
     * including the moment B1 decides, the two are the same input — a pair envelope under `K_{w+1}`
     * whose L1 is the next chain index of the session and whose L0 is dated in week `w` — and the
     * message id is new to him in both (the literal case's original never arrived), so D3 has
     * nothing to match; the minute is days old, inside the bucket's freshness, so R9's age bound
     * passes: **B1 is the only thing between bob and the message**. What the literal case has and
     * this one does not is what follows the refusal: R8 has consumed the old message key, so the
     * genuine week-`w` envelope, when it is released, no longer decrypts, and the sender's own next
     * message was replaced. That half is **not built** (a `sealPair` decorator re-sealing the L1 of
     * a message the relay held back across the week boundary is constructible with the model
     * relay's `releaseNotBefore`; §22.27 item 8 names it). bob must drop the back-dated message
     * (`stale`) with nothing rendered and nothing sent, and the conversation must go on — the Olm
     * step was taken, and R8 commits the session state whatever R9 and B1 decide (§7.4), so the next
     * message is one chain index on and opens.
     *
     * **Checked in every run:** bob never renders the old-dated message. **Fault-free:** it was
     * `SENT` (so it did reach bob), its L0 was dated in the week before its key's and inside R9's
     * window for its bucket (so B1 and not R9 is what refused it), bob counted exactly one `stale`
     * drop, and the next message was rendered.
     *
     * **The oracles, all three on.** No-loss, with one declared loss: the old-dated message, dropped
     * by design (B1), declared only once the decorator has actually back-dated its L0 in the run
     * ([DmScenario.declaredLoss]'s rule); the fault-free run measures the drop. Liveness: alice ↔
     * bob. Nothing owed.
     *
     * **Its mutant is MC-9 ("no freshness check"), since §22.38.** §22.27 registered none: B1 and
     * R9 are Kotlin comparisons in `ReceiveStep.decryptAndApply` over the decoded author minute and
     * the arrival time — no statement carries the decision and no port result is the decision, so
     * none of the harness's mechanisms reached it faithfully. §22.38 moved the comparisons, verbatim
     * and in their order, into RECV's freshness policy (`ContentFreshness.RULE`), which the crash
     * worlds substitute, and MC-9 is killed here fault-free and at crash points inside the RECV it
     * first changes ([RP7_MARK]). The check is also shown able to fail by `DmHarnessSelfTest` item
     * 10's control: the same decorator dating the L0 a minute earlier **in the key's own week**,
     * which B1 lets through, must fail the render check.
     */
    fun rp7AnOldL0ResealedUnderALaterWeekKey(
        /** True only in the control: the L0 is dated a minute earlier, in the key's own week. */
        sameWeek: Boolean = false,
    ): DmScenario = DmScenario(
        name = "RP7",
        liveness = "alice" to "bob",
        noLoss = true,
        declaredLoss = { world -> if (world.notes[RP7_DATED] != null) setOf(RP7_OLD) else emptySet() },
        setup = { world ->
            world.node("alice", 0x41)
            world.node("bob", 0x51)
            DmScripts.activate(world)
            DmScripts.establishBothWays(world, "alice", "bob")
            settle(world)
            val alice = world["alice"]
            alice.decorate = { real -> OldDatedL0(real, RP7_OLD.toByteArray(Charsets.UTF_8), world, sameWeek) }
            alice.reboot()
            DmStructuralInvariants.check(alice, "RP7 setup reboot")
        },
        steps = listOf(
            step("alice's device re-seals an L0 of last week under this week's key") { w ->
                w.notes.putIfAbsent(RP7_MARK, w.bus.count)
                // Two minutes first, so the control's L0 — a minute earlier — shares no rendered
                // position with the establishment's last message (the CS-2 proxy, which the
                // control would otherwise fail before the check it is about).
                w.advanceBy(2 * DmWorld.MINUTE)
                w["alice"].device.engine.send(DmScripts.contact(w, "alice", "bob"), RP7_OLD, null)
                round(w)
            },
            step("the conversation goes on") { w ->
                w["alice"].device.engine.send(DmScripts.contact(w, "alice", "bob"), RP7_NEXT, null)
                round(w)
                round(w)
            },
        ),
        alwaysChecks = { world ->
            if (RP7_OLD in DmScripts.everyInboundText(world["bob"])) {
                dmViolation("RP7: bob rendered an L0 dated in another week than the key that sealed it (binding B1, §7.6)")
            }
        },
        finalChecks = { world ->
            if (DmScripts.outgoingState(world, "alice", RP7_OLD) != MessageState.SENT) {
                dmViolation("RP7 fault-free: the old-dated message is not SENT, so its drop proved nothing")
            }
            val dated = world.notes[RP7_DATED] as? Long
                ?: dmViolation("RP7 fault-free: the decorator never dated an L0")
            val sealedWeek = world.notes[RP7_SEALED_WEEK] as Long
            if (DmTime.week(dated) >= sealedWeek) {
                dmViolation("RP7 fault-free: the L0 was dated in week ${DmTime.week(dated)}, not before the key's week $sealedWeek")
            }
            // Inside R9's window for the conversation's bucket, so B1 and not R9 refused it.
            val arrived = world.notes[RP7_SENT_AT] as Long
            if (arrived - dated >= RP7_R9_BOUND) {
                dmViolation("RP7 fault-free: the L0 is ${(arrived - dated) / DmWorld.DAY} days old, past R9's own bound")
            }
            val stale = world["bob"].device.engine.status().drops["stale"] ?: 0
            if (stale != 1) dmViolation("RP7 fault-free: bob counted $stale stale drops, expected exactly one")
            if (RP7_NEXT !in DmScripts.inboundTexts(world, "bob")) {
                dmViolation("RP7 fault-free: bob never rendered the message after the old-dated one")
            }
        },
    )

    /**
     * alice's device with one L0 dated in the ISO week before its own: the RP7 sender. It changes
     * one argument of one call — the author minute of the message whose body is [text] — and
     * records what it did in the world's notes for the fault-free checks.
     */
    private class OldDatedL0(
        private val real: DmEnvelopes,
        private val text: ByteArray,
        private val world: DmCrashWorld,
        private val sameWeek: Boolean,
    ) : DmEnvelopes by real {
        override fun encodeContent(
            kind: DmContent.Kind,
            messageId: ByteArray,
            authorMinute: Long,
            minuteIndex: Int,
            timerCode: Int,
            timerVersion: Long,
            quoteRef: ByteArray?,
            body: ByteArray,
            contactId: ByteArray,
            offerRootGen: Int,
            offerEnv: ByteArray,
            revocation: ByteArray,
            sessionReset: Boolean,
            pqKey: DmContent.PqKeyCandidate?,
            pqKeyFirst: Boolean,
        ): DmContent.Encoded {
            var minute = authorMinute
            if (kind == DmContent.Kind.TEXT && body.contentEquals(text)) {
                val seconds = authorMinute * DmTime.MINUTE
                val dated = if (sameWeek) {
                    seconds - DmTime.MINUTE
                } else {
                    DmTime.weekStart(DmTime.week(seconds)) - DmTime.DAY
                }
                world.notes[RP7_DATED] = dated
                world.notes[RP7_SEALED_WEEK] = DmTime.week(seconds)
                world.notes[RP7_SENT_AT] = seconds
                minute = dated / DmTime.MINUTE
            }
            return real.encodeContent(
                kind, messageId, minute, minuteIndex, timerCode, timerVersion, quoteRef, body,
                contactId, offerRootGen, offerEnv, revocation, sessionReset, pqKey, pqKeyFirst,
            )
        }
    }

    private const val RP7_OLD: String = "rp7-dated-last-week"
    private const val RP7_NEXT: String = "rp7-next"
    private const val RP7_DATED: String = "rp7Dated"
    private const val RP7_SEALED_WEEK: String = "rp7SealedWeek"
    private const val RP7_SENT_AT: String = "rp7SentAt"

    /**
     * R9's age bound for the default seven-day bucket, `FRESH(7 d)` (§21.10 point 3): the L0 of the
     * case must be younger, so the refusal it measures is B1's.
     */
    private val RP7_R9_BOUND: Long = DmTimers.freshSeconds(DmTimers.bucketOf(Timer.DAYS_7.code))

    // ------------------------------------------------------------------ shared by KC12, RS2 and RP7

    /** One relay round, a pass, three minutes, a pass (SCN-I's `round`). */
    private fun round(w: DmCrashWorld) {
        w.pump()
        w.passes()
        w.advanceBy(3 * DmWorld.MINUTE)
        w.passes()
    }

    /** Unfaulted settling in a setup: three rounds and a last pump and pass. */
    private fun settle(world: DmCrashWorld) {
        repeat(3) {
            world.pump()
            world.passes()
            world.advanceBy(3 * DmWorld.MINUTE)
        }
        world.pump()
        world.passes()
    }

    private fun now(w: DmCrashWorld): Long = w.nodes().maxOf { it.clock.now }

    /** Moves the world's clock **to** [target] if it is not there yet: idempotent, so a lost step shortens nothing. */
    private fun advanceTo(w: DmCrashWorld, target: Long) {
        val now = now(w)
        if (target > now) w.advanceBy(target - now)
    }

    private fun contactBytes(w: DmCrashWorld, key: String): ByteArray =
        requireNotNull(w.contacts[key]) { "no contact $key" }.toByteArray()

    private fun rawCount(w: DmCrashWorld, node: String, query: String, args: List<Any?> = emptyList()): Long {
        var out = 0L
        w[node].raw.query(query, args) { out = it.long(0) }
        return out
    }

    private fun trustOf(w: DmCrashWorld, node: String, key: String): String? {
        var out: String? = null
        w[node].raw.query(
            "SELECT trust_state FROM dm_contact WHERE contact_id = ?",
            listOf(contactBytes(w, key)),
        ) { out = it.string(0) }
        return out
    }

    private fun pinnedHex(w: DmCrashWorld, node: String, key: String): String? {
        var out: String? = null
        w[node].raw.query(
            "SELECT hex(pinned_identity) FROM dm_contact WHERE contact_id = ?",
            listOf(contactBytes(w, key)),
        ) { if (!it.isNull(0)) out = it.string(0) }
        return out
    }

    /**
     * Every row of each of [tables] on [node], every column `quote()`d, sorted; raw, so no event.
     * The columns are read from the schema itself, so a column a later migration adds is compared
     * too.
     */
    fun stateOf(w: DmCrashWorld, node: String, tables: List<String>): Map<String, List<String>> =
        tables.associateWith { table ->
            val columns = ArrayList<String>()
            w[node].raw.query("PRAGMA table_info($table)") { columns += it.string(1) }
            check(columns.isNotEmpty()) { "no table $table" }
            val rows = ArrayList<String>()
            w[node].raw.query(
                "SELECT " + columns.joinToString(" || ',' || ") { "quote(\"$it\")" } + " FROM $table",
            ) { rows += it.string(0) }
            rows.sorted()
        }

    private fun currentSessionHex(w: DmCrashWorld, node: String, key: String): String? {
        var out: String? = null
        w[node].raw.query(
            "SELECT hex(session_id) FROM olm_session WHERE contact_id = ? AND slot = 'current'",
            listOf(contactBytes(w, key)),
        ) { out = it.string(0) }
        return out
    }

    /** The second device of alice's identity (KC12). */
    const val KC12_SECOND_DEVICE: String = "alice2"
    private const val KC12_SECOND_TEXT: String = "second identity"
    private const val KC12_WELCOME: String = "kc12-welcome"
    private const val KC12_PAIR: String = "kc12-pair"
    private const val KC12_PINNED: String = "kc12Pinned"
    private const val KC12_STILL_REQUEST: String = "kc12StillRequest"
    private const val KC12_MISMATCHES: String = "kc12Mismatches"
    private const val KC12_STATE: String = "kc12State"
    private const val KC12_STATE_CHANGED: String = "kc12StateChanged"
    private const val KC12_DROPPED_AS_REQUEST: String = "kc12DroppedAsRequest"

    /**
     * The tables of bob's DM state KC12's fault-free "no state change" compares, every row with every
     * column: everything a contact's messages can write, and nothing that moves on its own in a pass
     * that drops a blob — the inbox's bookkeeping (`inbox_blob`, `inbox_source`), the outbox
     * (`outbox_*`, `dm_outbound_op`), the drop counters and `dm_self` (its expiry clock rises at
     * every sweep) are outside it.
     */
    val KC12_STATE_TABLES: List<String> = listOf(
        "dm_contact", "dm_conversation", "dm_message", "dm_held", "dm_seen", "dm_pair_key",
        "dm_pair_offer", "dm_peer_pq", "olm_session", "olm_prekey_used", "dm_outbound_item",
        "dm_pending_send", "dm_scheduled", "dm_bundle_candidate",
    )

    /** The note KC12 writes the event count into at the step MC-24 can first change (§22.27). */
    const val KC12_MARK: String = "kc12Mark"

    /** How many rounds bob's decision waits for the second identity's first flight. */
    private const val KC12_DRAIN_ROUNDS: Int = 8

    private const val RS2_LOST: String = "rs2-away"
    private const val RS2_MID: String = "rs2-day40"
    private const val RS2_AFTER: String = "rs2-after"
    private const val RS2_ANSWER: String = "rs2-answer"
    private const val RS2_AWAY: String = "rs2Away"
    private const val RS2_AWAY_SENT: String = "rs2AwaySent"
    private const val RS2_BACK: String = "rs2Back"
    private const val RS2_GENERATION: String = "rs2Generation"
    private const val RS2_NEWEST_WEEK: String = "rs2NewestWeek"
    private const val RS2_SESSIONS: String = "rs2Sessions"

    /** The note RP5 writes the event count into as bob's first flight starts (§22.37). */
    const val RP5_MARK: String = "rp5Mark"

    /** The note RP7 writes at its re-sealing step: MC-9's window starts after it. */
    const val RP7_MARK: String = "rp7Mark"

    /** The note EP-sweep-log writes at its first step: ME-11's window starts after it. */
    const val EP_LOG_MARK: String = "epLogMark"

    /** The note EP-clock-back writes at its first step: ME-17's window starts after it. */
    const val EP_CLOCK_MARK: String = "epClockMark"

    /** The note RO-prune writes at its day-fifty-two step: MC-30's windows start after it. */
    /** EP-store-after-expiry's second step: the sweep that deletes the message while its op is in flight (ME-20). */
    const val EP_LATE_MARK: String = "epLateMark"
    /** EP-sender-ahead's first step: bob's RECV of the message written five days ahead (ME-19). */
    const val EP_AHEAD_MARK: String = "epAheadMark"
    /** EP-stale-display's first step: bob's first RECV of the two five-minute messages (ME-7). */
    const val EP_STALE_MARK: String = "epStaleMark"
    private const val EP_SHOWN: String = "ep-shown"
    private const val EP_STALE: String = "ep-stale"
    private const val EP_SHOWN_COUNT: String = "epShownCount"
    private const val EP_STALE_COUNT: String = "epStaleCount"
    private const val EP_STALE_TEN: String = "epStaleTen"
    private const val EP_STALE_PAST: String = "epStalePast"
    private const val EP_AHEAD: String = "ep-ahead"
    private const val EP_AHEAD_PAST: String = "epAheadPast"
    private const val EP_AHEAD_SENT_AT: String = "epAheadSentAt"
    private const val EP_AHEAD_DATED: String = "epAheadDated"

    /** How far ahead alice's clock runs: five days, inside R9's `2σ` of six. */
    private const val EP_AHEAD_SECONDS: Long = 5 * DmWorld.DAY
    private const val EP_LATE: String = "ep-late"
    private const val EP_LATE_WRITTEN: String = "epLateWritten"
    private const val EP_LATE_EXPIRED: String = "epLateExpired"
    private const val EP_LATE_ID: String = "epLateId"
    private const val EP_LATE_OP: String = "epLateOp"
    private const val EP_LATE_IN_FLIGHT: String = "epLateInFlight"

    const val RO_PRUNE_MARK: String = "roPruneMark"
    private const val RO_PRUNE_LOST = "ro-lost"
    private const val RO_PRUNE_NEXT = "ro-next"
    private const val RO_PRUNE_HELD = "roPruneHeld"
    private const val RO_PRUNE_START = "roPruneStart"
    private const val RO_PRUNE_HELD_AT_49 = "roPruneHeldAt49"

    /** Past the thirty-day TTL of a timer-off message: the relay expires it unserved. */
    private const val RO_PRUNE_HOLD: Long = 40 * DmWorld.DAY

    /**
     * The days of sweeps before the key's age bound, about ten apart. The last is the check that the
     * key is still held: day 49, so that it is under 51 days old even when the day it was first seen
     * and the day the steps count from straddle a midnight.
     */
    private val RO_PRUNE_DAYS: List<Long> = listOf(10L, 20L, 30L, 40L, 49L)
    private const val EP_CLOCK_TEXT: String = "ep-clock-back"
    private const val EP_CLOCK_SEEN: String = "epClockSeen"
    private const val EP_CLOCK_AHEAD: String = "epClockAhead"
    private const val EP_CLOCK_BACK: String = "epClockBack"
    private const val EP_CLOCK_SENT: String = "epClockSent"
    private const val EP_CLOCK_CORRECTED: String = "epClockCorrected"
    private const val EP_LOG_MEASURED: String = "epLogMeasured"
    private const val EP_LOG_FIRST: String = "ep-log-first"
    private const val EP_LOG_SECOND: String = "ep-log-second"
    private const val RP5_FIRST: String = "rp5-hello"
    private const val RP5_AGAIN: String = "rp5-again"
    private const val RP5_REJECTED: String = "rp5Rejected"
    private const val RP5_REJECTING: String = "rp5Rejecting"
    private const val RP5_RESTARTED: String = "rp5Restarted"

    private const val RP4_FIRST: String = "rp4-hello"
    private const val RP4_AGAIN: String = "rp4-again"
    private const val RP4_AFTER: String = "rp4-after-reset"
    private const val RP4_SESSION: String = "rp4Session"
    private const val RP4_RESET: String = "rp4Reset"
    private const val RP11_FIRST: String = "rp11-hello"
    private const val RP11_OLD: String = "rp11-old"
    private const val RP11_SESSION: String = "rp11Session"
    private const val RP11_HOLD_UNTIL: String = "rp11HoldUntil"
    private const val RP11_RENEWALS: String = "rp11Renewals"
    private const val RP11_REPLACED: String = "rp11Replaced"
    private const val RP11_REOFFERED: String = "rp11Reoffered"

    /** How long the relay holds RP11's old envelope: longer than every renewal a crash can repeat. */
    private const val RP11_HOLD_SECONDS: Long = 6 * DmWorld.HOUR

    /** Renewals RP11 may need: two, and one more for each a crash interrupted before bob took it. */
    private const val RP11_MAX_RENEWALS: Int = 4

    /** Rounds a delivery of RP4, RP5 or RP11 may take: each is three minutes, past the gap hold with room. */
    private const val RP_DRAIN_ROUNDS: Int = 12

    /** The note RS2 writes the event count into at the step MC-21 can first change (§22.27). */
    const val RS2_MARK: String = "rs2Mark"

    /**
     * RS2's absence — 61 days, the far side of S9's cliff from this world's Wednesday start (see
     * the case's KDoc) — and the five-day relay sessions of alice's that fill it.
     */
    const val RS2_ABSENCE_DAYS: Long = 61
    private const val RS2_ABSENCE: String = "rs2Absence"
    private const val RS2_STEP_DAYS: Long = 5
    private const val RS2_ABSENCE_STEPS: Int = 12

    /** The day of the absence alice writes the message it must not lose (inside the 30-day TTL at the return). */
    private const val RS2_MID_DAY: Long = 40

    /**
     * The gap, in week-indices, from bob's newest in-key to the week he returns in that RS2 must
     * reach: nine, one past the catch-up cap of eight S9's defect had (§22.14 item 15(d)).
     */
    private const val RS2_MIN_GAP_WEEKS: Long = 9

    /** Rounds after a send: five of three minutes, past §7.7 point 2's twelve-minute gap hold. */
    private const val RS2_GAP_ROUNDS: Int = 5

    /**
     * **RP5 — a PreKey replay across a restart** (§15.5 RP5, §7.6 D2b, §7.8; built by §22.37).
     *
     * The CB replay's shape ([cbRejectedRequestStaysRejected]) with the two things RP5 adds. The
     * first flight reaches bob **inside** the armed phase, so a crash can land in the RECV
     * transaction that builds the request and writes the reuse tuple `(gen_id, session_id)` to
     * `olm_prekey_used` (§7.8: in that same transaction). And bob **restarts** between rejecting the
     * request and the replay, so what refuses the replay is the tuple read back from the database
     * by a new process, not anything a live one held.
     *
     * alice adds bob and writes; bob rejects the request — the contact, the session and the rows go,
     * the tuple stays (§12.3) — and restarts. alice writes again: nothing of bob's reached her, so her
     * session is still unacknowledged and the envelope is another PreKey message of the same
     * session, which D2b refuses by its tuple. **Checked in every run:** once bob has rejected, he
     * holds no contact at the end (a second request is D2b off, or its tuple lost) and never renders
     * the second text. **Fault-free:** bob restarted after the rejection and before the re-send,
     * alice's second text is `SENT`, and bob dropped exactly one envelope as `replay`.
     *
     * **Redo rule (§22.19 item 6):** every step first finishes what a crash interrupted — the first
     * flight is settled (written, `SENT`, owed to bob by no relay, consumed) before bob decides, and
     * the rejection is taken again while a request stands — judged from rows and engine reads, never
     * from which step ran. MC-7′'s second half, the tuple split out of the RECV transaction, is killed
     * here under a crash in its split window ([DmMutants.MC7_SPLIT]).
     */
    fun rp5PreKeyReplayAcrossARestart(): DmScenario = DmScenario(
        name = "RP5",
        setup = { world ->
            world.node("alice", 0x41)
            world.node("bob", 0x51)
            DmScripts.activate(world)
            world["alice"].device.engine.addContact(world["bob"].device.card(), CardSource.QR_IN_PERSON)
            world.contacts["alice->bob"] = world["alice"].device.engine.contacts().single().id
        },
        steps = listOf(
            step("alice's first flight reaches bob") { w ->
                w.notes.putIfAbsent(RP5_MARK, w.bus.count)
                rpDeliver(w, "alice", "bob", RP5_FIRST, "RP5")
            },
            step("bob rejects the request") { w -> rp5EnsureRejected(w) },
            step("bob restarts") { w ->
                rp5EnsureRejected(w)
                w["bob"].reboot()
                w.notes[RP5_RESTARTED] = true
            },
            step("the requester re-sends the same session") { w ->
                rp5EnsureRejected(w)
                rpDeliver(w, "alice", "bob", RP5_AGAIN, "RP5")
            },
        ),
        alwaysChecks = { world ->
            if (world.notes[RP5_REJECTED] == true && world["bob"].device.engine.contacts().isNotEmpty()) {
                dmViolation("RP5: a rejected request came back as a second one (D2b is off, or its tuple was lost)")
            }
            if (RP5_AGAIN in DmScripts.inboundTexts(world, "bob")) {
                dmViolation("RP5: bob rendered the second message of a session he had rejected")
            }
        },
        finalChecks = { world ->
            if (world.notes[RP5_RESTARTED] != true) dmViolation("RP5: bob never restarted between the rejection and the replay")
            val again = DmScripts.outgoingState(world, "alice", RP5_AGAIN)
            if (again != MessageState.SENT) dmViolation("RP5: alice's re-sent message is $again, not SENT")
            val replays = world["bob"].device.engine.status().drops["replay"] ?: 0
            if (replays != 1) dmViolation("RP5: bob dropped $replays envelopes as replay, expected exactly one")
        },
    )

    /**
     * bob's rejection, taken again while a request stands — and only once the first flight is
     * settled, so the request it rejects is the one the flight built and nothing of it is still on
     * its way. The note that arms the every-run check is written once bob holds no contact.
     *
     * A crash after the rejection committed and before that note leaves bob with no contact, which
     * is the rejection standing, not the request lost: [RP5_REJECTING], written before the call, is
     * what tells the two apart (the crash enumeration's point 932 of RP5, §22.37).
     */
    private fun rp5EnsureRejected(w: DmCrashWorld) {
        if (w.notes[RP5_REJECTED] == true) return
        rpDeliver(w, "alice", "bob", RP5_FIRST, "RP5")
        val request = w["bob"].device.engine.contacts().singleOrNull()
        if (request == null) {
            if (w.notes[RP5_REJECTING] != true) dmViolation("RP5: alice's first flight settled and bob holds no request")
        } else {
            if (request.trust != TrustState.REQUEST) dmViolation("RP5: bob's contact for alice is ${request.trust}, not a request")
            w.notes[RP5_REJECTING] = true
            if (!w["bob"].device.engine.rejectRequest(request.id)) dmViolation("RP5: bob could not reject the request")
        }
        if (w["bob"].device.engine.contacts().isNotEmpty()) dmViolation("RP5: a rejected request lingered")
        w.notes[RP5_REJECTED] = true
    }

    /**
     * **RP4 — a first flight of a session the recipient reset** (§15.5 RP4, "first-flight replay
     * after session resets (D2b, then D3)"; §7.6 D2b, §8.7; built by §22.37). The CB replay's shape:
     * the replayed flight is the requester's own next envelope of a session that is still
     * unacknowledged on her side.
     *
     * Setup (unfaulted): alice writes, bob accepts, and nothing of bob's reaches alice, so every
     * envelope alice seals is a PreKey message of that one session. Armed: alice writes again and
     * the relay holds the envelope for bob; **bob resets** the conversation (§8.7: both session rows
     * go, the reuse tuple stays); his inbox then takes the envelope — a PreKey message of a session
     * he no longer holds — and D2b drops it as `replay`; bob writes, so his new session reaches
     * alice and the two talk. Without D2b the envelope would build the reset session again, and
     * since bob's own sessions are initiator ones then, R-SS1's age exception (§22.8.4) would not
     * stop it: it would become `current`, over the reset the user asked for.
     *
     * **Checked in every run:** once bob has reset, he never holds the reset session again and never
     * renders the held message. **Fault-free:** exactly one `replay` drop, the held message `SENT`,
     * bob's message after the reset rendered by alice. **Oracles:** no-loss with one declared loss
     * (the held message, once bob's reset has preceded its receipt), liveness alice ↔ bob, nothing
     * owed. **Not built:** §15.5's "then D3" — D3 refuses a replay whose L0 bob has seen, and the
     * envelope here carries a new message (the CB shape), so D2b alone decides (§22.37).
     */
    fun rp4FirstFlightOfAResetSession(): DmScenario = DmScenario(
        name = "RP4",
        setup = { world ->
            world.node("alice", 0x41)
            world.node("bob", 0x51)
            DmScripts.activate(world)
            world["alice"].device.engine.addContact(world["bob"].device.card(), CardSource.QR_IN_PERSON)
            world.contacts["alice->bob"] = world["alice"].device.engine.contacts().single().id
            rpDeliver(world, "alice", "bob", RP4_FIRST, "RP4")
            val request = world["bob"].device.engine.contacts().single()
            check(world["bob"].device.engine.acceptRequest(request.id)) { "bob could not accept" }
            world.contacts["bob->alice"] = request.id
            world.notes[RP4_SESSION] = rpOnlySessionOf(world, "bob")
            check(rawCount(world, "alice", "SELECT count(*) FROM olm_session WHERE acknowledged = 0") == 1L) {
                "alice's session was acknowledged before the replay"
            }
        },
        steps = listOf(
            step("alice writes again, and the relay holds it for bob") { w -> rpStore(w, "alice", RP4_AGAIN, "RP4") },
            step("bob resets the conversation") { w -> rp4EnsureReset(w) },
            step("bob's inbox takes the held envelope") { w ->
                rp4EnsureReset(w)
                rpTake(w, "bob", "RP4")
            },
            step("bob writes after the reset") { w ->
                rp4EnsureReset(w)
                rpDeliver(w, "bob", "alice", RP4_AFTER, "RP4")
            },
        ),
        alwaysChecks = { world ->
            if (world.notes[RP4_RESET] == true && rpHolds(world, "bob", world.notes[RP4_SESSION] as ByteArray)) {
                dmViolation("RP4: bob holds the session he reset again (D2b is off)")
            }
            if (RP4_AGAIN in DmScripts.inboundTexts(world, "bob")) {
                dmViolation("RP4: bob rendered a message of the session he reset")
            }
        },
        finalChecks = { world ->
            val replays = world["bob"].device.engine.status().drops["replay"] ?: 0
            if (replays != 1) dmViolation("RP4: bob dropped $replays envelopes as replay, expected exactly one")
            val held = DmScripts.outgoingState(world, "alice", RP4_AGAIN)
            if (held != MessageState.SENT) dmViolation("RP4: alice's held message is $held, not SENT")
            if (RP4_AFTER !in DmScripts.inboundTexts(world, "alice")) {
                dmViolation("RP4: alice never rendered bob's message after the reset")
            }
        },
        liveness = "alice" to "bob",
        noLoss = true,
        declaredLoss = { w -> if (w.notes[RP4_RESET] == true) setOf(RP4_AGAIN) else emptySet() },
    )

    /** bob's reset, taken again while he still holds the session — and only once the held message is out. */
    private fun rp4EnsureReset(w: DmCrashWorld) {
        if (w.notes[RP4_RESET] == true) return
        rpStore(w, "alice", RP4_AGAIN, "RP4")
        val session = w.notes[RP4_SESSION] as ByteArray
        if (rpHolds(w, "bob", session)) {
            w["bob"].device.engine.resetSession(DmScripts.contact(w, "bob", "alice"))
        }
        if (rpHolds(w, "bob", session)) dmViolation("RP4: bob still holds the session after resetting it")
        w.notes[RP4_RESET] = true
    }

    /**
     * **RP11 — a PreKey message of a session R-SS1 replaced** (§15.5 RP11; R-SS1 as §22.8.4 amended
     * it; §7.6 D2b; built by §22.37).
     *
     * Setup (unfaulted): alice writes, bob accepts, nothing of bob's reaches alice. Armed: alice
     * writes again and the relay holds that envelope back ([ModelDmRelay.releaseNotBefore], six
     * hours); alice resets and writes, twice, so bob receives two first flights of new sessions:
     * R-SS1 makes the first `current` and the original `previous`, then the second `current` and
     * the first `previous` — the original is gone. The hold ends and bob's inbox takes the old
     * envelope, a PreKey message of a session R-SS1 replaced: D2b drops it as `replay`.
     *
     * **Two layers, each sufficient (§22.37).** Without D2b the envelope would build the old session
     * again — and R-SS1's age exception would refuse it as `stale_session`, since both of bob's
     * sessions are responder sessions newer than it. So no session comes back either way: RP11 is
     * not a detector of MC-7′ by its property, as §15.7's registry says it is (its entry predates
     * §22.8.4's amendment). What RP11 pins is that D2b decides first.
     *
     * **Checked in every run:** once R-SS1 has replaced it, bob never holds the original session again
     * and never renders the held message. **Fault-free:** two renewals, exactly one `replay` drop,
     * the held message `SENT`. **Oracles:** no-loss with one declared loss (the held message, once the
     * original session was gone before it arrived), liveness alice ↔ bob, nothing owed.
     */
    fun rp11APreKeyMessageOfAReplacedSession(): DmScenario = DmScenario(
        name = "RP11",
        setup = { world ->
            world.node("alice", 0x41)
            world.node("bob", 0x51)
            DmScripts.activate(world)
            world["alice"].device.engine.addContact(world["bob"].device.card(), CardSource.QR_IN_PERSON)
            world.contacts["alice->bob"] = world["alice"].device.engine.contacts().single().id
            rpDeliver(world, "alice", "bob", RP11_FIRST, "RP11")
            val request = world["bob"].device.engine.contacts().single()
            check(world["bob"].device.engine.acceptRequest(request.id)) { "bob could not accept" }
            world.contacts["bob->alice"] = request.id
            world.notes[RP11_SESSION] = rpOnlySessionOf(world, "bob")
        },
        steps = listOf(
            step("alice writes again, and the relay holds it back") { w -> rp11EnsureHeld(w) },
            step("alice renews the session twice") { w -> rp11EnsureReplaced(w) },
            step("the hold ends, and bob's inbox takes the old envelope") { w ->
                rp11EnsureReplaced(w)
                advanceTo(w, w.notes[RP11_HOLD_UNTIL] as Long + DmWorld.MINUTE)
                rpTake(w, "bob", "RP11")
            },
        ),
        alwaysChecks = { world ->
            if (world.notes[RP11_REPLACED] == true && rpHolds(world, "bob", world.notes[RP11_SESSION] as ByteArray)) {
                dmViolation("RP11: bob holds the session R-SS1 replaced again")
            }
            if (RP11_OLD in DmScripts.inboundTexts(world, "bob")) {
                dmViolation("RP11: bob rendered the held message of a replaced session")
            }
        },
        finalChecks = { world ->
            val renewals = world.notes[RP11_RENEWALS] as Int? ?: 0
            if (renewals != 2) dmViolation("RP11: alice renewed $renewals times, expected two")
            val reoffered = world.notes[RP11_REOFFERED] as Int? ?: 0
            if (reoffered != 2) dmViolation("RP11: the relay re-offered bob's bundle $reoffered times, expected once per renewal")
            val replays = world["bob"].device.engine.status().drops["replay"] ?: 0
            if (replays != 1) dmViolation("RP11: bob dropped $replays envelopes as replay, expected exactly one")
            val held = DmScripts.outgoingState(world, "alice", RP11_OLD)
            if (held != MessageState.SENT) dmViolation("RP11: alice's held message is $held, not SENT")
        },
        liveness = "alice" to "bob",
        noLoss = true,
        declaredLoss = { w -> if (w.notes[RP11_REPLACED] == true) setOf(RP11_OLD) else emptySet() },
    )

    /** alice's held message, stored under the hold (set until the store is `SENT`, then lifted). */
    private fun rp11EnsureHeld(w: DmCrashWorld) {
        if (DmScripts.outgoingState(w, "alice", RP11_OLD) == MessageState.SENT) {
            w.relay.releaseNotBefore = emptyMap()
            return
        }
        val until = w.notes.getOrPut(RP11_HOLD_UNTIL) { now(w) + RP11_HOLD_SECONDS } as Long
        w.relay.releaseNotBefore = mapOf("alice" to until)
        rpStore(w, "alice", RP11_OLD, "RP11")
        w.relay.releaseNotBefore = emptyMap()
    }

    /** alice's renewals, one more while bob still holds the original session, each written and taken. */
    private fun rp11EnsureReplaced(w: DmCrashWorld) {
        if (w.notes[RP11_REPLACED] == true) return
        rp11EnsureHeld(w)
        val session = w.notes[RP11_SESSION] as ByteArray
        // A renewal a crash interrupted is finished before another starts: its reset may have
        // committed and its text be owed, and a second reset over it would only make a third.
        (w.notes[RP11_RENEWALS] as Int?)?.let { n -> rpDeliver(w, "alice", "bob", "rp11-renewal-$n", "RP11", ::rp11Reoffer) }
        while (rpHolds(w, "bob", session)) {
            val renewal = (w.notes[RP11_RENEWALS] as Int? ?: 0) + 1
            if (renewal > RP11_MAX_RENEWALS) dmViolation("RP11: bob still holds the original session after ${renewal - 1} renewals")
            w.notes[RP11_RENEWALS] = renewal
            w["alice"].device.engine.resetSession(DmScripts.contact(w, "alice", "bob"))
            rpDeliver(w, "alice", "bob", "rp11-renewal-$renewal", "RP11", ::rp11Reoffer)
        }
        if (now(w) >= w.notes[RP11_HOLD_UNTIL] as Long) dmViolation("RP11: the hold ended before R-SS1 replaced the session")
        w.notes[RP11_REPLACED] = true
    }

    /**
     * The relay lists bob's bundle again once alice's `EST-START` forgot its tombstone
     * ([ModelDmRelay.reofferForgottenBundles]) — asked only while alice holds no session, the one
     * window in which her reset's bundle fetch is owed, and counted for the fault-free check.
     */
    private fun rp11Reoffer(w: DmCrashWorld) {
        if (rawCount(w, "alice", "SELECT count(*) FROM olm_session") != 0L) return
        val n = w.relay.reofferForgottenBundles(w["alice"])
        w.notes[RP11_REOFFERED] = (w.notes[RP11_REOFFERED] as Int? ?: 0) + n
    }

    /**
     * One text from [from] to [to], written if no row of it exists (a crash may have lost the send),
     * then moved until it is settled — `SENT`, owed to [to] by no relay, consumed by its inbox —
     * which for a PreKey message of a session [to] does not hold includes §7.7 point 2's gap hold.
     */
    private fun rpDeliver(
        w: DmCrashWorld,
        from: String,
        to: String,
        text: String,
        case: String,
        beforeRound: (DmCrashWorld) -> Unit = {},
    ) {
        if (DmScripts.outgoingState(w, from, text) == null) {
            w[from].device.engine.send(DmScripts.contact(w, from, to), text, null)
        }
        var rounds = 0
        while (!(DmScripts.outgoingState(w, from, text) == MessageState.SENT && rpInboxEmpty(w, to))) {
            if (rounds++ >= RP_DRAIN_ROUNDS) dmViolation("$case: $from's '$text' was still in flight after $RP_DRAIN_ROUNDS rounds")
            beforeRound(w)
            w.pump()
            w.pass(from)
            w.advanceBy(3 * DmWorld.MINUTE)
            w.pass(from)
            w.pump()
            w.hint(to)
        }
    }

    /** One text from [from], written if missing and stored at the relay (`SENT`); the recipient runs no pass. */
    private fun rpStore(w: DmCrashWorld, from: String, text: String, case: String) {
        val to = if (from == "alice") "bob" else "alice"
        if (DmScripts.outgoingState(w, from, text) == null) {
            w[from].device.engine.send(DmScripts.contact(w, from, to), text, null)
        }
        var rounds = 0
        while (DmScripts.outgoingState(w, from, text) != MessageState.SENT) {
            if (rounds++ >= RP_DRAIN_ROUNDS) dmViolation("$case: $from's '$text' was not stored after $RP_DRAIN_ROUNDS rounds")
            w.pump()
            w.pass(from)
            w.advanceBy(3 * DmWorld.MINUTE)
            w.pass(from)
        }
    }

    /** [node]'s inbox takes what the relay holds for it, through the gap hold, until nothing is owed or pending. */
    private fun rpTake(w: DmCrashWorld, node: String, case: String) {
        var rounds = 0
        while (!rpInboxEmpty(w, node)) {
            if (rounds++ >= RP_DRAIN_ROUNDS) dmViolation("$case: $node's inbox was not empty after $RP_DRAIN_ROUNDS rounds")
            w.pump()
            w.hint(node)
            w.advanceBy(3 * DmWorld.MINUTE)
            w.pump()
            w.hint(node)
        }
    }

    private fun rpInboxEmpty(w: DmCrashWorld, node: String): Boolean =
        w.relay.owed(listOf(w[node]), now(w)) == 0 &&
            rawCount(w, node, "SELECT count(*) FROM inbox_blob WHERE state <> 'done'") == 0L

    /** The id of the one session [node] holds, read raw (setup only). */
    private fun rpOnlySessionOf(w: DmCrashWorld, node: String): ByteArray {
        val ids = ArrayList<ByteArray>()
        w[node].raw.query("SELECT session_id FROM olm_session") { ids += it.blob(0) }
        return ids.singleOrNull() ?: error("$node holds ${ids.size} sessions, expected one")
    }

    /** Whether [node] holds a session with [sessionId], in either slot; raw. */
    private fun rpHolds(w: DmCrashWorld, node: String, sessionId: ByteArray): Boolean =
        rawCount(w, node, "SELECT count(*) FROM olm_session WHERE session_id = ?", listOf(sessionId)) > 0L

    /**
     * **KC5b — a genuine binding replayed** (§15.5 KC5b: "a genuine binding replayed with another
     * recipient namespace, another ciphertext or base key, or a stale minute → no state change";
     * §3.4, §21.4 point 1; built by §22.37).
     *
     * alice writes to bob four times, and each intro is sealed with KC5b's hook on one field
     * (`DmEquivalence.bindingHooks`, a test-library entry point): the envelope is alice's own, sealed
     * as she seals every intro, and its binding is her **genuine** signature over another value of
     * that field than the envelope carries — another recipient namespace, a stale minute (`FRESH`
     * and a minute before the one the envelope carries, which R5 accepts), another X-Wing
     * ciphertext, another base key. Those are the bytes a replayed binding presents, and no JVM seam
     * could build them (§22.27 item 8). Each must stop at the binding: `bad_binding`, nothing kept.
     * The hook stays on to the end, so an intro a crash left to be sealed later is a replay too.
     *
     * **Checked in every run:** bob holds no contact, no session and no reuse tuple, and renders none
     * of the four. **Fault-free:** exactly four `bad_binding` drops, the four texts `SENT`.
     * **Oracles:** no-loss with the four texts declared (each is refused by design), no liveness
     * (bob refuses all of alice, so the pair never forms), nothing owed.
     */
    fun kc5bAGenuineBindingReplayed(): DmScenario = DmScenario(
        name = "KC5b",
        setup = { world ->
            world.node("alice", 0x41)
            world.node("bob", 0x51)
            DmScripts.activate(world)
            world["alice"].device.engine.addContact(world["bob"].device.card(), CardSource.QR_IN_PERSON)
            world.contacts["alice->bob"] = world["alice"].device.engine.contacts().single().id
        },
        steps = KC5B_REPLAYS.map { (field, label) ->
            step("an intro whose binding names another $label reaches bob") { w ->
                w.notes.putIfAbsent(kc5bMark(field), w.bus.count)
                w["alice"].bindingPerturb = field
                w["alice"].installBindingHooks()
                rpDeliver(w, "alice", "bob", kc5bText(label), "KC5b")
            }
        },
        alwaysChecks = { world ->
            val rendered = DmScripts.everyInboundText(world["bob"])
            for ((_, label) in KC5B_REPLAYS) {
                if (kc5bText(label) in rendered) {
                    dmViolation("KC5b: bob accepted an intro whose binding names another $label")
                }
            }
            if (world["bob"].device.engine.contacts().isNotEmpty()) {
                dmViolation("KC5b: bob holds a contact, and every binding alice sent was replayed")
            }
            if (rawCount(world, "bob", "SELECT count(*) FROM olm_session") != 0L) {
                dmViolation("KC5b: bob holds a session built from a replayed binding")
            }
            if (rawCount(world, "bob", "SELECT count(*) FROM olm_prekey_used") != 0L) {
                dmViolation("KC5b: bob recorded a reuse tuple for a replayed binding")
            }
        },
        finalChecks = { world ->
            val refused = world["bob"].device.engine.status().drops["bad_binding"] ?: 0
            if (refused != KC5B_REPLAYS.size) {
                dmViolation("KC5b: bob refused $refused intros at the binding, expected ${KC5B_REPLAYS.size}")
            }
            for ((_, label) in KC5B_REPLAYS) {
                val state = DmScripts.outgoingState(world, "alice", kc5bText(label))
                if (state != MessageState.SENT) dmViolation("KC5b: alice's '${kc5bText(label)}' is $state, not SENT")
            }
        },
        noLoss = true,
        declaredLoss = { KC5B_REPLAYS.map { (_, label) -> kc5bText(label) }.toSet() },
    )

    /** KC5b's four replays: the binding field each moves, and its name in the case's messages. */
    private val KC5B_REPLAYS: List<Pair<Int, String>> = listOf(
        DmEquivalence.BINDING_NAMESPACE to "namespace",
        DmEquivalence.BINDING_MINUTE to "minute",
        DmEquivalence.BINDING_CIPHERTEXT to "ciphertext",
        DmEquivalence.BINDING_BASE_KEY to "base key",
    )

    private fun kc5bText(label: String): String = "kc5b-" + label.replace(' ', '-')

    /** The note KC5b writes at the start of the step that replays [field]: MC-20's window starts after it. */
    fun kc5bMark(field: Int): String = "kc5bMark$field"

    /**
     * **EP — SWEEP truncates the log** (§10.9 item 3, §10.7 "Checkpoint", T25; §15.5 EP, "the §10.9
     * cases"; built by §22.38).
     *
     * Two five-minute messages from alice to bob, each left unread past its §10.3 deadline, each
     * then swept away on both sides — so SWEEP deletes rows twice after the mark, and checkpoints
     * each time. The clause is the standing one of [DmStructuralInvariants.checkpointsTruncatedTheLog]
     * (measured right after every checkpoint the device reports done, for every scenario); this case
     * is the one built to reach it **twice** in its armed phase, which ME-11's kill needs: a crash
     * at the first checkpoint reboots through R-K1, which truncates, so only a later one can show
     * the mutant again.
     *
     * **Fault-free:** both messages reached bob before their deadlines and are gone after them, and
     * bob measured at least two checkpoints after the mark. **Oracles:** no-loss with the two texts
     * declared (their expiry is the subject), liveness alice ↔ bob, nothing owed.
     */
    fun epSweepTruncatesTheLog(): DmScenario = DmScenario(
        name = "EP-sweep-log",
        setup = { world ->
            world.node("alice", 0x41)
            world.node("bob", 0x51)
            DmScripts.activate(world)
            DmScripts.establishBothWays(world, "alice", "bob")
            world["alice"].device.engine.setTimer(DmScripts.contact(world, "alice", "bob"), Timer.MIN_5)
            world.pump()
            world.passes()
        },
        steps = listOf(
            step("the first five-minute message reaches bob") { w ->
                w.notes.putIfAbsent(EP_LOG_MARK, w.bus.count)
                w.notes.putIfAbsent(EP_LOG_MEASURED, w["bob"].checkpointsMeasured)
                epLogDeliver(w, EP_LOG_FIRST)
            },
            step("past its deadline, both sides sweep it") { w -> epLogExpire(w) },
            step("the second five-minute message reaches bob") { w -> epLogDeliver(w, EP_LOG_SECOND) },
            step("past its deadline, both sides sweep it") { w -> epLogExpire(w) },
        ),
        finalChecks = { world ->
            for (text in listOf(EP_LOG_FIRST, EP_LOG_SECOND)) {
                if (world.notes["arrived-$text"] != true) {
                    dmViolation("EP-sweep-log: '$text' never reached bob, so its expiry proved nothing")
                }
                if (text in DmScripts.inboundTexts(world, "bob")) {
                    dmViolation("EP-sweep-log: '$text' is still at bob after its deadline and a sweep")
                }
            }
            val measured = world["bob"].checkpointsMeasured - (world.notes[EP_LOG_MEASURED] as Int)
            if (measured < 2) {
                dmViolation("EP-sweep-log: bob measured $measured checkpoints after the mark, so the clause was not reached twice")
            }
        },
        liveness = "alice" to "bob",
        noLoss = true,
        declaredLoss = { setOf(EP_LOG_FIRST, EP_LOG_SECOND) },
    )

    /** One of EP-sweep-log's messages: written if no row of it exists, then carried to bob with no clock advance. */
    private fun epLogDeliver(w: DmCrashWorld, text: String) {
        if (DmScripts.outgoingState(w, "alice", text) == null && w.notes["arrived-$text"] != true) {
            w["alice"].device.engine.send(DmScripts.contact(w, "alice", "bob"), text, null)
        }
        w.pump()
        w.passes()
        w.pump()
        w.passes()
        if (text in DmScripts.inboundTexts(w, "bob")) w.notes["arrived-$text"] = true
    }

    /** Past the unread deadline (`consume + bucket + 1 h`, §10.3) and the sender's, then a pass on each side. */
    private fun epLogExpire(w: DmCrashWorld) {
        w.advanceBy(2 * DmWorld.HOUR)
        w.pump()
        w.passes()
    }

    /**
     * **EP — a clock stepped back one day does not delay deletion** (§10.9 item 4, R-T7, §10.3;
     * §15.5 EP, "a clock step back"; built by §22.38).
     *
     * alice and bob in pair mode with a five-minute timer. bob's device clock steps back one day
     * after his sweeps have raised the expiry clock (`dm_self.expiry_clock_minute`, R-T7) to the
     * true time. alice writes; bob's RECV stamps the unread cap from **his** clock —
     * `min(E, consume + bucket + 1 h)`, consume being the stepped-back arrival — so the row's
     * `delete_at_minute` lies **between** his wall clock and the expiry clock he already reached.
     * R-T7 measures every deadline against `now_e = max(wall, expiry_clock_minute)`, so the sweep
     * that follows the RECV deletes it; an engine that measured against the wall clock would keep
     * it for the hour the wall needs to catch up — mutant ME-17. The check reads the expiry clock
     * **raw**, so it is the true `now_e` whatever the engine read. §22.27 item 8 thought this case
     * needed the model relay's own clock (a relay expiry in the recipient's past); the consume term
     * of the cap puts the deadline there on its own, and the relay is left as it is (§22.38).
     *
     * After the check bob's clock is corrected, so the liveness probes carry ordinary deadlines.
     *
     * **Checked in the steps** (a crash in one leaves the next to take the message, sweep and check
     * again, with bob still a day behind): after bob's passes, no message of his has a
     * `delete_at_minute` at or before the true `now_e`. **Fault-free:** bob's clock was stepped
     * back after his expiry clock reached the true time, and the message reached him (a `dm_seen`
     * tag was written) and is gone. **Oracles:** no-loss with the message declared (it expires on
     * arrival by design), liveness alice ↔ bob, nothing owed.
     */
    fun epClockSteppedBackDoesNotDelayDeletion(): DmScenario = DmScenario(
        name = "EP-clock-back",
        setup = { world ->
            world.node("alice", 0x41)
            world.node("bob", 0x51)
            DmScripts.activate(world)
            DmScripts.establishBothWays(world, "alice", "bob")
            world["alice"].device.engine.setTimer(DmScripts.contact(world, "alice", "bob"), Timer.MIN_5)
            world.pump()
            world.passes()
            world.notes[EP_CLOCK_SEEN] = rawCount(world, "bob", "SELECT count(*) FROM dm_seen")
        },
        steps = listOf(
            step("bob's clock steps back one day") { w ->
                w.notes.putIfAbsent(EP_CLOCK_MARK, w.bus.count)
                epClockStepBack(w)
            },
            step("alice's five-minute message reaches bob, and bob sweeps") { w ->
                epClockStepBack(w)
                epClockDeliverAndCheck(w)
            },
            step("bob's passes once more, and the check again") { w ->
                epClockStepBack(w)
                epClockDeliverAndCheck(w)
            },
            step("bob's clock is corrected") { w ->
                if (w.notes[EP_CLOCK_BACK] == true && w.notes[EP_CLOCK_CORRECTED] != true) {
                    w["bob"].clock.now += DmWorld.DAY
                    w.notes[EP_CLOCK_CORRECTED] = true
                }
            },
        ),
        finalChecks = { world ->
            if (world.notes[EP_CLOCK_AHEAD] != true) {
                dmViolation("EP-clock-back: bob's expiry clock had not reached the true time when his clock stepped back")
            }
            val seen = rawCount(world, "bob", "SELECT count(*) FROM dm_seen") - (world.notes[EP_CLOCK_SEEN] as Long)
            if (seen < 1L) dmViolation("EP-clock-back: the message never reached bob, so its deletion proved nothing")
            if (EP_CLOCK_TEXT in DmScripts.inboundTexts(world, "bob")) {
                dmViolation("EP-clock-back: the message is still at bob")
            }
        },
        liveness = "alice" to "bob",
        noLoss = true,
        declaredLoss = { setOf(EP_CLOCK_TEXT) },
    )

    /** bob's clock one day back, once, after checking his expiry clock stands at the true time. */
    private fun epClockStepBack(w: DmCrashWorld) {
        if (w.notes[EP_CLOCK_BACK] == true) return
        val trueMinute = DmTime.floorMinute(w["bob"].clock.now)
        var stored = 0L
        w["bob"].raw.query("SELECT expiry_clock_minute FROM dm_self WHERE id = 1") { stored = it.long(0) }
        w.notes[EP_CLOCK_AHEAD] = stored >= trueMinute - DmWorld.HOUR
        w["bob"].clock.now -= DmWorld.DAY
        w.notes[EP_CLOCK_BACK] = true
    }

    /** The message, written if missing and carried with no clock advance; then bob's passes and the check. */
    private fun epClockDeliverAndCheck(w: DmCrashWorld) {
        if (DmScripts.outgoingState(w, "alice", EP_CLOCK_TEXT) == null && w.notes[EP_CLOCK_SENT] != true) {
            w["alice"].device.engine.send(DmScripts.contact(w, "alice", "bob"), EP_CLOCK_TEXT, null)
            w.notes[EP_CLOCK_SENT] = true
        }
        w.pump()
        w.passes()
        w.pump()
        w.passes()
        var stored = 0L
        w["bob"].raw.query("SELECT expiry_clock_minute FROM dm_self WHERE id = 1") { stored = it.long(0) }
        val nowE = maxOf(DmTime.floorMinute(w["bob"].clock.now), stored)
        val late = rawCount(
            w, "bob",
            "SELECT count(*) FROM dm_message WHERE delete_at_minute IS NOT NULL AND delete_at_minute <= ?",
            listOf(nowE),
        )
        if (late != 0L) {
            dmViolation("EP-clock-back: bob kept $late messages past their delete_at_minute on the expiry clock after SWEEP (R-T7, §10.9 item 4)")
        }
    }

    /**
     * **RO-prune — a skipped key is erased at `FRESH + 2σ`** (§7.7 point 4, V-15; the T34 age case in
     * a crash world; design §22.38).
     *
     * alice writes [RO_PRUNE_LOST] into a relay that holds it past its thirty-day TTL — stored, alice
     * told so, and expired unserved: a declared loss — and then [RO_PRUNE_NEXT], which arrives. bob
     * decrypts it one chain index ahead, after §7.7 point 2's gap hold, and his session keeps the
     * skipped key of the lost message, its first-seen day in the sidecar. Then about fifty days of
     * sweeps pass: on day forty-nine the key is still held — recorded, so the case shows that the key
     * it is about exists — and on day fifty-two SWEEP must have erased it. What holds it to that are two standing
     * clauses: the age bound after the runner's last pass (`DmStructuralInvariants.skippedKeysPruned`)
     * and the sidecar's projection at every check (`DmStructuralInvariants.sessionStates`).
     *
     * **Every later step first clears the relay's hold, and the first of them finishes what a crash
     * cut short** — a store, a fetch, the gap hold — in five rounds, inside every message's
     * freshness, as a device that is online would. The enumeration found why: a crash at `ro-next`'s
     * commit left its delivery to the end of the run, fifty-two days on, where R9 rightly refused it
     * and the no-loss oracle charged the loss to the engine. One crash per run, so only the first
     * step can leave anything undone. The sends are not redone (S10's rule): a run whose crash lost
     * [RO_PRUNE_NEXT] skips no key, and the clauses then hold trivially; the fault-free run is what
     * shows the key existed.
     *
     * **Mutants.** MC-30, both halves: the prune not done (a `DmEnvelopes` decorator) and the sidecar
     * kept as an insert-only log (a native hook); each window starts at [RO_PRUNE_MARK], the
     * day-fifty-two step, whose sweep is the prune.
     *
     * **The oracles, all three on.** No-loss with [RO_PRUNE_LOST] declared once it was written into
     * the hold; liveness alice ↔ bob; nothing owed.
     */
    fun roPruneASkippedKeyAtItsAgeBound(): DmScenario = DmScenario(
        name = "RO-prune",
        liveness = "alice" to "bob",
        noLoss = true,
        declaredLoss = { world -> if (world.notes[RO_PRUNE_HELD] == true) setOf(RO_PRUNE_LOST) else emptySet() },
        setup = { world ->
            world.node("alice", 0x41)
            world.node("bob", 0x51)
            DmScripts.activate(world)
            DmScripts.establishBothWays(world, "alice", "bob")
            // The timer off: the key is about fifty-two days, and under the default seven-day timer
            // every message of the conversation would be swept long before (RS2 does the same).
            world["alice"].device.engine.setTimer(DmScripts.contact(world, "alice", "bob"), Timer.OFF)
            settle(world)
        },
        steps = buildList {
            add(
                step("alice writes into a relay that holds it past its TTL, then a message that arrives") { w ->
                    w.relay.releaseNotBefore = mapOf("alice" to now(w) + RO_PRUNE_HOLD)
                    // Declared before the call (§22.19 item 9), as RS2 declares its lost message.
                    w.notes[RO_PRUNE_HELD] = true
                    w["alice"].device.engine.send(DmScripts.contact(w, "alice", "bob"), RO_PRUNE_LOST, null)
                    round(w)
                    w.relay.releaseNotBefore = emptyMap()
                    w["alice"].device.engine.send(DmScripts.contact(w, "alice", "bob"), RO_PRUNE_NEXT, null)
                    // §7.7 point 2's gap hold: the held message never arrives, so this one waits.
                    repeat(RS2_GAP_ROUNDS) { round(w) }
                },
            )
            for (day in RO_PRUNE_DAYS) {
                add(
                    step("day $day of the skipped key") { w ->
                        w.relay.releaseNotBefore = emptyMap()
                        // What a crash cut short in the first step — a store, a fetch, the gap hold
                        // — is finished here, inside every message's freshness, as a device that is
                        // online finishes it. Only here: one crash per run, and a crash in a later
                        // step leaves nothing of the first one undone.
                        if (day == RO_PRUNE_DAYS.first()) repeat(RS2_GAP_ROUNDS) { round(w) }
                        w.notes.putIfAbsent(RO_PRUNE_START, now(w))
                        advanceTo(w, (w.notes[RO_PRUNE_START] as Long) + day * DmWorld.DAY)
                        w.passes()
                        if (day == RO_PRUNE_DAYS.last()) {
                            w.notes[RO_PRUNE_HELD_AT_49] = DmSessionStates.all(w["bob"], "RO-prune day $day")
                                .flatMap { s -> s.pickleKeys.map { it to s.sidecar[it] } }
                        }
                    },
                )
            }
            add(
                step("day 52: the key is past FRESH + 2σ") { w ->
                    w.relay.releaseNotBefore = emptyMap()
                    w.notes.putIfAbsent(RO_PRUNE_START, now(w))
                    w.notes.putIfAbsent(RO_PRUNE_MARK, w.bus.count)
                    advanceTo(w, (w.notes[RO_PRUNE_START] as Long) + 52 * DmWorld.DAY)
                    w.passes()
                },
            )
        },
        finalChecks = { world ->
            if (RO_PRUNE_NEXT !in DmScripts.inboundTexts(world, "bob")) {
                dmViolation("RO-prune fault-free: bob never rendered $RO_PRUNE_NEXT, so no key was skipped")
            }
            @Suppress("UNCHECKED_CAST")
            val held = world.notes[RO_PRUNE_HELD_AT_49] as? List<Pair<DmSessionStates.Key, Long?>>
                ?: dmViolation("RO-prune fault-free: day forty-nine was never reached")
            // Exactly the one key the lost message left, with its first-seen day: without it the
            // age clause had nothing to prune and proved nothing.
            if (held.size != 1 || held.single().second == null) {
                dmViolation("RO-prune fault-free: on day forty-nine bob held $held, not exactly the one skipped key with its day")
            }
        },
    )

    /**
     * **EP — a five-minute message stored after its own expiry** (§21.10 point 2, §10.6, §7.5
     * "Retained blob", T25; §15.5 EP, "HIGH mode 5-minute store after expiry"; design §22.38).
     *
     * §15.5 builds the case in HIGH mode, where a `not_before` past the message's own expiry is what
     * holds the op back. Every crash world is STANDARD (`DmDevice` fixes the mode), so here the same
     * shape comes from **no network**: alice's device is offline ([ModelDmRelay.offline]) when she
     * writes, so her op is still `pending` — the ciphertext in Phase 7's row, the retained blob in
     * `dm_outbound_op` — when her SWEEP deletes the message at its five-minute expiry. What must
     * happen is §21.10 point 2's: the message, its item, its op and the op's retained blob go
     * together, by the cascade, and **nothing cancels the op** — "ops run to their outcome or
     * deadline", SWEEP never calls `Outbox.cancel` (ME-21) — so once alice is back online the op is
     * stored, its outcome lands on a message that no longer exists (`OutcomeStep`: "the message
     * expired and was swept meanwhile … the release stands"), and bob receives it, unread, capped
     * from his own arrival (C-11).
     *
     * **Every step first does what a crash cut short in the one before** — the send (a user retry,
     * never once the clock has passed the message's expiry), the clock past its expiry, alice's
     * sweep — and the last step takes alice's device off the offline list before it raises a single
     * event, so no crash leaves her offline for the run's tail. One crash per run, so no step is
     * cut short twice.
     *
     * **Checked at every check of every run:** the standing T25 clause
     * [DmStructuralInvariants.retainedBlobs]. **Checked in every run:** once alice's op for the
     * message existed, bob renders the message at the end — the op ran to its outcome after its
     * message was gone. **Fault-free:** alice's SWEEP deleted the message while its op was still
     * pending, and the op's late outcome was released. **Oracles:** no-loss (alice's row goes by her
     * own timer, so she calls nothing sent that bob must render; bob's copy is the check above),
     * liveness alice ↔ bob, nothing owed.
     *
     * **Mutant ME-20** (the retained blob survives its message's deletion): a rewrite of the schema
     * of alice's device — which migrates on the bus in the setup for it ([DmCrashWorld.node]) —
     * whose window is the SWEEP transaction that deletes the message after [EP_LATE_MARK].
     */
    fun epStoreAfterExpiry(): DmScenario = DmScenario(
        name = "EP-store-after-expiry",
        setup = { world ->
            world.node("alice", 0x41, migrateOnTheBus = true)
            world.node("bob", 0x51)
            DmScripts.activate(world)
            DmScripts.establishBothWays(world, "alice", "bob")
            world["alice"].device.engine.setTimer(DmScripts.contact(world, "alice", "bob"), Timer.MIN_5)
            world.pump()
            world.passes()
        },
        steps = listOf(
            step("alice's device goes offline, and she writes a five-minute message") { w ->
                w.relay.offline = setOf("alice")
                epLateWrite(w)
            },
            step("past its expiry, alice's SWEEP runs with no network") { w ->
                w.notes.putIfAbsent(EP_LATE_MARK, w.bus.count)
                epLateWrite(w)
                epLateExpire(w)
            },
            step("alice is back online: her op is stored, its outcome lands on a deleted message, bob receives it") { w ->
                // First, before any event: no crash can leave alice offline for the run's tail.
                w.relay.offline = emptySet()
                epLateWrite(w)
                // What a crash cut short in the step before — the clock, the sweep — before the
                // first pump, so still with no network.
                epLateExpire(w)
                w.pump()
                w.passes()
                w.pump()
                w.passes()
            },
        ),
        alwaysChecks = { world ->
            if (world.notes[EP_LATE_WRITTEN] == true && EP_LATE !in DmScripts.inboundTexts(world, "bob")) {
                dmViolation(
                    "EP-store-after-expiry: alice's op for '$EP_LATE' existed and bob never received it — an op " +
                        "runs to its outcome after its message is deleted (§21.10 point 2)",
                )
            }
        },
        finalChecks = { world ->
            if (world.notes[EP_LATE_IN_FLIGHT] != true) {
                dmViolation(
                    "EP-store-after-expiry fault-free: alice's SWEEP did not delete the message while its op was " +
                        "still pending, so nothing was in flight past its deletion",
                )
            }
            val op = world.notes[EP_LATE_OP] as ByteArray
            val released = rawCount(
                world, "alice", "SELECT count(*) FROM outbox_op WHERE operation_id = ? AND released = 1", listOf(op),
            )
            if (released != 1L) {
                dmViolation("EP-store-after-expiry fault-free: the late outcome of alice's op was not released")
            }
        },
        liveness = "alice" to "bob",
        noLoss = true,
    )

    /**
     * [EP_LATE], written if no row of it exists and the clock has not yet passed its expiry — a user
     * retry of a send a crash lost — and its op recorded.
     */
    private fun epLateWrite(w: DmCrashWorld) {
        if (w.notes[EP_LATE_EXPIRED] != true && DmScripts.outgoingState(w, "alice", EP_LATE) == null) {
            w["alice"].device.engine.send(DmScripts.contact(w, "alice", "bob"), EP_LATE, null)
        }
        if (w.notes[EP_LATE_OP] != null) return
        val id = w["alice"].device.engine.conversation(DmScripts.contact(w, "alice", "bob"), 50, null)
            .firstOrNull { it.outgoing && it.text == EP_LATE }?.id?.toByteArray() ?: return
        var op: ByteArray? = null
        w["alice"].raw.query(
            "SELECT o.operation_id FROM dm_outbound_op o JOIN dm_outbound_item i ON i.item_id = o.item_id " +
                "WHERE i.message_ref = ?",
            listOf(id),
        ) { op = it.blob(0) }
        w.notes[EP_LATE_ID] = id
        w.notes[EP_LATE_OP] = op ?: return
        w.notes[EP_LATE_WRITTEN] = true
    }

    /**
     * The clock past [EP_LATE]'s expiry, once — `ceil_minute(send + 5 min)` is at most six minutes
     * on — then a pass on each side, and whether alice's sweep deleted the message while its op was
     * still pending with its ciphertext.
     */
    private fun epLateExpire(w: DmCrashWorld) {
        if (w.notes[EP_LATE_EXPIRED] != true) {
            w.advanceBy(6 * DmWorld.MINUTE)
            w.notes[EP_LATE_EXPIRED] = true
        }
        w.passes()
        val id = w.notes[EP_LATE_ID] as? ByteArray ?: return
        val op = w.notes[EP_LATE_OP] as ByteArray
        val gone = rawCount(w, "alice", "SELECT count(*) FROM dm_message WHERE message_id = ?", listOf(id)) == 0L
        val pending = rawCount(
            w, "alice",
            "SELECT count(*) FROM outbox_op WHERE operation_id = ? AND outcome = 'pending' AND ciphertext IS NOT NULL",
            listOf(op),
        ) == 1L
        if (gone && pending) w.notes[EP_LATE_IN_FLIGHT] = true
    }

    /**
     * **EP — a sender clock five days ahead does not extend the unread deadline** (C-11, §10.3;
     * §15.5 EP, "a sender clock 5 days ahead does not extend the unread deadline (ME-19)"; design
     * §22.38).
     *
     * alice and bob in pair mode with a five-minute timer, from the first hour of an ISO week. alice's
     * clock runs five days ahead when she writes, and what bob sees of a sender's clock is exactly
     * one thing: the author minute her content carries, five days in his future — inside R9's `2σ`
     * (six days), and still the week of the pair key that seals it, so binding B1 takes it
     * ([AheadDatedL0] dates it, as RP7's [OldDatedL0] dates its L0 back). Every device's clock stays
     * the world's on purpose: the model relay has no clock of its own and measures a blob's TTL on
     * the fetching device's, so a device five days ahead would find the other side's one-hour blobs
     * expired — the first version of this case moved alice's clock and lost bob's liveness probe
     * that way, a harness artifact and not the engine's. bob's unread cap must be
     * `min(E, consume + bucket + 1 h)` from **his** arrival (§10.3, C-11): content says nothing
     * about how long a message may be kept. An engine that took `author + bucket` would keep the
     * unread message five days longer — mutant ME-19.
     *
     * **Checked in the steps and at the end of every run** ([capsFromTheRecipientsClock]): no
     * incoming message at bob carries an unread cap later than his own `now_e` plus its bucket, an
     * hour and a minute. **Every step first finishes what a crash cut short** — the send (a user
     * retry, never once the clock has moved), its delivery — and only the last moves the clock.
     * **Fault-free:** the message was dated five days ahead, it reached bob, and the sweep past
     * `consume + bucket + 1 h` deleted it. **Oracles:** no-loss with the message declared (it
     * expires unread by design), liveness alice ↔ bob, nothing owed.
     *
     * **Mutant ME-19**: a rewrite of RECV's incoming insert whose cap is `author + bucket + 1 h`; its
     * window is bob's RECV of the message after [EP_AHEAD_MARK].
     */
    fun epSenderClockAhead(): DmScenario = DmScenario(
        name = "EP-sender-ahead",
        setup = { world ->
            world.node("alice", 0x41)
            world.node("bob", 0x51)
            DmScripts.activate(world)
            DmScripts.establishBothWays(world, "alice", "bob")
            world["alice"].device.engine.setTimer(DmScripts.contact(world, "alice", "bob"), Timer.MIN_5)
            settle(world)
            // The first hour of the next ISO week, so that five days ahead is the same week (B1).
            advanceTo(world, DmTime.weekStart(DmTime.week(now(world)) + 1) + DmWorld.HOUR)
            settle(world)
            val alice = world["alice"]
            alice.decorate = { real -> AheadDatedL0(real, EP_AHEAD.toByteArray(Charsets.UTF_8), world) }
            alice.reboot()
            DmStructuralInvariants.check(alice, "EP-sender-ahead setup reboot")
        },
        steps = listOf(
            step("alice writes with her clock five days ahead; the message reaches bob") { w ->
                w.notes.putIfAbsent(EP_AHEAD_MARK, w.bus.count)
                epAheadDeliver(w)
            },
            step("what a crash cut short: the message reaches bob") { w -> epAheadDeliver(w) },
            step("past bob's own unread cap, bob sweeps") { w ->
                if (w.notes[EP_AHEAD_PAST] != true) {
                    w.advanceBy(2 * DmWorld.HOUR + DmWorld.MINUTE)
                    w.notes[EP_AHEAD_PAST] = true
                }
                w.pump()
                w.passes()
                capsFromTheRecipientsClock(w, "bob")
            },
        ),
        alwaysChecks = { world -> capsFromTheRecipientsClock(world, "bob") },
        finalChecks = { world ->
            val dated = world.notes[EP_AHEAD_DATED] as? Long
                ?: dmViolation("EP-sender-ahead fault-free: the decorator never dated the message")
            val sent = world.notes[EP_AHEAD_SENT_AT] as Long
            if (dated - sent != EP_AHEAD_SECONDS) {
                dmViolation("EP-sender-ahead fault-free: the message was dated ${dated - sent} s ahead, not five days")
            }
            if (world.notes["arrived-$EP_AHEAD"] != true) dmViolation("EP-sender-ahead: '$EP_AHEAD' never reached bob")
            if (EP_AHEAD in DmScripts.inboundTexts(world, "bob")) {
                dmViolation("EP-sender-ahead: '$EP_AHEAD' is still at bob past his own unread cap and a sweep")
            }
        },
        liveness = "alice" to "bob",
        noLoss = true,
        declaredLoss = { setOf(EP_AHEAD) },
    )

    /**
     * alice's device with its clock five days ahead, as bob sees it: the author minute of the
     * message whose body is [text], [EP_AHEAD_SECONDS] later than her own. It changes one argument
     * of one call, like RP7's [OldDatedL0], and records the minutes for the fault-free checks.
     */
    private class AheadDatedL0(
        private val real: DmEnvelopes,
        private val text: ByteArray,
        private val world: DmCrashWorld,
    ) : DmEnvelopes by real {
        override fun encodeContent(
            kind: DmContent.Kind,
            messageId: ByteArray,
            authorMinute: Long,
            minuteIndex: Int,
            timerCode: Int,
            timerVersion: Long,
            quoteRef: ByteArray?,
            body: ByteArray,
            contactId: ByteArray,
            offerRootGen: Int,
            offerEnv: ByteArray,
            revocation: ByteArray,
            sessionReset: Boolean,
            pqKey: DmContent.PqKeyCandidate?,
            pqKeyFirst: Boolean,
        ): DmContent.Encoded {
            var minute = authorMinute
            if (kind == DmContent.Kind.TEXT && body.contentEquals(text)) {
                minute = authorMinute + EP_AHEAD_SECONDS / DmTime.MINUTE
                world.notes[EP_AHEAD_SENT_AT] = authorMinute * DmTime.MINUTE
                world.notes[EP_AHEAD_DATED] = minute * DmTime.MINUTE
            }
            return real.encodeContent(
                kind, messageId, minute, minuteIndex, timerCode, timerVersion, quoteRef, body,
                contactId, offerRootGen, offerEnv, revocation, sessionReset, pqKey, pqKeyFirst,
            )
        }
    }

    /** [EP_AHEAD], written if no row of it exists and the clock has not moved, carried to bob, and bob's caps checked. */
    private fun epAheadDeliver(w: DmCrashWorld) {
        if (w.notes[EP_AHEAD_PAST] != true && w.notes["arrived-$EP_AHEAD"] != true &&
            DmScripts.outgoingState(w, "alice", EP_AHEAD) == null
        ) {
            w["alice"].device.engine.send(DmScripts.contact(w, "alice", "bob"), EP_AHEAD, null)
        }
        w.pump()
        w.passes()
        w.pump()
        w.passes()
        if (EP_AHEAD in DmScripts.inboundTexts(w, "bob")) w.notes["arrived-$EP_AHEAD"] = true
        capsFromTheRecipientsClock(w, "bob")
    }

    /**
     * No incoming message at [node] carries an unread cap later than [node]'s own `now_e` plus its
     * bucket, an hour and a minute (C-11, §10.3): the cap is `ceil_minute(min(E, consume + bucket +
     * 1 h))` with `consume` an arrival on the recipient's clock, never later than now, and `now_e`
     * is at least the wall clock's minute.
     */
    private fun capsFromTheRecipientsClock(w: DmCrashWorld, node: String) {
        val nowE = expiryClockOf(w, node)
        w[node].raw.query(
            "SELECT timer_code, unread_deadline_minute FROM dm_message " +
                "WHERE direction = 'in' AND unread_deadline_minute IS NOT NULL",
        ) { r ->
            val bound = nowE + DmTimers.bucketOf(r.long(0).toInt()).seconds.toLong() + DmWorld.HOUR + DmWorld.MINUTE
            if (r.long(1) > bound) {
                dmViolation(
                    "EP-sender-ahead: $node holds an unread message capped at ${r.long(1)}, past its own now_e $nowE " +
                        "plus its bucket, an hour and a minute — the cap came from the sender's clock (C-11, §10.3)",
                )
            }
        }
    }

    /**
     * **EP — the recipient's countdown starts at the first display, and a stale `markDisplayed`
     * resurrects nothing** (§10.3, ADR-27 point 9, §21.10 point 6, R-T7; §15.5 EP, "a stale
     * `markDisplayed`" and the displayed and unread paths of §10.9; design §22.38).
     *
     * alice and bob in pair mode with a five-minute timer; alice writes two messages and both reach
     * bob unread, his screen holding their ids. bob's screen shows [EP_SHOWN] at once, and its
     * countdown starts there: five minutes from the display. [EP_STALE] he leaves unread, and ten
     * minutes on — past its own five minutes — it must **still be there**, because an unread
     * message is kept to its unread cap `consume + bucket + 1 h` and no countdown has started
     * (mutant ME-7, "recipient countdown at receive", would have deleted it at five minutes). Then
     * the clock passes that cap before bob's device runs a pass — a phone frozen for two hours — and
     * the screen marks the held id displayed: DISPLAY must ignore it (its read carries the §10.7
     * point 4 filter against `now_e`), count nothing, and leave the row to the next SWEEP, which
     * deletes it. A DISPLAY that found it would start a five-minute countdown after the deadline the
     * row had already passed: a message resurrected past its bound.
     *
     * **Checked in the steps and at the end of every run** ([displayedAfterItsCap]): no incoming
     * message at bob was displayed after its unread cap — a read row's countdown, its
     * `expire_at_minute` less its own timer, starts no later than its cap. A display at `t` before
     * the cap writes `ceil_minute(t + timer)`, whose countdown starts at or before the cap, so the
     * bound is exact. **Checked in the step ten minutes on:** the unread message that arrived is
     * still at bob. **Every step first finishes what a crash cut short** — the sends (user retries,
     * never once the clock has moved), their delivery. **Fault-free:** the timely display counted
     * one and its message is gone after its five minutes, the stale display counted none, and both
     * messages are gone at the end. **Oracles:** no-loss with both texts declared (they expire at bob
     * by design), liveness alice ↔ bob, nothing owed.
     *
     * **Mutant ME-7**: a rewrite of RECV's incoming insert that starts the countdown at receipt; its
     * window is bob's first RECV after [EP_STALE_MARK].
     */
    fun epStaleDisplayResurrectsNothing(): DmScenario = DmScenario(
        name = "EP-stale-display",
        setup = { world ->
            world.node("alice", 0x41)
            world.node("bob", 0x51)
            DmScripts.activate(world)
            DmScripts.establishBothWays(world, "alice", "bob")
            world["alice"].device.engine.setTimer(DmScripts.contact(world, "alice", "bob"), Timer.MIN_5)
            world.pump()
            world.passes()
        },
        steps = listOf(
            step("alice writes two five-minute messages; both reach bob unread, and his screen holds their ids") { w ->
                w.notes.putIfAbsent(EP_STALE_MARK, w.bus.count)
                epStaleDeliver(w)
            },
            step("bob's screen shows the first at once") { w ->
                epStaleDeliver(w)
                val id = w.notes["id-$EP_SHOWN"] as? org.ghost.messaging.api.MessageId
                if (id != null && w.notes[EP_SHOWN_COUNT] == null) {
                    w.notes[EP_SHOWN_COUNT] = w["bob"].device.engine.markDisplayed(listOf(id))
                }
                displayedAfterItsCap(w, "bob")
            },
            step("ten minutes on, past both timers: the unread one is still there") { w ->
                if (w.notes[EP_STALE_TEN] != true) {
                    w.advanceBy(10 * DmWorld.MINUTE)
                    w.notes[EP_STALE_TEN] = true
                }
                w.passes()
                if (w.notes["arrived-$EP_STALE"] == true && EP_STALE !in DmScripts.inboundTexts(w, "bob")) {
                    dmViolation(
                        "EP-stale-display: bob's unread five-minute message is gone before its unread cap — " +
                            "the recipient's countdown started before its display (§10.3, ADR-27 point 9)",
                    )
                }
                displayedAfterItsCap(w, "bob")
            },
            step("the clock passes the unread cap before bob's device runs a pass; the screen marks the held id displayed") { w ->
                if (w.notes[EP_STALE_PAST] != true) {
                    val cap = w.notes["cap-$EP_STALE"] as? Long
                    if (cap != null) advanceTo(w, cap + DmWorld.MINUTE) else w.advanceBy(2 * DmWorld.HOUR + DmWorld.MINUTE)
                    w.notes[EP_STALE_PAST] = true
                }
                val id = w.notes["id-$EP_STALE"] as? org.ghost.messaging.api.MessageId
                if (id != null && w.notes[EP_STALE_COUNT] == null) {
                    w.notes[EP_STALE_COUNT] = w["bob"].device.engine.markDisplayed(listOf(id))
                }
                displayedAfterItsCap(w, "bob")
            },
            step("bob's device sweeps") { w ->
                w.pump()
                w.passes()
                displayedAfterItsCap(w, "bob")
            },
        ),
        alwaysChecks = { world -> displayedAfterItsCap(world, "bob") },
        finalChecks = { world ->
            if (world.notes[EP_SHOWN_COUNT] != 1) {
                dmViolation("EP-stale-display fault-free: the timely display counted ${world.notes[EP_SHOWN_COUNT]}, not 1")
            }
            if (world.notes[EP_STALE_COUNT] != 0) {
                dmViolation(
                    "EP-stale-display fault-free: the stale display counted ${world.notes[EP_STALE_COUNT]} messages, " +
                        "not 0 (§21.10 point 6)",
                )
            }
            for (text in listOf(EP_SHOWN, EP_STALE)) {
                if (world.notes["arrived-$text"] != true) dmViolation("EP-stale-display: '$text' never reached bob")
                if (text in DmScripts.inboundTexts(world, "bob")) {
                    dmViolation("EP-stale-display: '$text' is still at bob past its deadline and a sweep")
                }
            }
        },
        liveness = "alice" to "bob",
        noLoss = true,
        declaredLoss = { setOf(EP_SHOWN, EP_STALE) },
    )

    /**
     * EP-stale-display's two messages: each written if no row of it exists and the clock has not
     * moved, carried to bob with no clock advance, and recorded — its id as bob's screen holds it,
     * its unread cap read raw — once it is there.
     */
    private fun epStaleDeliver(w: DmCrashWorld) {
        for (text in listOf(EP_SHOWN, EP_STALE)) {
            if (w.notes[EP_STALE_TEN] != true && w.notes["arrived-$text"] != true &&
                DmScripts.outgoingState(w, "alice", text) == null
            ) {
                w["alice"].device.engine.send(DmScripts.contact(w, "alice", "bob"), text, null)
            }
        }
        w.pump()
        w.passes()
        w.pump()
        w.passes()
        val contact = DmScripts.contact(w, "bob", "alice")
        for (text in listOf(EP_SHOWN, EP_STALE)) {
            if (w.notes["id-$text"] != null) continue
            val item = w["bob"].device.engine.conversation(contact, 50, null)
                .firstOrNull { !it.outgoing && it.text == text } ?: continue
            var cap: Long? = null
            w["bob"].raw.query(
                "SELECT unread_deadline_minute FROM dm_message WHERE message_id = ?",
                listOf(item.id.toByteArray()),
            ) { cap = it.long(0) }
            w.notes["id-$text"] = item.id
            w.notes["cap-$text"] = cap ?: continue
            w.notes["arrived-$text"] = true
        }
    }

    /**
     * No incoming message at [node] was displayed after its unread cap (§21.10 point 6): a `read`
     * row's countdown — its `expire_at_minute` less its own timer — starts no later than its
     * `unread_deadline_minute`.
     */
    private fun displayedAfterItsCap(w: DmCrashWorld, node: String) {
        w[node].raw.query(
            "SELECT timer_code, expire_at_minute, unread_deadline_minute FROM dm_message " +
                "WHERE direction = 'in' AND state = 'read' AND expire_at_minute IS NOT NULL " +
                "AND unread_deadline_minute IS NOT NULL",
        ) { r ->
            val started = r.long(1) - DmTimers.timerSeconds(r.long(0).toInt())
            if (started > r.long(2)) {
                dmViolation(
                    "EP-stale-display: $node displayed a message after its unread cap — its countdown starts at " +
                        "$started, past the cap ${r.long(2)} (§21.10 point 6)",
                )
            }
        }
    }

    fun all(): List<DmScenario> = listOf(
        rp6ReEncryptionAfterAWronglyReportedFailure(),
        rp9FlippedBytesDoNotOpenAndAnswerNothing(),
        cbRejectedRequestStaysRejected(),
        epExpiredRowsAreNotReadable(),
        kc12ARequestSendingTwoIdentities(),
        rs2AClientOfflineSixtyDays(),
        rp7AnOldL0ResealedUnderALaterWeekKey(),
        rp5PreKeyReplayAcrossARestart(),
        rp4FirstFlightOfAResetSession(),
        rp11APreKeyMessageOfAReplacedSession(),
        kc5bAGenuineBindingReplayed(),
        epSweepTruncatesTheLog(),
        epClockSteppedBackDoesNotDelayDeletion(),
        roPruneASkippedKeyAtItsAgeBound(),
        epStoreAfterExpiry(),
        epSenderClockAhead(),
        epStaleDisplayResurrectsNothing(),
    )
}
