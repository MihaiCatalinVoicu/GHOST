package org.ghost.messaging.harness

import org.ghost.messaging.DmWorld
import org.ghost.messaging.api.CardSource
import org.ghost.messaging.api.MessageState
import org.ghost.messaging.api.SendResult
import org.ghost.messaging.api.Timer

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
 * The rest of RO, RS, RP, KC, CB, RE, EP, OS and RK is not here. §22.15 lists them by sub-case.
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
     */
    fun rp6ReEncryptionAfterAWronglyReportedFailure(): DmScenario = DmScenario(
        name = "RP6",
        liveness = "alice" to "bob",
        noLoss = true,
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

    fun all(): List<DmScenario> = listOf(
        rp6ReEncryptionAfterAWronglyReportedFailure(),
        rp9FlippedBytesDoNotOpenAndAnswerNothing(),
        cbRejectedRequestStaysRejected(),
        epExpiredRowsAreNotReadable(),
    )
}
