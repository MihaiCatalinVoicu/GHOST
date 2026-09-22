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
 * Three are here, each chosen because it is the **only** case that kills a mutant this slice
 * registers, and each is a case §15.5 names:
 *  - **RP6** "re-encryption after a wrongly reported FAILED" — the one path that reaches D3, and so
 *    the one that can detect MC-5;
 *  - the §12.3 rejected-request replay — the one that reaches D2b, and so MC-7′;
 *  - **EP** "a read path ignores expiry", the behavioural half of the DAO lint, and so ME-16.
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
     * message's own id, and it is the only thing between the recipient and a message rendered
     * twice.
     */
    fun rp6ReEncryptionAfterAWronglyReportedFailure(): DmScenario = DmScenario(
        name = "RP6",
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

    fun all(): List<DmScenario> = listOf(
        rp6ReEncryptionAfterAWronglyReportedFailure(),
        cbRejectedRequestStaysRejected(),
        epExpiredRowsAreNotReadable(),
    )
}
