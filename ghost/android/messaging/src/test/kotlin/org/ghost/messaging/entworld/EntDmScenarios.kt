package org.ghost.messaging.entworld

import org.ghost.entitlement.api.ActivationState
import org.ghost.entitlement.harness.EntClient
import org.ghost.entitlement.harness.EntScenario
import org.ghost.entitlement.harness.EntWorld
import org.ghost.entitlement.harness.inviteText
import org.ghost.messaging.api.AddContactResult
import org.ghost.messaging.api.CardSource
import org.ghost.messaging.api.MessageState
import org.ghost.messaging.api.SendResult
import org.ghost.messaging.api.TrustState
import org.ghost.sync.harness.CallKind
import org.ghost.sync.harness.ClientSpec
import org.ghost.sync.harness.EventKind
import org.ghost.sync.harness.World
import org.ghost.sync.harness.World.Companion.HOUR
import org.ghost.sync.harness.World.Companion.MINUTE
import org.ghost.sync.harness.foreground
import org.ghost.sync.harness.jobs

/**
 * A scenario of the entitlement world (§15.1 variant (b)): a Phase 8 [EntScenario] — so the
 * Phase 7 runner, its structural and quiescence invariants, and the entitlement engine's own
 * quiescence conditions, MS-6, the token accounting and the T3 canaries all apply — with two
 * clients, alice (the armed subject) and bob, each carrying the entitlement engine **and** the DM
 * layer ([EntDmWorld]). The world starts where every entitlement world starts: Friday of access
 * week 2975 at 08:00 UTC.
 *
 * This is the base SCN-E, JD8 and the OS suite build on (design §22.23): it owns the setup, the
 * trial activation through the real issuer lane every one of them needs, the read helpers and the
 * end checks, and nothing scenario-specific; the one-scan establishment of §12.2 as user actions
 * at scripted times is [EntDmConversation]'s.
 */
internal abstract class EntDmScenario(name: String) : EntScenario(name) {
    lateinit var dm: EntDmWorld
    lateinit var bob: EntClient
    lateinit var aliceDm: EntDmClient
    lateinit var bobDm: EntDmClient

    /** A DM world that does not settle should fail in hours of tail, not in the 31 days Phase 8 allows. */
    override val maxTailRounds: Int get() = 200

    /**
     * The four slot relays, the entitlement world over them, alice (armed) and bob (unarmed), each
     * with its relay directory, its entitlement engine and its DM layer. [genesis]: the identities
     * exist already, so no trial runs and the K20 hook never fires — ACTIVATE then comes from
     * §21.12 point 2's resume at the first time-triggered pass (as `restored`, the side `DmActor`
     * takes when it cannot tell) — and the tokens have to come from somewhere else
     * (`EntClient.addTokens`, or a pack through the `ModelIssuer`).
     */
    protected fun twoDmClients(w: World, genesis: Boolean = false) {
        val relays = EntDmWorld.slotRelays(w)
        ent = EntWorld(w, relays, config())
        dm = EntDmWorld(w, ent)
        val a = subject(w, "alice")
        a.directory(*relays.toTypedArray())
        alice = ent.attach(a, genesis)
        aliceDm = dm.attach(alice, ALICE_BRANCH)
        val b = w.client(ClientSpec("bob", armed = false))
        b.directory(*relays.toTypedArray())
        bob = ent.attach(b, genesis)
        bobDm = dm.attach(bob, BOB_BRANCH)
    }

    /**
     * The trial activation of §8.3 through the real issuer lane: an invite of another identity (its
     * INVITE token minted with the test key — the inviter's purchase, not this client's), activated
     * in the foreground at [at]; `RedeemInvite` runs as a user issuer call, the tokens are the
     * `ModelIssuer`'s blind signatures finalized by the harness native layer, and the K20 hook runs
     * the DM layer's ACTIVATE. Retried in two later foregrounds when nothing started (a crash).
     */
    protected fun World.trial(ec: EntClient, label: String, at: Long) {
        val (text, _) = inviteText(ent, "$label|$seed")
        foreground(ec.c, at - MINUTE, at + 20 * MINUTE)
        at(at, "activate $label") { ec.e().activate(text) }
        for (t in listOf(at + 30 * MINUTE, at + 90 * MINUTE)) {
            foreground(ec.c, t - 5 * MINUTE, t + 15 * MINUTE)
            at(t, "$label activates again if nothing started") {
                if (ec.e().activationState() == ActivationState.NONE) ec.e().activate(text)
            }
        }
    }

    /** The inbound texts of every conversation of [dmc], oldest first. */
    fun inbound(dmc: EntDmClient): List<String> = dmc.read { d ->
        d.engine.contacts().flatMap { contact ->
            d.engine.conversation(contact.id, 200, null).reversed().filter { !it.outgoing }.mapNotNull { it.text }
        }
    }.orEmpty()

    /** The state of [dmc]'s outgoing message [text], or null. */
    fun outgoing(dmc: EntDmClient, text: String): MessageState? = dmc.read { d ->
        d.engine.contacts().asSequence().flatMap { d.engine.conversation(it.id, 200, null).asSequence() }
            .firstOrNull { it.outgoing && it.text == text }?.state
    }

    override fun extraQuiescence(w: World): List<String> = super.extraQuiescence(w) + dm.quiescenceProblems()

    /** The DM world's end checks, then Phase 8's and the test's outcome; the DM contexts close last. */
    override fun finalChecks(w: World) {
        try {
            dm.finalChecks()
            super.finalChecks(w)
        } finally {
            dm.close()
        }
    }

    companion object {
        const val ALICE_BRANCH = 0x41
        const val BOB_BRANCH = 0x51
    }
}

/**
 * **ENT-DM/conversation** — the proof that the entitlement world works end to end: a DM conversation
 * that proceeds only on capabilities the entitlement engine redeemed and keys the registration lane
 * registered.
 *
 * Both clients activate a trial in the foreground (alice at 1 min, bob at 3 min). From there nothing
 * is scripted but the user: periodic jobs every 15 minutes (background sessions and quiet runs,
 * as the production scheduler draws them, a foreground about once a day) carry the redeem lane, the
 * work lane and the read lane; the DM layer runs on the triggers `:app` wires. At 6 h alice scans
 * bob's card in person and writes; bob accepts the request and answers in a foreground at 8 h (again
 * at 9 h and 10 h if nothing arrived yet); alice writes once more at 11 h, after bob's answer. The
 * Phase 7 runner then drives the quiescence tail.
 *
 * [refuseBobRedemptions] is the control: the **same** world — the same trial, the same schedule,
 * the same user — in which every relay answers each of bob's `RedeemToken` calls `relay_unavailable`
 * before it reaches the redeem model, so bob never holds a capability. It cannot reach the Phase 7
 * quiescence (bob holds eligible tokens and a waiting need, which is exactly what the entitlement
 * liveness premise forbids), so the test runs it to a fixed horizon instead.
 *
 * [acrossWeekBoundary] runs the same world on over the boundary of access week 2975 (Monday 00:00,
 * 64 h in): the planner renews every own namespace's capability with a week-2976 trial token at its
 * PRF time in the last 23 h of week 2975 (the EXPIRING row of Phase 8 §12.4), REGROWS then keeps the
 * `c`/`c + 1` rows of the new capability's week and the work lane registers them, and at 68 h alice
 * writes once more — the renewal the whole week-boundary half of §15.1 variant (b) is about.
 */
internal class EntDmConversation(
    val refuseBobRedemptions: Boolean = false,
    val acrossWeekBoundary: Boolean = false,
) : EntDmScenario(
    when {
        refuseBobRedemptions -> "ENT-DM/no-redemption"
        acrossWeekBoundary -> "ENT-DM/renewal"
        else -> "ENT-DM/conversation"
    },
) {
    private val end: Long = if (acrossWeekBoundary) RENEWAL_END else END

    override fun build(w: World) {
        twoDmClients(w)
        if (refuseBobRedemptions) {
            w.relayHook = { client, kind, info ->
                if (client === bob.c && info.kind == CallKind.REDEEM && kind == EventKind.RELAY_BEFORE_SEND) "relay_unavailable" else null
            }
        }
        w.trial(alice, "alice", MINUTE)
        w.trial(bob, "bob", 3 * MINUTE)
        w.jobs(alice.c, 25 * MINUTE, end)
        w.jobs(bob.c, 27 * MINUTE, end)
        if (acrossWeekBoundary) {
            // 68 h, Monday 04:00 of week 2976: alice writes after the boundary (again at 68 h 20).
            w.foreground(alice.c, 68 * HOUR, 68 * HOUR + 40 * MINUTE)
            for (t in listOf(68 * HOUR + MINUTE, 68 * HOUR + 20 * MINUTE)) {
                w.at(t, "alice writes after the week boundary") {
                    if (outgoing(aliceDm, AFTER_BOUNDARY) != null) return@at
                    aliceDm.user { d -> d.engine.send(d.engine.contacts().single().id, AFTER_BOUNDARY, null) }
                }
            }
        }

        // 6 h: alice scans bob's card in person and writes (again at 6 h 20 if a crash lost it).
        w.foreground(alice.c, 6 * HOUR, 6 * HOUR + 40 * MINUTE)
        for (t in listOf(6 * HOUR + MINUTE, 6 * HOUR + 20 * MINUTE)) {
            w.at(t, "alice adds bob and writes") {
                if (outgoing(aliceDm, HELLO) != null) return@at
                aliceDm.user { d ->
                    if (d.engine.contacts().isEmpty()) {
                        check(d.engine.addContact(bobDm.d().card(), CardSource.QR_IN_PERSON) == AddContactResult.ADDED) { "alice could not add bob's card" }
                    }
                    check(d.engine.send(d.engine.contacts().single().id, HELLO, null) == SendResult.QUEUED) { "alice's first message was not queued" }
                }
            }
        }
        // 8 h (9 h, 10 h): bob accepts the request and answers, once.
        for (t in listOf(8 * HOUR, 9 * HOUR, 10 * HOUR)) {
            w.foreground(bob.c, t, t + 30 * MINUTE)
            w.at(t + 5 * MINUTE, "bob accepts and answers") {
                bobDm.user { d ->
                    val request = d.engine.contacts().firstOrNull { it.trust == TrustState.REQUEST } ?: return@user
                    check(d.engine.acceptRequest(request.id)) { "bob could not accept alice's request" }
                    check(d.engine.send(request.id, HI_BACK, null) == SendResult.QUEUED) { "bob's answer was not queued" }
                }
            }
        }
        // 11 h: alice answers once bob's answer arrived (again at 11 h 20 if a crash lost it).
        w.foreground(alice.c, 11 * HOUR, 11 * HOUR + 30 * MINUTE)
        for (t in listOf(11 * HOUR + 5 * MINUTE, 11 * HOUR + 20 * MINUTE)) {
            w.at(t, "alice writes again") {
                if (HI_BACK !in inbound(aliceDm) || outgoing(aliceDm, PAIR_NOW) != null) return@at
                aliceDm.user { d -> d.engine.send(d.engine.contacts().single().id, PAIR_NOW, null) }
            }
        }
        w.endMillis = end
    }

    companion object {
        const val HELLO = "hello"
        const val HI_BACK = "hi back"
        const val PAIR_NOW = "pair now"
        const val AFTER_BOUNDARY = "after the boundary"
        const val END = 13 * HOUR
        const val RENEWAL_END = 72 * HOUR
    }
}
