package org.ghost.messaging.entworld

import org.ghost.entitlement.api.ActivationState
import org.ghost.entitlement.harness.EntClient
import org.ghost.entitlement.harness.EntConfig
import org.ghost.entitlement.harness.EntScenario
import org.ghost.entitlement.harness.EntWorld
import org.ghost.entitlement.harness.inviteText
import org.ghost.messaging.api.AddContactResult
import org.ghost.messaging.api.CardSource
import org.ghost.messaging.api.MessageState
import org.ghost.messaging.api.SendResult
import org.ghost.messaging.api.TrustState
import org.ghost.network.EntitlementCrypto
import org.ghost.sync.api.CapabilityKind
import org.ghost.sync.api.NamespaceId
import org.ghost.sync.harness.CallKind
import org.ghost.sync.harness.ClientSpec
import org.ghost.sync.harness.EventKind
import org.ghost.sync.harness.ModelRelay
import org.ghost.sync.harness.World
import org.ghost.sync.harness.World.Companion.HOUR
import org.ghost.sync.harness.World.Companion.MINUTE
import org.ghost.sync.harness.foreground
import org.ghost.sync.harness.jobs

/**
 * A scenario of the entitlement world (§15.1 variant (b)): a Phase 8 [EntScenario] — so the
 * Phase 7 runner, its structural and quiescence invariants, and the entitlement engine's own
 * quiescence conditions, MS-6, the token accounting and the T3 canaries all apply — with two
 * clients, alice and bob, each carrying the entitlement engine **and** the DM layer
 * ([EntDmWorld]). Either may be the armed subject (the one whose events a crash plan counts). The
 * world starts where every entitlement world starts: Friday of access week 2975 at 08:00 UTC.
 *
 * This is the base SCN-E, JD8 and the OS suite build on (design §22.22): it owns the setup, the
 * trial activation through the real issuer lane every one of them needs, the read helpers, the
 * evidence snapshots and the end checks, and nothing scenario-specific; the one-scan establishment
 * of §12.2 as user actions at scripted times is [EntDmConversation]'s.
 */
internal abstract class EntDmScenario(name: String) : EntScenario(name) {

    /**
     * The trial arms three ACCESS tokens per ES slot, not the Grid's two: since S4-owner every
     * activated identity redeems one token per (relay, own namespace, week) for `X_0`, `P_0` **and
     * `M_0` (Phase 11 design §5.2's token accounting — at most 3 per slot against
     * `access_per_slot = 16`), and a registration row is only served where a usable, funded write
     * capability exists (the `SERVING` join of the registration lane). With two, the third own
     * namespace's capability starves at some relays and its registration rows never serve — bob's
     * deposits are then refused exactly where alice never registered (F-S4o-5, §22.7).
     */
    override fun config(): EntConfig = configured(EntConfig(trialPerSlot = 3))
    lateinit var dm: EntDmWorld
    lateinit var bob: EntClient
    lateinit var aliceDm: EntDmClient
    lateinit var bobDm: EntDmClient

    /** A DM world that does not settle should fail in hours of tail, not in the 31 days Phase 8 allows. */
    override val maxTailRounds: Int get() = 200

    /** Outgoing texts the scenario expects to end `FAILED` or `INDETERMINATE` (the "nothing owed" oracle). */
    open val expectedFailures: Set<String> get() = emptySet()

    /**
     * The four slot relays, the entitlement world over them, alice and bob — [armBob] picks which
     * one is armed — each with its relay directory, its entitlement engine and its DM layer.
     * [genesis]: the identities exist already, so no trial runs and the K20 hook never fires —
     * ACTIVATE then comes from §21.12 point 2's resume at the first time-triggered pass (as
     * `restored`, the side `DmActor` takes when it cannot tell) — and the tokens have to come from
     * somewhere else (`EntClient.addTokens`, or a pack through the `ModelIssuer`).
     */
    protected fun twoDmClients(w: World, genesis: Boolean = false, armBob: Boolean = false) {
        val relays = EntDmWorld.slotRelays(w)
        ent = EntWorld(w, relays, config())
        dm = EntDmWorld(w, ent)
        val a = if (armBob) w.client(ClientSpec("alice", armed = false)) else subject(w, "alice")
        a.directory(*relays.toTypedArray())
        alice = ent.attach(a, genesis)
        aliceDm = dm.attach(alice, ALICE_BRANCH)
        val b = if (armBob) subject(w, "bob") else w.client(ClientSpec("bob", armed = false))
        b.directory(*relays.toTypedArray())
        bob = ent.attach(b, genesis)
        bobDm = dm.attach(bob, BOB_BRANCH)
    }

    /**
     * The trial activation of §8.3 through the real issuer lane: an invite of another identity (its
     * INVITE token minted with the test key — the inviter's purchase, not this client's), activated
     * in the foreground at [at]; `RedeemInvite` runs as a user issuer call, the tokens are the
     * `ModelIssuer`'s blind signatures finalized by the harness native layer, and the K20 hook posts
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

    // ------------------------------------------------------------------ evidence snapshots

    /**
     * What both clients hold, read from the models and their tables at one instant ([EntDmEvidence]):
     * the own namespaces, the write rows, the registrations (with what the relay records for them),
     * the read rows that are no credential v3, and the conversation (inbound texts, outgoing states).
     * A run that crosses week boundaries reads its evidence where it means something — a capability
     * is replaced by its renewal, a registration and its deposit charges are swept once their week is
     * over, and a message is erased when its timer runs out (§10.3) — so it takes snapshots at
     * scripted times ([snapshotAt]); a short run reads one at its end.
     */
    class Snapshot(
        val atMillis: Long,
        val own: Map<String, Map<String, ByteArray>>,
        val caps: Map<String, List<EntDmEvidence.WriteCapability>>,
        val regs: Map<String, List<EntDmEvidence.Registration>>,
        val foreignReads: Map<String, Int>,
        val inbound: Map<String, List<String>>,
        val outgoing: Map<String, Map<String, MessageState>>,
    )

    val snapshots = LinkedHashMap<String, Snapshot>()

    fun snapshot(w: World): Snapshot {
        val clients = listOf(aliceDm, bobDm)
        return Snapshot(
            w.clock.millis,
            clients.associate { it.c.name to it.ownNamespaces() },
            clients.associate { it.c.name to EntDmEvidence.writeCapabilities(dm, it) },
            clients.associate { it.c.name to EntDmEvidence.registrations(dm, it) },
            clients.associate { it.c.name to EntDmEvidence.foreignReadTokens(it) },
            clients.associate { it.c.name to inbound(it) },
            clients.associate { dmc ->
                dmc.c.name to dmc.read { d ->
                    d.engine.contacts().flatMap { d.engine.conversation(it.id, 200, null) }.filter { it.outgoing && it.text != null }
                        .associate { it.text!! to it.state }
                }.orEmpty()
            },
        )
    }

    /** A world action at [t] that keeps [snapshot] under [label] (it reads through the raw connection: no event). */
    protected fun World.snapshotAt(t: Long, label: String) = at(t, "evidence snapshot $label") { snapshots[label] = snapshot(this) }

    override fun extraQuiescence(w: World): List<String> = super.extraQuiescence(w) + dm.quiescenceProblems(expectedFailures)

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

        /** The access week the world starts in (2975) and the start of week [WEEK0] + [k], in world milliseconds. */
        val WEEK0: Long = ModelRelay.week(World.T0)

        fun boundary(k: Int): Long = (ModelRelay.weekStart(WEEK0 + k) - World.T0) * 1_000
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
 * before it reaches the redeem model (an unreachable redeem path, not a refused token), so bob never
 * holds a capability. It cannot reach the Phase 7 quiescence (bob holds eligible tokens and a waiting
 * need, which is exactly what the entitlement liveness premise forbids), so the test runs it to a
 * fixed horizon instead.
 *
 * [acrossWeekBoundary] runs the same world on for two more weeks, into access week 2978. The trial
 * covers weeks 2975 and 2976 (`Grid.TRIAL_WEEKS`), so the planner renews every own namespace's
 * capability with a week-2976 trial token at its PRF time in the last 23 h of week 2975 (the
 * EXPIRING row of Phase 8 §12.4), and REGROWS has the work lane register the renewed capability's
 * `c + 1` rows (week 2977). No token of week 2977 exists: from Monday 00:00 of week 2977 neither
 * client holds a capability, and every registration made with the Friday capability (weeks 2975 and
 * 2976) is dead from `start(2978) + 1 h` (`valid_until = start(p + 2) + 1 h`, §4.4). At
 * `start(2978) + 2 h` alice writes once more: that deposit can only be charged to a week-2977
 * registration, which only the renewal made. [refuseBobRenewal] is its control: the same run with
 * bob's week-2976 redemptions — and only those — refused before the relay.
 *
 * [fairyAt] is the negative control of the checks themselves: at that time a "redeem fairy" (the
 * Phase 7 helper `Client.capability`, the core world's shortcut) installs a relay-minted write
 * capability for bob's inbox at every relay of its set; with [fairyChecked] the world's every-commit
 * check is on, as in every other run.
 */
internal class EntDmConversation(
    val refuseBobRedemptions: Boolean = false,
    val acrossWeekBoundary: Boolean = false,
    val refuseBobRenewal: Boolean = false,
    val fairyAt: Long? = null,
    val fairyChecked: Boolean = true,
    val armBob: Boolean = false,
) : EntDmScenario(
    when {
        refuseBobRedemptions -> "ENT-DM/no-redemption"
        refuseBobRenewal -> "ENT-DM/no-renewal"
        acrossWeekBoundary -> "ENT-DM/renewal"
        fairyAt != null -> "ENT-DM/fairy"
        else -> "ENT-DM/conversation"
    },
) {
    val renewal: Boolean get() = acrossWeekBoundary || refuseBobRenewal
    private val end: Long = if (renewal) RENEWAL_END else END

    override fun build(w: World) {
        twoDmClients(w, armBob = armBob)
        if (refuseBobRedemptions || refuseBobRenewal) {
            w.relayHook = { client, kind, info ->
                val refused = client === bob.c && info.kind == CallKind.REDEEM && kind == EventKind.RELAY_BEFORE_SEND &&
                    (refuseBobRedemptions || tokenWeek(info.hashes.single()) == WEEK0 + 1)
                if (refused) "relay_unavailable" else null
            }
        }
        w.trial(alice, "alice", MINUTE)
        w.trial(bob, "bob", 3 * MINUTE)
        w.jobs(alice.c, 25 * MINUTE, end)
        w.jobs(bob.c, 27 * MINUTE, end)

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
        if (renewal) {
            // The last minute of week 2975: every renewal is done and nothing of week 2975 has lapsed yet.
            w.snapshotAt(boundary(1) - MINUTE, BEFORE_BOUNDARY)
            // start(2978) + 2 h: every registration the Friday capability made is dead; alice writes.
            val t = LAPSED_AT
            w.foreground(alice.c, t, t + 40 * MINUTE)
            for (at in listOf(t + MINUTE, t + 20 * MINUTE)) {
                w.at(at, "alice writes after the old registrations lapsed") {
                    if (outgoing(aliceDm, AFTER_LAPSE) != null) return@at
                    aliceDm.user { d -> d.engine.send(d.engine.contacts().single().id, AFTER_LAPSE, null) }
                }
            }
        }
        fairyAt?.let { t ->
            if (!fairyChecked) dm.checkEveryCommit = false
            w.at(t, "a redeem fairy installs bob's inbox capabilities") {
                val inbox = checkNotNull(bobDm.ownNamespaces()["inbox"]) { "bob has no inbox yet" }
                for (name in EntDmEvidence.relaySet(dm, bobDm, inbox)) {
                    bob.c.capability(w.relays.single { it.name == name }, NamespaceId(inbox), CapabilityKind.WRITE)
                }
            }
        }
        w.endMillis = end
    }

    /** The ACCESS week of the token whose nullifier a `REDEEM` call names, or −1. */
    private fun tokenWeek(nullifier: String): Long =
        ent.records.issued[nullifier]?.takeIf { it.kind == EntitlementCrypto.KIND_ACCESS }?.epoch ?: -1

    companion object {
        const val HELLO = "hello"
        const val HI_BACK = "hi back"
        const val PAIR_NOW = "pair now"
        const val AFTER_LAPSE = "after the old registrations lapsed"
        const val END = 13 * HOUR
        const val BEFORE_BOUNDARY = "before-boundary"

        /** `start(2978) + 2 h`: one hour after the week-2976 registrations' `valid_until`. */
        val LAPSED_AT: Long = EntDmScenario.boundary(3) + 2 * HOUR
        val RENEWAL_END: Long = EntDmScenario.boundary(3) + 6 * HOUR
    }
}
