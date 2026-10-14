package org.ghost.messaging.entworld

import org.ghost.entitlement.harness.Bytes
import org.ghost.messaging.api.AddContactResult
import org.ghost.messaging.api.CardSource
import org.ghost.messaging.api.MessageState
import org.ghost.messaging.api.SendResult
import org.ghost.messaging.api.Timer
import org.ghost.messaging.api.TrustState
import org.ghost.messaging.engine.ContactKeeper
import org.ghost.messaging.engine.DmSyncPorts
import org.ghost.messaging.engine.RelaySetResolver
import org.ghost.messaging.harness.DmMutants
import org.ghost.messaging.harness.DmStructuralInvariants
import org.ghost.messaging.port.EsSlots
import org.ghost.sync.api.BlobHash
import org.ghost.sync.api.NamespaceId
import org.ghost.sync.api.SyncChange
import org.ghost.sync.engine.Session
import org.ghost.sync.harness.CallInfo
import org.ghost.sync.harness.CallKind
import org.ghost.sync.harness.Client
import org.ghost.sync.harness.EventKind
import org.ghost.sync.harness.Mutation
import org.ghost.sync.harness.RelayNode
import org.ghost.sync.harness.World
import org.ghost.sync.harness.World.Companion.DAY
import org.ghost.sync.harness.World.Companion.HOUR
import org.ghost.sync.harness.World.Companion.MINUTE
import org.ghost.sync.harness.foreground
import org.ghost.sync.harness.jobs
import org.ghost.sync.harness.violation
import org.ghost.sync.store.Time
import java.util.IdentityHashMap

/**
 * **SCN-E, the offline recipient** (Phase 9 design §15.3; §22.25), on the entitlement world of
 * §15.1 variant (b) — the real redeem lane and the real registration lane, never a redeem fairy.
 *
 * > B offline across 3 week boundaries: deposits succeed with its static per-slot credential while
 * > any registration lives, then wait in `wait_capability` (§21.2 point 9 …); B returns, renews,
 * > registers; waiting ops of A delivered before their deadlines or FAILED after; a LOSE_KEYS
 * > variant exercising the healing rule. — §15.3
 *
 * Two variants, one class.
 *
 * **[Variant.OFFLINE].** alice and bob are genesis identities holding ACCESS tokens for six weeks
 * (a trial covers two, `Grid.TRIAL_WEEKS`; `EntClient.addTokens` in the unarmed setup), both with
 * periodic jobs every 15 minutes; ACTIVATE is §21.12 point 2's resume at the first time-triggered
 * pass. On Friday of week `W0` alice scans bob's card in person, turns the conversation's timer off
 * (so nothing the oracles read is erased, and a blob waits 30 days at the relay) and writes; bob
 * accepts and answers; alice answers in pair mode. From Saturday 04:00 bob is **offline** — no
 * network, the phone on — until Monday 12:00 of week `W0 + 4`: across **four** week boundaries, one
 * more than §15.3's three, because a message written after the lapse can outlive its 7-day
 * deadline (§10.1 R-T4) before bob returns only if he is away for a fourth. bob's newest capability
 * is of week `c = W0` (he was offline before the renewal window), so his registrations are of `W0`
 * and `W0 + 1` — the `c + 1` row is what buys the offline tolerance (§4.8, E-8) — and they accept
 * deposits until `start(W0 + 2) + 1 h` and `start(W0 + 3) + 1 h` (§21.2 point 9). alice writes:
 *  - [E_EARLY] on Tuesday of `W0 + 1`, while both registrations live — stored, `SENT`, and read by
 *    bob three weeks later (a 30-day blob);
 *  - [E_LATE] on Wednesday of `W0 + 2`, after `start(W0 + 2) + 1 h`: only the `c + 1` registration
 *    still accepts it — stored and `SENT`, which is the half of the offline horizon a registration
 *    of `c` alone cannot give (the review found no deposit there, §22.25 item 14);
 *  - [E_DOOMED] an hour after the lapse — refused at every relay, it waits, and its deadline passes
 *    ten hours before bob returns: it must end `FAILED`, and not before its deadline;
 *  - [E_WAITING] four days after the lapse — it waits, bob returns, renews with a week-`W0 + 4`
 *    token, registers, and it must be delivered before its deadline.
 * bob answers [E_BACK] once he shows [E_WAITING].
 *
 * **[Variant.LOSE_KEYS].** The same establishment, bob stays online, and at [LOSS_AT] the relay of
 * bob's inbox set whose operator is alone in that set loses its `keys.redb` (hostile mode LOSE_KEYS,
 * `ModelRelay.loseKeys`): every registration at that relay is gone, blobs are not. alice writes
 * [E_HEAL] four minutes later. The two other relays of the set belong to one operator, so the
 * message cannot be decided `SENT` (two operators, ADR-11) until the relay that lost its keys holds
 * bob's DEPOSIT registration again — which only §4.8's healing rule restores: bob's own READ
 * credential is refused there, KEEPER re-arms the pair's `done` rows and re-puts the credential, and
 * the work lane registers them again.
 *
 * **Checked in every run** (faulted or not), each against the relay-side record or the clients'
 * rows through the raw connection, so a check is never an event of the run it checks:
 *  - **§21.2 point 7 at the client** ([CredentialWatch], every commit of either client): a refused
 *    deposit credential is re-put only inside a time-triggered pass (a relay session start, a
 *    consumer or quiet-run tail, the actor timer, a database open) or a user send — the trigger
 *    read from what the wiring **scheduled**, never from the pass's own flag — so a re-put on the
 *    refusal's own `CAPABILITIES` hint, by whatever path, fails at its commit (mutant MC-15); and a
 *    refusal the sender heard parks the delivery in `wait_capability` (§15.3);
 *  - **§21.2 point 7 at the relay** ([StoreView], every store): a client's store into one namespace
 *    at one relay refused again under a credential put again needs a time trigger, a user send or a
 *    reboot of that client in between; refused again under the **same** generation it needs the
 *    earlier refusal to have gone unheard (the harness's own record of a store that reached the
 *    relay without an answer reaching the engine) or a reboot in between — so a sender that hears
 *    `unauthorized` and simply tries again fails here. The per-session count §21.2 point 7 states
 *    is measured and reported, because the real engine does not meet it (§22.25 item 4);
 *  - OFFLINE: bob reached no relay while away; while [E_EARLY] is stored the relays hold bob's
 *    DEPOSIT registrations of exactly `W0` and `W0 + 1`, and while [E_LATE] is, of exactly `W0 + 1`
 *    (the `W0 + 2` row pending); both `SENT` before the lapse with deposits accepted; no deposit of
 *    [E_DOOMED] or [E_WAITING] accepted by any relay before bob returned, and alice tried (refused
 *    deposits exist); [E_DOOMED] still `QUEUED` an hour before its deadline, `FAILED` three hours
 *    after it — or still undecided only while a delivery of it holds a possible copy whose outcome
 *    alice never learned (OUT-4; the engine keeps such an op open past its deadline, §22.25 item
 *    14(a)) — never stored, and no store of it attempted after its deadline; [E_WAITING] `QUEUED`
 *    the minute before bob returns; six hours after bob returns, a redeemed capability of the new
 *    week at every relay of both his sets and every registration of that week **and the next**
 *    done, held by the relay and paid for by that week's capabilities only; at the end [E_WAITING]
 *    `SENT` with its first accepted deposit after bob's return and before its deadline;
 *  - LOSE_KEYS: six hours after the loss, every registration of bob's inbox at that relay from the
 *    current week on is held by the relay again (mutant MC-14), bob re-registered there after the
 *    loss, and his READ credential there was re-put; [E_HEAL] `SENT`, with a deposit accepted at
 *    that relay after the loss.
 *
 * **The oracles at quiescence**, §15.3's and S10b's: the entitlement world's (IN-1 over the DM
 * namespaces, "nothing owed and nothing given up" with [E_DOOMED] the one text allowed to end
 * `FAILED`, no LOCAL need waiting, no pass threw), then **no loss** (every text either device marked
 * `SENT` is rendered by the other), **CS-2** (no device renders a message twice), **CS-4** within the
 * run (the render order is kept, [renderOrder], and `ScnETest` compares every faulted run's with the
 * recording run's over the messages both hold) and **session liveness** (one more message each way
 * decrypts, both sent at once); and the DM structural invariants of §15.3 at every reboot (the
 * rebooted client heavy, the other light) and at the end, settled, with the post-sweep clauses.
 * **Declared narrowings:** §15.3's "the WAL is 0 bytes after R-K1" is not checked — the entitlement
 * world's reboot is Phase 7's (`migrate`, `verifyIntegrity`), which runs no R-K1; and T28 (no
 * time-triggered step caused by an arriving blob) has no check of its own here.
 *
 * **User actions are done again when a crash interrupted them** (S10b's rule, §22.19 item 6), each
 * judged from the rows the screen shows — a contact in the list, the timer, a message in the
 * conversation, a request — read on the raw connection; the action itself goes through the facade.
 */
internal class ScnE(
    val variant: Variant,
    val armBob: Boolean,
    /** A §15.7 mutant installed on both clients, or null for the real engine. */
    val dmMutant: DmMutants.Mutation? = null,
    /** A negative control of the scenario's own checks, or null. */
    val control: Control? = null,
) : EntDmScenario(nameOf(variant, dmMutant, control)) {

    enum class Variant { OFFLINE, LOSE_KEYS }

    /**
     * Negative controls: worlds that break one thing the scenario's checks are about, and must fail
     * for that reason (`ScnETest`'s self-test), each with the variant and the armed client it runs.
     */
    enum class Control(val variant: Variant, val armBob: Boolean) {
        /** Every `RedeemToken` of bob's after his return answered `relay_unavailable`: he never renews. */
        NO_RENEWAL_ON_RETURN(Variant.OFFLINE, true),

        /** bob returns a day after [E_WAITING]'s deadline instead of before it. */
        RETURN_AFTER_EVERY_DEADLINE(Variant.OFFLINE, true),

        /**
         * The review's second path to MC-15's defect, as the review built it: on every
         * `CAPABILITIES` hint the wiring posts a **time-triggered** pass (`EntDmClient.timePass`) —
         * what `ContactKeeper`'s KDoc describes ("a pass runs at … a `CAPABILITIES` hint"). A
         * refused credential is then re-put by the refusal's own hint, through a pass whose own
         * flag says "time-triggered", which the first rule counted as a trigger.
         */
        TIME_PASS_ON_EVERY_HINT(Variant.LOSE_KEYS, false),

        /**
         * alice's refusals are neither marked on the credential nor park the delivery (statement
         * rewrites of `CapabilityStore.refuse` for a write credential and of `parkForCapability`'s
         * park, on alice): the delivery stays pending under the refused credential and is tried
         * again — the review's "`NEEDS_CAPABILITY` retried as not applied" in effect.
         */
        REFUSAL_IGNORED(Variant.LOSE_KEYS, false),
    }

    override val expectedFailures: Set<String>
        get() = if (variant == Variant.OFFLINE) setOf(E_DOOMED) else emptySet()

    /** The world, kept for the tests' reads after a run (its bus, the event counts). */
    lateinit var world: World

    /** The relay-side record of every store (see [StoreView]). */
    lateinit var stores: StoreView

    /** The client-side record of every re-put and refusal of a deposit credential (see [CredentialWatch]). */
    lateinit var credentials: CredentialWatch

    /** `w.bus.count` at the start of each phase of the script (the stratified sample's strata). */
    val phaseMarks = LinkedHashMap<String, Long>()

    /** Event indices of the armed client's `RELAY_AFTER_APPLY` of a store (the store-fault points). */
    val storeEvents = ArrayList<Long>()

    /** Measurements the tests print (never checked by themselves). */
    val notes = ArrayList<String>()

    /**
     * The conversation each client renders at the end, oldest first, before the liveness probes
     * (CS-4 across runs: `ScnETest` compares a faulted run's with the recording run's).
     */
    val renderOrder = LinkedHashMap<String, List<String>>()

    /** User **sends** made, per client: the one user action that re-puts a credential (`SendStep`'s plan). */
    val userSends = HashMap<String, Long>()

    /** The client inside a user send right now, or null ([CredentialWatch] allows a re-put there). */
    var sending: EntDmClient? = null
        private set

    /**
     * A user action on [dmc]'s facade. A send is counted before it runs (a crash inside it still
     * counts: the rules stay conservative); adding a contact, accepting a request and setting the
     * timer re-put nothing and are not counted (the review: counting every facade call widened the
     * rule).
     */
    private fun <T> act(dmc: EntDmClient, send: Boolean, block: (org.ghost.messaging.DmDevice) -> T): T? {
        if (!send) return dmc.user(block)
        userSends.merge(dmc.c.name, 1L, Long::plus)
        val outer = sending
        sending = dmc
        try {
            return dmc.user(block)
        } finally {
            sending = outer
        }
    }

    /** Blob hashes (hex) of every op of alice's outgoing texts, by the text's author minute ([captureHashes]). */
    private val hashesOf = HashMap<Long, MutableSet<String>>()

    /** The relay that lost its keys (LOSE_KEYS), and bob's READ credential generation there before the loss. */
    var lostRelay: String? = null
        private set
    private var readGenerationBeforeLoss: Long = -1

    private val returnAt: Long
        get() = if (control == Control.RETURN_AFTER_EVERY_DEADLINE) WAITING_AT + 8 * DAY else RETURN_AT
    private val end: Long
        get() = when (variant) {
            Variant.OFFLINE -> returnAt + 18 * HOUR
            Variant.LOSE_KEYS -> LOSS_AT + 12 * HOUR
        }

    override fun build(w: World) {
        world = w
        check(control == null || control.variant == variant) { "control $control runs in ${control?.variant}" }
        // A statement rewrite is installed on the armed client through Phase 7's `subject()` (it
        // survives the client's reboots) and on the unarmed one right after its only boot.
        val rewrite = dmMutant?.rewrite ?: if (control == Control.REFUSAL_IGNORED) REFUSAL_IGNORED_REWRITE else null
        if (rewrite != null) mutation = Mutation(rewrite = { _ -> rewrite })
        twoDmClients(w, genesis = true, armBob = armBob)
        if (rewrite != null && dmMutant != null) (if (armBob) alice.c else bob.c).sql.rewrite = rewrite
        check(control != Control.REFUSAL_IGNORED || !armBob) { "REFUSAL_IGNORED rewrites alice, the armed client" }
        if (dmMutant?.hintKeeper == true) {
            aliceDm.onHint = ::keeperOnCapabilitiesHint
            bobDm.onHint = ::keeperOnCapabilitiesHint
        }
        if (control == Control.TIME_PASS_ON_EVERY_HINT) {
            val post = { dmc: EntDmClient, changes: Set<SyncChange> ->
                if (SyncChange.CAPABILITIES in changes) {
                    w.driver.scheduleProcess(w.clock.millis, dmc.c, "control-time-pass:${dmc.c.name}") { dmc.timePass() }
                }
            }
            aliceDm.onHint = post
            bobDm.onHint = post
        }

        // Six weeks of ACCESS tokens for both, as a finalized pack would leave them (unarmed setup).
        val eligible = Time.floorMinute(w.clock.epochSeconds()) - 3_600
        for (ec in listOf(alice, bob)) {
            for (week in WEEK0 until WEEK0 + TOKEN_WEEKS) {
                for (slot in 0 until EntDmWorld.SLOTS) ec.addTokens("access", week, slot, TOKENS_PER_SLOT, eligible)
            }
        }

        stores = StoreView(this, w)
        stores.install()
        credentials = CredentialWatch(this, w)
        credentials.install()
        structuralAtEveryReboot(w)
        captureAtEveryCommit(w)

        if (control == Control.NO_RENEWAL_ON_RETURN) {
            w.relayHook = { client, kind, info ->
                val refused = client === bob.c && info.kind == CallKind.REDEEM && kind == EventKind.RELAY_BEFORE_SEND &&
                    w.clock.millis >= returnAt
                if (refused) "relay_unavailable" else null
            }
        }

        w.jobs(alice.c, 5 * MINUTE, end)
        w.jobs(bob.c, 7 * MINUTE, end)
        establish(w)
        when (variant) {
            Variant.OFFLINE -> offline(w)
            Variant.LOSE_KEYS -> loseKeys(w)
        }
        w.endMillis = end
    }

    // ------------------------------------------------------------------ the script

    private fun mark(w: World, t: Long, phase: String) = w.at(t, "phase $phase") { phaseMarks.putIfAbsent(phase, w.bus.count) }

    /** Friday of `W0`: alice adds bob, turns the timer off and writes; bob accepts and answers; alice answers. */
    private fun establish(w: World) {
        mark(w, 0, "establishment")
        w.foreground(alice.c, HELLO_AT, HELLO_AT + 40 * MINUTE)
        for (t in listOf(HELLO_AT + MINUTE, HELLO_AT + 20 * MINUTE)) {
            w.at(t, "alice adds bob, turns the timer off and writes") {
                if (!hasContact(aliceDm)) {
                    act(aliceDm, send = false) { d ->
                        check(d.engine.addContact(bobDm.d().card(), CardSource.QR_IN_PERSON) == AddContactResult.ADDED) { "alice could not add bob's card" }
                    }
                }
                if (timerCode(aliceDm) != 0L) act(aliceDm, send = false) { d -> d.engine.setTimer(d.engine.contacts().single().id, Timer.OFF) }
                if (!wrote(aliceDm, HELLO_AT)) act(aliceDm, send = true) { d -> check(d.engine.send(d.engine.contacts().single().id, E_HELLO, null) == SendResult.QUEUED) { "alice's first message was not queued" } }
            }
        }
        for (t in listOf(HI_AT, HI_AT + HOUR, HI_AT + 2 * HOUR)) {
            w.foreground(bob.c, t, t + 30 * MINUTE)
            w.at(t + 5 * MINUTE, "bob accepts and answers") {
                if (!hasContact(bobDm)) return@at
                act(bobDm, send = false) { d ->
                    d.engine.contacts().firstOrNull { it.trust == TrustState.REQUEST }?.let { request ->
                        check(d.engine.acceptRequest(request.id)) { "bob could not accept alice's request" }
                    }
                }
                if (!wrote(bobDm, HI_AT, window = 3 * HOUR) && accepted(bobDm)) {
                    act(bobDm, send = true) { d -> check(d.engine.send(d.engine.contacts().single().id, E_HI, null) == SendResult.QUEUED) { "bob's answer was not queued" } }
                }
            }
        }
        w.foreground(alice.c, PAIR_AT, PAIR_AT + 40 * MINUTE)
        for (t in listOf(PAIR_AT + 5 * MINUTE, PAIR_AT + 25 * MINUTE, PAIR_AT + HOUR)) {
            w.at(t, "alice answers in pair mode") {
                if (inboundCount(aliceDm) == 0L || wrote(aliceDm, PAIR_AT, window = 2 * HOUR)) return@at
                act(aliceDm, send = true) { d -> d.engine.send(d.engine.contacts().single().id, E_PAIR, null) }
            }
        }
    }

    private fun offline(w: World) {
        bob.c.offlineWindows.add(OFFLINE_AT until returnAt)
        mark(w, OFFLINE_AT, "offline, registrations live")
        write(w, aliceDm, EARLY_AT, E_EARLY)
        mark(w, C1_ONLY_AT, "offline, the c + 1 registration only")
        write(w, aliceDm, LATE_AT, E_LATE)
        mark(w, LAPSE_AT, "lapsed, deposits refused")
        write(w, aliceDm, DOOMED_AT, E_DOOMED)
        write(w, aliceDm, WAITING_AT, E_WAITING)
        mark(w, returnAt, "return, renewal, registration")
        mark(w, returnAt + 6 * HOUR, "after the return")

        // The offline horizon, both halves (§21.2 point 9, §4.8's c + 1 row): which registrations
        // the relays hold for bob while each message is stored, and that each was stored.
        w.at(EARLY_AT + 12 * HOUR, "check: bob's registrations of W0 and W0 + 1 held while e-early is stored") {
            registrationsHeldWhileAway(setOf(WEEK0, WEEK0 + 1), E_EARLY)
            storedWhileAway(EARLY_AT, E_EARLY)
        }
        w.at(LATE_AT + 12 * HOUR, "check: e-late stored under the c + 1 registration alone") {
            registrationsHeldWhileAway(setOf(WEEK0 + 1), E_LATE)
            storedWhileAway(LATE_AT, E_LATE)
        }
        // The deadline half: E_DOOMED waits until its deadline and fails after it, never before.
        w.at(DOOMED_AT + 7 * DAY - HOUR, "check: E_DOOMED still waits an hour before its deadline") {
            requireState(aliceDm, DOOMED_AT, "queued", "$E_DOOMED an hour before its deadline")
        }
        w.at(DOOMED_AT + 7 * DAY + 3 * HOUR, "check: E_DOOMED failed after its deadline") {
            // An attempt whose outcome the sender could not learn — a timeout after the relay
            // refused it, or a death with the store in flight, which Phase 7's M1 counts as a
            // possible copy at the next open — leaves a possible copy (`copy_hour`), and the Phase 7
            // engine keeps the op undecided while one may still be resolved (the W clause of
            // `OutboxStore.decide`): the op waits for a check that is answered only once bob has
            // registered again, and is decided then (see [offlineEnd]). That is past R-T4's "after
            // the deadline the op closes", recorded as an engine finding (§22.25 item 14(a)); SCN-E
            // bounds it only by its own end, because bob comes back.
            val row = outgoingRow(aliceDm, DOOMED_AT) ?: violation("SCN-E: $E_DOOMED was never written")
            if (row.first != "failed") {
                if (!possibleCopy(DOOMED_AT)) violation("SCN-E: $E_DOOMED three hours after its deadline is ${row.first}, expected failed")
                if (row.first == "sent") violation("SCN-E: $E_DOOMED is SENT three hours after its deadline")
                doomedHeldACopy = true
                notes += "$E_DOOMED holds a possible copy: ${row.first} three hours after its deadline"
            }
        }
        w.at(returnAt - MINUTE, "check: nothing written after the lapse was stored while bob was away") {
            nothingStoredWhileLapsed()
            bobReachedNoRelayWhileAway()
        }
        w.at(returnAt + 6 * HOUR, "check: bob renewed and registered on his return") { renewedAndRegistered() }

        // bob answers once he shows E_WAITING (the user has read it).
        for (t in listOf(returnAt + 6 * HOUR, returnAt + 7 * HOUR, returnAt + 8 * HOUR)) {
            w.foreground(bob.c, t, t + 30 * MINUTE)
            w.at(t + 5 * MINUTE, "bob answers after his return") {
                if (!received(bobDm, WAITING_AT) || wrote(bobDm, returnAt + 6 * HOUR, window = 3 * HOUR)) return@at
                act(bobDm, send = true) { d -> d.engine.send(d.engine.contacts().single().id, E_BACK, null) }
            }
        }
    }

    private fun loseKeys(w: World) {
        mark(w, LOSS_AT, LOSS_PHASE)
        w.at(LOSS_AT, "the relay that bob's inbox set needs for its second operator loses its keys") {
            val node = loneOperatorRelay(w)
            lostRelay = node.name
            readGenerationBeforeLoss = readGeneration(bobDm, node)
            node.model.loseKeys()
        }
        write(w, aliceDm, HEAL_AT, E_HEAL)
        mark(w, LOSS_AT + HEAL_BOUND, "healed")
        w.at(LOSS_AT + HEAL_BOUND, "check: the healing rule restored the registrations") { healed() }
    }

    /** alice writes [text] at [at] (again at +20 and +40 min if a crash lost it), in a foreground. */
    private fun write(w: World, dmc: EntDmClient, at: Long, text: String) {
        w.foreground(dmc.c, at, at + 50 * MINUTE)
        for (t in listOf(at + MINUTE, at + 20 * MINUTE, at + 40 * MINUTE)) {
            w.at(t, "${dmc.c.name} writes '$text'") {
                if (wrote(dmc, at)) return@at
                act(dmc, send = true) { d -> check(d.engine.send(d.engine.contacts().single().id, text, null) == SendResult.QUEUED) { "'$text' was not queued" } }
            }
        }
    }

    // ------------------------------------------------------------------ MC-15's trigger substitution

    /**
     * §15.7 MC-15 as a trigger substitution (§22.25): the contact half of KEEPER — the production
     * [ContactKeeper] over the device's own database, material, slots and clock — runs on every
     * `CAPABILITIES` hint, as a process action of the client at the same instant, where the engine
     * runs it only on a time-triggered pass (`DmActor.pass`). A refused credential is then re-put the
     * moment its refusal is committed, and the delivery it parked is due again at once.
     */
    private fun keeperOnCapabilitiesHint(dmc: EntDmClient, changes: Set<SyncChange>) {
        if (SyncChange.CAPABILITIES !in changes) return
        val w = world
        w.driver.scheduleProcess(w.clock.millis, dmc.c, "mc15-keeper:${dmc.c.name}") {
            val d = dmc.device ?: return@scheduleProcess
            if (!dmc.ent.identity.exists) return@scheduleProcess
            dmc.sync()
            val ports = DmSyncPorts(d.stores.namespaces, d.stores.capabilities, d.stores.registrations, d.stores.outbox, d.stores.inbox)
            val keeper = ContactKeeper(d.database, ports, d.material, RelaySetResolver(EsSlots { d.slots }), d.clock, d.contexts)
            try {
                keeper.run()
            } catch (e: Exception) {
                dm.swallowed += "${dmc.c.name}: ${e.javaClass.simpleName}: ${e.message}"
            }
        }
    }

    // ------------------------------------------------------------------ raw reads (no event)

    private fun count(dmc: EntDmClient, sql: String, args: List<Any?> = emptyList()): Long {
        var n = 0L
        dmc.c.jdbc.query(sql, args) { n = it.long(0) }
        return n
    }

    private fun seconds(t: Long): Long = World.T0 + t / 1_000

    private fun hasContact(dmc: EntDmClient): Boolean = count(dmc, "SELECT count(*) FROM dm_contact") > 0

    private fun accepted(dmc: EntDmClient): Boolean =
        count(dmc, "SELECT count(*) FROM dm_contact WHERE trust_state IN ('unverified', 'verified')") > 0

    private fun timerCode(dmc: EntDmClient): Long {
        var code = -1L
        dmc.c.jdbc.query("SELECT timer_code FROM dm_conversation") { code = it.long(0) }
        return code
    }

    /** An outgoing text authored in `[at, at + window)`: the step at [at] already wrote its message. */
    private fun wrote(dmc: EntDmClient, at: Long, window: Long = HOUR): Boolean = count(
        dmc,
        "SELECT count(*) FROM dm_message WHERE direction = 'out' AND kind = 1 AND author_minute >= ?1 AND author_minute < ?2",
        listOf(seconds(at) - 60, seconds(at + window)),
    ) > 0

    private fun inboundCount(dmc: EntDmClient): Long = count(dmc, "SELECT count(*) FROM dm_message WHERE direction = 'in' AND kind = 1")

    /** An inbound text authored in `[at, at + 1 h)`: the peer's step at [at] reached this device. */
    private fun received(dmc: EntDmClient, at: Long): Boolean = count(
        dmc,
        "SELECT count(*) FROM dm_message WHERE direction = 'in' AND kind = 1 AND author_minute >= ?1 AND author_minute < ?2",
        listOf(seconds(at) - 60, seconds(at + HOUR)),
    ) > 0

    /** The state of the outgoing text the step at [at] wrote, and its author minute (seconds), or null. */
    private fun outgoingRow(dmc: EntDmClient, at: Long): Pair<String, Long>? {
        var row: Pair<String, Long>? = null
        dmc.c.jdbc.query(
            "SELECT state, author_minute FROM dm_message WHERE direction = 'out' AND kind = 1 AND author_minute >= ?1 AND author_minute < ?2",
            listOf(seconds(at) - 60, seconds(at + HOUR)),
        ) { row = it.string(0) to it.long(1) }
        return row
    }

    private fun requireState(dmc: EntDmClient, at: Long, state: String, what: String) {
        val row = outgoingRow(dmc, at) ?: violation("SCN-E: $what: the message was never written")
        if (row.first != state) violation("SCN-E: $what is ${row.first}, expected $state")
    }

    /**
     * The blob hashes of every op of alice's outgoing texts, by the text's author minute (seconds).
     * Read on the raw connection after **every** commit of alice's that touched an outbox row
     * ([captureAtEveryCommit]): the join rows of an op go once its outcome is released and collected,
     * so a read at a scripted time can come too late — the first gate-scale sample found exactly that
     * (§22.25 item 10(c)).
     */
    private fun captureHashes() {
        aliceDm.c.jdbc.query(
            "SELECT m.author_minute, o.blob_hash FROM dm_message m JOIN dm_outbound_item i ON i.message_ref = m.message_id " +
                "JOIN dm_outbound_op x ON x.item_id = i.item_id JOIN outbox_op o ON o.operation_id = x.operation_id " +
                "WHERE m.direction = 'out' AND m.kind = 1",
        ) { hashesOf.getOrPut(it.long(0)) { LinkedHashSet() } += Bytes.hex(it.blob(1)) }
    }

    /** [captureHashes] after every outbox commit of alice's, on the executor of every boot. */
    private fun captureAtEveryCommit(w: World) {
        alice.c.sql.onCommit += { captureHashes() }
        val boot = w.onBoot
        w.onBoot = { c ->
            boot?.invoke(c)
            if (c === alice.c) c.sql.onCommit += { captureHashes() }
        }
    }

    /** The hashes of every op the text the step at [at] wrote has had (authored in `[at, at + 1 h)`). */
    fun hashes(at: Long): Set<String> {
        captureHashes()
        return hashesOf.filterKeys { it >= seconds(at) - 60 && it < seconds(at + HOUR) }.values.flatten().toSet()
    }

    /**
     * alice holds a **possible copy** of the text the step at [at] wrote: a delivery of one of its ops
     * with `copy_hour` set and no acknowledgement — the sender's own record that an attempt's
     * outcome is unknown (a timeout after apply, or a lease a death left in flight, which M1 turns
     * into a possible copy at the next open). A refusal the sender heard is a definite "not
     * applied" and leaves none.
     */
    private fun possibleCopy(at: Long): Boolean {
        val hashes = hashes(at)
        var found = false
        aliceDm.c.jdbc.query(
            "SELECT o.blob_hash FROM outbox_delivery d JOIN outbox_op o ON o.operation_id = d.operation_id " +
                "WHERE d.copy_hour IS NOT NULL AND d.ack_minute IS NULL",
        ) { if (Bytes.hex(it.blob(0)) in hashes) found = true }
        return found
    }

    /** [E_DOOMED] was still undecided, holding a possible copy, three hours after its deadline. */
    private var doomedHeldACopy = false

    private fun readGeneration(dmc: EntDmClient, node: RelayNode): Long {
        val inbox = dmc.ownNamespaces()["inbox"] ?: return -1
        var generation = -1L
        dmc.c.jdbc.query(
            "SELECT generation FROM relay_capability WHERE relay_id = ?1 AND namespace_id = ?2 AND kind = 'read'",
            listOf(dmc.c.id(node).value, inbox),
        ) { generation = it.long(0) }
        return generation
    }

    /** The relay of bob's inbox set whose operator no other relay of the set shares. */
    private fun loneOperatorRelay(w: World): RelayNode {
        val inbox = bobDm.ownNamespaces()["inbox"] ?: violation("SCN-E/LOSE_KEYS: bob has no inbox at the loss")
        val set = EntDmEvidence.relaySet(dm, bobDm, inbox).map { name -> w.relays.single { it.name == name } }
        val lone = set.groupBy { it.operatorId.toList() }.values.filter { it.size == 1 }.flatten()
        if (set.size != 3 || lone.size != 1) violation("SCN-E/LOSE_KEYS: bob's inbox set is not three relays over two operators: ${set.map { it.name }}")
        return lone.single()
    }

    // ------------------------------------------------------------------ the checks of every run

    /**
     * The relays hold bob's inbox DEPOSIT registrations of exactly [periods] at every relay of the
     * set, read from his rows and the relay model's records: the registrations a deposit of [what]
     * can be accepted under while he is away. For [E_EARLY] that is `{W0, W0 + 1}`; for [E_LATE],
     * written after `start(W0 + 2) + 1 h`, it is `{W0 + 1}` alone — the `c + 1` row of §4.8 — with
     * the current week's row pending (he cannot register it offline).
     */
    private fun registrationsHeldWhileAway(periods: Set<Long>, what: String) {
        val inbox = bobDm.ownNamespaces()["inbox"] ?: violation("SCN-E: bob has no inbox while away")
        val regs = EntDmEvidence.registrations(dm, bobDm).filter { it.namespaceHex == hexOf(inbox) && it.kind == "deposit" }
        for (relay in EntDmEvidence.relaySet(dm, bobDm, inbox)) {
            val held = regs.filter { it.relay == relay && it.recorded }.map { it.period }.toSet()
            if (held != periods) {
                violation(
                    "SCN-E: while $what is stored bob's inbox DEPOSIT registrations held at $relay are of weeks $held, expected $periods " +
                        "(§21.2 point 9, §4.8's c + 1 row): ${regs.filter { it.relay == relay }}",
                )
            }
        }
        notes += "while $what is stored: bob's DEPOSIT registrations held at every relay of his inbox set are of weeks $periods"
    }

    /** The text the step at [at] wrote is `SENT`, with accepted deposits at two relays at least, made while bob was away. */
    private fun storedWhileAway(at: Long, text: String) {
        requireState(aliceDm, at, "sent", "$text while bob is away")
        val hashes = hashes(at)
        val accepted = stores.attempts.filter { it.client == "alice" && it.hashHex in hashes && it.outcome == StoreView.Outcome.ACCEPTED }
        if (accepted.map { it.relay }.distinct().size < 2) violation("SCN-E: $text was SENT with deposits accepted at ${accepted.map { it.relay }.distinct()} only: $accepted")
    }

    /** bob's network was really off: no relay saw a call of his between going offline and coming back. */
    private fun bobReachedNoRelayWhileAway() {
        val calls = dm.seen().filter { it.client == "bob" && it.atMillis >= OFFLINE_AT + 5 * MINUTE && it.atMillis < returnAt }
        if (calls.isNotEmpty()) violation("SCN-E: bob was offline and a relay saw ${calls.size} call(s) of his: ${calls.take(5)}")
    }

    private fun nothingStoredWhileLapsed() {
        requireState(aliceDm, WAITING_AT, "queued", "$E_WAITING the minute before bob returns")
        val waiting = hashes(DOOMED_AT) + hashes(WAITING_AT)
        if (waiting.isEmpty()) violation("SCN-E: no op of $E_DOOMED or $E_WAITING was ever enqueued")
        val early = stores.attempts.filter { it.hashHex in waiting && it.outcome == StoreView.Outcome.ACCEPTED }
        if (early.isNotEmpty()) violation("SCN-E: a relay accepted a deposit written after the lapse while bob was away: $early")
        val refused = stores.attempts.count { it.client == "alice" && it.hashHex in waiting && it.outcome == StoreView.Outcome.REFUSED }
        if (refused == 0) violation("SCN-E: alice never tried to deposit a message written after the lapse (no refused store)")
        if ((credentials.parks["alice"] ?: 0) == 0L) violation("SCN-E: alice's refused deposits never parked a delivery in wait_capability")
    }

    private fun renewedAndRegistered() {
        val week = org.ghost.sync.harness.ModelRelay.week(seconds(returnAt + 6 * HOUR))
        val caps = EntDmEvidence.writeCapabilities(dm, bobDm)
        val regs = EntDmEvidence.registrations(dm, bobDm)
        for ((role, ns) in bobDm.ownNamespaces()) {
            // Since S4-owner the own set has three namespaces (Phase 11 design §5.1): `M_0` keeps
            // DEPOSIT and READ registrations like `X_0`, only `P_0` keeps FETCH.
            val kinds = if (role == "inbox" || role == "media") listOf("deposit", "read") else listOf("fetch")
            for (relay in EntDmEvidence.relaySet(dm, bobDm, ns)) {
                if (caps.none { it.relay == relay && it.namespaceHex == hexOf(ns) && it.redeemed && it.week == week }) {
                    violation("SCN-E: six hours after his return bob holds no redeemed capability of week $week for his $role at $relay: $caps")
                }
                // The week's row and the c + 1 row the week's capability buys (§4.8), both paid for
                // by that capability alone.
                for (period in listOf(week, week + 1)) {
                    for (kind in kinds) {
                        val row = regs.singleOrNull { it.relay == relay && it.namespaceHex == hexOf(ns) && it.kind == kind && it.period == period }
                        if (row == null || row.state != "done" || !row.recorded || row.serialWeeks.isEmpty() || row.serialWeeks.any { it != week }) {
                            violation("SCN-E: six hours after his return bob's $kind registration of week $period for his $role at $relay is not done, held and paid for by week $week: $row")
                        }
                    }
                }
            }
        }
        val redeemedAfter = dm.redemptions().count { it.client == "bob" && it.atMillis >= returnAt }
        notes += "bob on his return: $redeemedAfter redemptions of week $week, registrations of weeks $week and ${week + 1} done and held at every relay of both sets"
    }

    private fun healed() {
        val relay = lostRelay ?: violation("SCN-E/LOSE_KEYS: no relay lost its keys")
        val lossWeek = org.ghost.sync.harness.ModelRelay.week(seconds(LOSS_AT))
        for (dmc in listOf(bobDm, aliceDm)) {
            val inbox = dmc.ownNamespaces()["inbox"] ?: continue
            if (relay !in EntDmEvidence.relaySet(dm, dmc, inbox)) {
                if (dmc === bobDm) violation("SCN-E/LOSE_KEYS: $relay is not in bob's inbox set")
                continue
            }
            val rows = EntDmEvidence.registrations(dm, dmc).filter { it.relay == relay && it.namespaceHex == hexOf(inbox) && it.period >= lossWeek }
            if (rows.isEmpty()) violation("SCN-E/LOSE_KEYS: ${dmc.c.name} keeps no inbox registration at $relay from week $lossWeek on")
            val lost = rows.filter { !it.recorded }
            if (lost.isNotEmpty()) {
                violation(
                    "SCN-E/LOSE_KEYS: ${HEAL_BOUND / HOUR} h after $relay lost its keys, ${dmc.c.name}'s inbox registrations there are not held " +
                        "again (the healing rule, §4.8): $lost",
                )
            }
        }
        val node = world.relays.single { it.name == relay }
        val registered = dm.seen().count { it.client == "bob" && it.kind == CallKind.REGISTER && it.relay == relay && it.atMillis >= LOSS_AT }
        if (registered == 0) violation("SCN-E/LOSE_KEYS: bob made no RegisterKey call at $relay after the loss")
        val generation = readGeneration(bobDm, node)
        if (generation <= readGenerationBeforeLoss) {
            violation("SCN-E/LOSE_KEYS: bob's READ credential at $relay was never re-put after the loss (generation $readGenerationBeforeLoss → $generation)")
        }
        // Measured, not checked: the rule heals `X_0` only. bob's bundle namespace `P_0` has no own
        // READ credential whose refusal could tell him the relay lost its FETCH registrations.
        val bundle = bobDm.ownNamespaces()["bundle"]
        val fetchRows = if (bundle == null) emptyList() else {
            EntDmEvidence.registrations(dm, bobDm).filter { it.relay == relay && it.namespaceHex == hexOf(bundle) && it.period >= lossWeek }
        }
        notes += "LOSE_KEYS: $relay lost its keys at ${LOSS_AT / MINUTE} min; bob re-registered there with $registered call(s); READ credential generation " +
            "$readGenerationBeforeLoss → $generation; bob's bundle FETCH rows there ${if (fetchRows.isEmpty()) "none (not in P_0's set)" else fetchRows.joinToString { "p${it.period} ${it.state} held=${it.recorded}" }}"
    }

    /** Every reboot: §15.3's DM structural invariants on the rebooted client (heavy) and the other (light). */
    private fun structuralAtEveryReboot(w: World) {
        val boot = w.onBoot
        w.onBoot = { c ->
            boot?.invoke(c)
            if (c.boots > 1) {
                for (other in listOf(alice.c, bob.c)) {
                    DmStructuralInvariants.check(other.jdbc, other.name, "reboot ${c.boots - 1} of ${c.name}", heavy = other === c, settled = false)
                }
            }
        }
    }

    // ------------------------------------------------------------------ the end

    /**
     * At the end of every run, after the runner's quiescence tail (the bus is disarmed): the scenario's
     * end checks, the settled structural invariants, no loss, CS-2, the render order (CS-4 across runs
     * is `ScnETest`'s) and session liveness; then the entitlement world's and Phase 8's own (MS-6,
     * the token accounting, T3), and the test's outcome.
     */
    override fun finalChecks(w: World) {
        try {
            when (variant) {
                Variant.OFFLINE -> offlineEnd()
                Variant.LOSE_KEYS -> healEnd()
            }
            for (c in listOf(alice.c, bob.c)) {
                DmStructuralInvariants.check(c.jdbc, c.name, "end", heavy = true, settled = true)
                DmStructuralInvariants.afterSweep(c.jdbc, c.name, w.clock.epochSeconds(), "end")
                DmStructuralInvariants.retiredSessionsGone(c.jdbc, c.name, w.clock.epochSeconds(), "end")
            }
            noLeaseLeftInFlight()
            noMessageTheSenderCallsSentIsMissing()
            displayedAtMostOnce()
            for (dmc in listOf(aliceDm, bobDm)) renderOrder[dmc.c.name] = rendered(dmc)
            sessionIsStillLive(w)
            notes += stores.summary()
            notes += credentials.summary()
        } catch (e: Throwable) {
            runCatching { dm.close() }
            throw e
        }
        super.finalChecks(w)
    }

    private fun offlineEnd() {
        val waiting = outgoingRow(aliceDm, WAITING_AT) ?: violation("SCN-E: $E_WAITING was never written")
        val doomedState = outgoingRow(aliceDm, DOOMED_AT)?.first
        // FAILED after its deadline; INDETERMINATE only for an op that held a possible copy past it
        // (OUT-4: a possible copy is never called FAILED).
        if (doomedState != "failed" && !(doomedState == "indeterminate" && (doomedHeldACopy || possibleCopy(DOOMED_AT)))) {
            violation("SCN-E: $E_DOOMED at the end is $doomedState, expected failed")
        }
        // Backstops: every control that breaks these fails an earlier check of the run first
        // (`nothingStoredWhileLapsed` at the minute before the return), so no control shows them
        // able to fail on their own (§22.25 item 14(f)).
        if (waiting.first != "sent") violation("SCN-E: $E_WAITING is ${waiting.first} at the end: bob's return did not deliver it")
        val deadline = waiting.second + 7 * 86_400
        val accepted = stores.attempts.filter { it.hashHex in hashes(WAITING_AT) && it.outcome == StoreView.Outcome.ACCEPTED }
        val first = accepted.minOfOrNull { it.atMillis } ?: violation("SCN-E: $E_WAITING is SENT and no relay accepted a deposit of it")
        if (first < returnAt) violation("SCN-E: a deposit of $E_WAITING was accepted before bob returned")
        if (seconds(first) >= deadline) violation("SCN-E: $E_WAITING was first stored after its deadline")
        val doomed = hashes(DOOMED_AT)
        val doomedRow = outgoingRow(aliceDm, DOOMED_AT) ?: violation("SCN-E: $E_DOOMED was never written")
        val doomedDeadline = Math.floorDiv(doomedRow.second + 7 * 86_400 + 3_599, 3_600) * 3_600
        val late = stores.attempts.filter { it.hashHex in doomed && seconds(it.atMillis) > doomedDeadline }
        if (late.isNotEmpty()) violation("SCN-E: alice still tried to store $E_DOOMED after its deadline: $late")
        if (stores.attempts.any { it.hashHex in doomed && it.outcome == StoreView.Outcome.ACCEPTED }) violation("SCN-E: a relay accepted $E_DOOMED")
        val doomedRefused = stores.attempts.filter { it.hashHex in doomed && it.outcome == StoreView.Outcome.REFUSED }
        val sessions = doomedRefused.map { it.session }.distinct().size
        val perRelayPerSession = doomedRefused.groupBy { it.relay to it.session }.values.maxOfOrNull { it.size } ?: 0
        val checks = stores.checks.filter { it.client == "alice" && it.hashes.any { h -> h in doomed } }
        notes += "E_DOOMED: ${doomedRefused.size} refused deposits over $sessions sessions of alice " +
            "(${doomedRefused.groupBy { it.relay }.mapValues { it.value.size }}; at most $perRelayPerSession at one relay in one session), " +
            "last ${(doomedDeadline - seconds(doomedRefused.maxOfOrNull { it.atMillis } ?: 0)) / 60} min before its deadline; " +
            "${checks.size} CHECK calls naming it, ${checks.count { seconds(it.atMillis) > doomedDeadline }} after its deadline; " +
            "E_WAITING first stored ${(first - returnAt) / MINUTE} min after bob's return"
    }

    private fun healEnd() {
        val relay = lostRelay ?: violation("SCN-E/LOSE_KEYS: no relay lost its keys")
        requireState(aliceDm, HEAL_AT, "sent", "$E_HEAL at the end")
        val accepted = stores.attempts.filter { it.hashHex in hashes(HEAL_AT) && it.relay == relay && it.outcome == StoreView.Outcome.ACCEPTED }
        if (accepted.none { it.atMillis >= LOSS_AT }) violation("SCN-E/LOSE_KEYS: $E_HEAL was never stored at $relay after the loss")
        val refused = stores.attempts.filter { it.hashHex in hashes(HEAL_AT) && it.relay == relay && it.outcome == StoreView.Outcome.REFUSED }
        notes += "E_HEAL: ${refused.size} deposit(s) refused at $relay before bob's healing, stored there ${(accepted.minOf { it.atMillis } - LOSS_AT) / MINUTE} min after the loss"
    }

    private fun texts(dmc: EntDmClient, outgoingSent: Boolean): List<String> = dmc.read { d ->
        d.engine.contacts().flatMap { contact ->
            d.engine.conversation(contact.id, 500, null).filter { m ->
                if (outgoingSent) m.outgoing && m.state == MessageState.SENT else !m.outgoing
            }.mapNotNull { it.text }
        }
    }.orEmpty()

    /** The conversation [dmc] renders, oldest first, both directions (texts are unique in SCN-E). */
    private fun rendered(dmc: EntDmClient): List<String> = dmc.read { d ->
        d.engine.contacts().flatMap { contact -> d.engine.conversation(contact.id, 500, null).reversed().mapNotNull { it.text } }
    }.orEmpty()

    /**
     * No store lease is in flight once the tail has quiesced: a lease a dead process left is turned
     * into a possible copy at the next session start (Phase 7's M1, `OutboxStore.normalizeLeases`),
     * and a quiesced world has had one. The review found a lease left in flight on a message already
     * `SENT` through its other relays invisible to every other check (§22.25 item 14(h)).
     */
    private fun noLeaseLeftInFlight() {
        for (dmc in listOf(aliceDm, bobDm)) {
            val n = count(dmc, "SELECT count(*) FROM outbox_delivery WHERE inflight = 1")
            if (n != 0L) violation("SCN-E: ${dmc.c.name} holds $n store lease(s) in flight at quiescence — a dead process's lease never normalized (Phase 7 M1)")
        }
    }

    /** §15.3's no-loss oracle: a text either device marked `SENT` is rendered by the other. */
    private fun noMessageTheSenderCallsSentIsMissing() {
        val checked = ArrayList<String>()
        for ((sender, recipient) in listOf(aliceDm to bobDm, bobDm to aliceDm)) {
            val rendered = texts(recipient, outgoingSent = false).toSet()
            val sent = texts(sender, outgoingSent = true)
            for (text in sent) {
                if (text !in rendered) violation("SCN-E: ${sender.c.name} marked it sent and no device rendered it: \"$text\"")
            }
            checked += "${sender.c.name} → ${recipient.c.name} ${sent.size} SENT, all rendered"
        }
        notes += "no loss: ${checked.joinToString("; ")}"
        if (variant == Variant.OFFLINE && E_DOOMED in texts(bobDm, outgoingSent = false)) violation("SCN-E: bob shows $E_DOOMED, which is FAILED")
    }

    /**
     * CS-2, as `DmCrashRunner.displayedAtMostOnce` checks it — no conversation holds two inbound
     * messages at one rendered position `(sort_minute, minute_index)` — and on the rendered page
     * itself: no inbound text twice (the review found the no-loss oracle compared sets).
     */
    private fun displayedAtMostOnce() {
        for (dmc in listOf(aliceDm, bobDm)) {
            val positions = count(
                dmc,
                "SELECT count(*) FROM (SELECT conversation_id, sort_minute, minute_index FROM dm_message WHERE direction = 'in' " +
                    "GROUP BY conversation_id, sort_minute, minute_index HAVING count(*) > 1)",
            )
            if (positions != 0L) violation("SCN-E: ${dmc.c.name}: CS-2 broken, $positions rendered positions hold two messages")
            val inbound = texts(dmc, outgoingSent = false)
            val twice = inbound.groupingBy { it }.eachCount().filterValues { it > 1 }
            if (twice.isNotEmpty()) violation("SCN-E: ${dmc.c.name}: CS-2 broken, rendered twice: $twice")
        }
    }

    /** §15.3's "one more message each way decrypts", both sent at once, with periodic jobs for two hours. */
    private fun sessionIsStillLive(w: World) {
        val start = maxOf(w.clock.millis, w.driver.time)
        act(aliceDm, send = true) { d -> d.engine.send(d.engine.contacts().single().id, PROBE_OUT, null) }
        act(bobDm, send = true) { d -> d.engine.send(d.engine.contacts().single().id, PROBE_BACK, null) }
        w.jobs(alice.c, start + 5 * MINUTE, start + LIVENESS_MILLIS)
        w.jobs(bob.c, start + 7 * MINUTE, start + LIVENESS_MILLIS)
        w.driver.runUntil(start + LIVENESS_MILLIS)
        val missing = buildList {
            if (PROBE_OUT !in texts(bobDm, outgoingSent = false)) add("alice → bob")
            if (PROBE_BACK !in texts(aliceDm, outgoingSent = false)) add("bob → alice")
        }
        if (missing.isNotEmpty()) violation("SCN-E: the session is not live after the run — ${missing.joinToString(" and ")} did not decrypt in ${LIVENESS_MILLIS / HOUR} h")
        notes += "liveness: both probes decrypted within ${LIVENESS_MILLIS / HOUR} h of quiescence (world minute ${start / MINUTE})"
    }

    companion object {
        const val E_HELLO = "e-hello"
        const val E_HI = "e-hi"
        const val E_PAIR = "e-pair"
        const val E_EARLY = "e-early"
        const val E_LATE = "e-late"
        const val E_DOOMED = "e-doomed"
        const val E_WAITING = "e-waiting"
        const val E_BACK = "e-back"
        const val E_HEAL = "e-heal"
        const val PROBE_OUT = "e-probe-out"
        const val PROBE_BACK = "e-probe-back"

        /** Weeks of ACCESS tokens each client holds from the start: `W0 … W0 + 5`. */
        const val TOKEN_WEEKS = 6

        /** Tokens per slot per week: each client has three own namespaces since Phase 11's S4-owner (§5.2: X_0, P_0, M_0), each at most once per slot. */
        const val TOKENS_PER_SLOT = 3

        const val HELLO_AT = HOUR
        const val HI_AT = 3 * HOUR
        const val PAIR_AT = 6 * HOUR

        /** Saturday 04:00 of `W0`: bob goes offline, before the renewal window (last 23 h of the week). */
        const val OFFLINE_AT = 20 * HOUR

        /** Tuesday 16:00 of `W0 + 1`: bob's registrations of `W0` and `W0 + 1` live. */
        val EARLY_AT: Long = boundary(1) + 40 * HOUR

        /** `start(W0 + 2) + 1 h`: bob's registration of `W0` is dead, the `c + 1` one of `W0 + 1` lives (§21.2 point 9). */
        val C1_ONLY_AT: Long = boundary(2) + HOUR

        /** Wednesday 16:00 of `W0 + 2`: only the `c + 1` registration accepts a deposit. */
        val LATE_AT: Long = boundary(2) + 2 * DAY + 16 * HOUR

        /** `start(W0 + 3) + 1 h`: the registrations of `W0 + 1`, bob's last, are dead (§21.2 point 9). */
        val LAPSE_AT: Long = boundary(3) + HOUR

        val DOOMED_AT: Long = boundary(3) + 2 * HOUR
        val WAITING_AT: Long = boundary(3) + 4 * DAY

        /** Monday 12:00 of `W0 + 4`: ten hours after [E_DOOMED]'s deadline, three days before [E_WAITING]'s. */
        val RETURN_AT: Long = boundary(4) + 12 * HOUR

        /** Friday 20:00 of `W0` (LOSE_KEYS), before the renewal window. */
        const val LOSS_AT = 12 * HOUR
        const val HEAL_AT = LOSS_AT + 4 * MINUTE

        /** LOSE_KEYS's phase from the loss to the healing check: where MC-14 and MC-15 act (`ScnETest.kill`). */
        const val LOSS_PHASE = "keys lost, healing"

        /** How long after the loss the healing may take: two dozen sessions of each client. */
        const val HEAL_BOUND = 6 * HOUR

        const val LIVENESS_MILLIS = 2 * HOUR

        fun nameOf(variant: Variant, mutant: DmMutants.Mutation?, control: Control?): String =
            (if (variant == Variant.OFFLINE) "SCN-E" else "SCN-E/LOSE_KEYS") +
                (mutant?.let { "/${it.id}" } ?: "") + (control?.let { "/$it" } ?: "")

        /** `CapabilityStore.refuse`'s statement and `OutboxStore.parkForCapability`'s park, verbatim. */
        private const val REFUSE_SQL = "UPDATE relay_capability SET state = ?5 WHERE relay_id = ?1 AND namespace_id = ?2 AND kind = ?3 " +
            "AND generation = ?4 AND state = 'usable'"
        private const val PARK_SQL = "UPDATE outbox_delivery SET state = 'wait_capability' WHERE operation_id = ?1 AND relay_id = ?2 AND state = 'pending'"

        /** [Control.REFUSAL_IGNORED]: a write credential's refusal marks nothing, and the refused delivery is not parked. */
        private val REFUSAL_IGNORED_REWRITE: (String, List<Any?>) -> Pair<String, List<Any?>> = { sql, args ->
            when {
                sql == REFUSE_SQL && args.getOrNull(2) == "write" -> Pair("$sql AND 0", args)
                sql == PARK_SQL -> Pair("$sql AND 0", args)
                else -> Pair(sql, args)
            }
        }
    }
}

/**
 * The client side of §21.2 point 7 in an [ScnE] run: every commit of either client is compared
 * with the one before it, on the raw connection, for each contact deposit credential (a `write` row
 * of a namespace that is not the client's own).
 *
 * - **A re-put of a refused credential** — a row that was `rejected` and now has a newer
 *   generation — must commit inside a time-triggered pass or a user send: the trigger is the one
 *   the wiring **scheduled** (`EntDmClient.trigger`), never the pass's own flag. The review found
 *   the first rule, which counted passes by their flag, let "a time-triggered pass on every
 *   `CAPABILITIES` hint" through (§22.25 item 14). A re-put in a hint pass, in the K20 hook's
 *   ACTIVATE, in a user action that is no send, or in a process no trigger of the wiring started
 *   (mutant MC-15's keeper) fails here, at its commit — so the kill no longer depends on the relay
 *   being asked again in the same session.
 * - **A refusal the sender heard parks** — a row that was `usable` and is now `rejected`, right
 *   after a refused store of that client at that relay into that namespace — leaves at least one
 *   delivery of the pair in `wait_capability` (§15.3's "then wait in `wait_capability`",
 *   `OutboxStore.parkForCapability`); counted per client ([parks]).
 *
 * The first snapshot of every boot is taken before any pass of the new process runs (a commit the
 * crash cut off before its hook ran is then simply not attributed, never misattributed).
 */
internal class CredentialWatch(private val scenario: ScnE, private val w: World) {

    private class Row(val generation: Long, val state: String)

    private val last = IdentityHashMap<Client, Map<String, Row>>()

    /** Re-puts of a refused credential, per client, and the triggers they committed under. */
    val reputs = HashMap<String, MutableMap<String, Long>>()

    /** Refusals the sender heard that parked a delivery, per client. */
    val parks = HashMap<String, Long>()

    fun install() {
        for (dmc in listOf(scenario.aliceDm, scenario.bobDm)) attach(dmc.c)
        val boot = w.onBoot
        w.onBoot = { c ->
            boot?.invoke(c)
            if (c === scenario.aliceDm.c || c === scenario.bobDm.c) attach(c)
        }
    }

    private fun attach(c: Client) {
        last[c] = rows(c)
        c.sql.onCommit += { committed(c) }
    }

    private fun rows(c: Client): Map<String, Row> {
        val out = HashMap<String, Row>()
        c.jdbc.query(
            "SELECT relay_id, namespace_id, generation, state FROM relay_capability WHERE kind = 'write' " +
                "AND namespace_id NOT IN (SELECT namespace_id FROM dm_own_namespace)",
        ) { out["${it.long(0)}|${Bytes.hex(it.blob(1))}"] = Row(it.long(2), it.string(3)) }
        return out
    }

    private fun relayName(c: Client, relayId: Long): String =
        c.relayIds.entries.firstOrNull { it.value.value == relayId }?.let { w.relays[it.key].name } ?: "relay#$relayId"

    private fun committed(c: Client) {
        val now = rows(c)
        val before = last.put(c, now) ?: return
        for ((key, row) in now) {
            val prev = before[key] ?: continue
            val relay = relayName(c, key.substringBefore('|').toLong())
            val nsHex = key.substringAfter('|')
            if (prev.state == "rejected" && row.generation > prev.generation) reput(c, relay, nsHex, prev.generation, row.generation)
            if (prev.state == "usable" && row.state == "rejected" && scenario.stores.lastStoreRefused(c.name, relay, nsHex)) parked(c, key, relay, nsHex, row.generation)
        }
    }

    private fun reput(c: Client, relay: String, nsHex: String, from: Long, to: Long) {
        val dmc = scenario.dm.clients[c] ?: return
        val trigger = dmc.trigger
        val legit = trigger?.timeTriggered == true || (trigger == EntDmClient.Trigger.USER && scenario.sending === dmc)
        val label = when {
            trigger == null -> "a process no trigger of the wiring started"
            trigger == EntDmClient.Trigger.USER && scenario.sending !== dmc -> "a user action that is no send"
            else -> "a ${trigger.name} " + if (trigger.timeTriggered) "pass" else "turn"
        }
        reputs.getOrPut(c.name) { java.util.TreeMap() }.merge(label, 1L, Long::plus)
        if (!legit) {
            violation(
                "SCN-E: ${c.name} re-put its refused deposit credential at $relay/${nsHex.take(8)} (generation $from → $to) in $label — " +
                    "not a time-triggered pass, a user send or a boot: the relay's refusal itself made it retry (§21.2 point 7)",
            )
        }
    }

    private fun parked(c: Client, key: String, relay: String, nsHex: String, generation: Long) {
        var waiting = 0L
        c.jdbc.query(
            "SELECT count(*) FROM outbox_delivery d JOIN outbox_op o ON o.operation_id = d.operation_id " +
                "WHERE d.relay_id = ?1 AND o.namespace_id = ?2 AND d.state = 'wait_capability'",
            listOf(key.substringBefore('|').toLong(), Bytes.unhex(nsHex)),
        ) { waiting = it.long(0) }
        if (waiting == 0L) {
            violation(
                "SCN-E: ${c.name}'s deposit credential at $relay/${nsHex.take(8)} was refused (generation $generation) and no delivery of the pair " +
                    "waits in wait_capability (§15.3, §21.2 point 9)",
            )
        }
        parks.merge(c.name, 1L, Long::plus)
    }

    /** A line of what the record holds (a measurement, not a check). */
    fun summary(): String = "credentials: refusals that parked a delivery $parks; re-puts of a refused credential by trigger $reputs"
}

/**
 * The relay side of every store of an [ScnE] run: which client stored which blob into which
 * namespace at which relay, in which of its relay sessions, and what the relay did with it —
 * accepted and charged it, or refused it (`unauthorized` or `quota`). Recorded through
 * `World.relayObserver`, chained after the entitlement world's own recorder, so a crash or a
 * network fault at the call hides nothing. CHECK calls that reached a relay are recorded too
 * ([checks]; a measurement).
 *
 * A store is **accepted** when the relay's charge count of `(namespace, blob)` grew at its
 * after-apply event, **refused** when it did not and the relay held no live copy before the call,
 * and **already held** otherwise — an identical re-store the relay answers without a charge, or a
 * refusal of a blob it already holds; neither is counted as a refusal, which keeps the checks below
 * conservative (they can only miss a refusal, never invent one).
 *
 * **The rules on refused stores (§21.2 point 7, CR-16), as the engine implements them**, checked
 * at the store that would break them, per client, relay and namespace:
 * - refused under a **new generation** of the credential — the refused one was put again — the
 *   client ran, since its last refused store there, a **time trigger** (counted where the wiring
 *   scheduled it, `EntDmClient.timeTriggers`: session starts, tails, timers, database opens), a
 *   **user send** (a send re-puts a credential that is not usable, `SendStep`'s plan) or a
 *   **reboot**. Nothing the relay answers can make the sender try again;
 * - refused under the **same** generation, the earlier refusal went **unheard** — the harness's own
 *   record (`Records.unanswered`) says that store reached the relay and no answer reached the
 *   engine (a timeout after apply, a transport closed under it, a death with it in flight) — or
 *   the client rebooted since (a death after the answer, before its park committed). A sender that
 *   hears `unauthorized` and simply retries under the same credential — never parked, never
 *   rejected (the review's `NEEDS_CAPABILITY` → `NOT_APPLIED` mutant) — fails here.
 *
 * **Why not §21.2 point 7's own words, "one retry per session".** They do not hold on the real
 * engine, and the first run of SCN-E measured it (§22.25 item 4): a session's first store can be
 * refused under the credential the previous session's consumer tail re-put, and its own start pass
 * then re-puts it again — two refused stores in one foreground session, 64 s apart. The per-session
 * maximum is reported ([summary]) rather than asserted.
 */
internal class StoreView(private val scenario: ScnE, private val w: World) {

    enum class Outcome { ACCEPTED, REFUSED, ALREADY_HELD }

    class Attempt(
        val client: String,
        val relay: String,
        val namespaceHex: String,
        val hashHex: String,
        val atMillis: Long,
        val session: String,
        val outcome: Outcome,
        /** For a failure message: the credential's generation, the client's triggers and its session. */
        val detail: String = "",
    ) {
        override fun toString(): String =
            "store@$relay/${namespaceHex.take(8)} of ${hashHex.take(8)} by $client in $session at ${atMillis / 1_000} s: $outcome" +
                (if (detail.isEmpty()) "" else " [$detail]")
    }

    /** A CHECK that reached a relay (a measurement: the checks a possible copy waits on). */
    class Check(val client: String, val relay: String, val hashes: List<String>, val atMillis: Long)

    val attempts = ArrayList<Attempt>()
    val checks = ArrayList<Check>()

    private class Before(val client: Client, val ns: NamespaceId, val hash: BlobHash, val charges: Int, val held: Boolean)

    /** One refused store: its generation, the client's triggers and boots, and the unanswered count of its (relay, namespace, blob) then. */
    private class Refusal(val generation: Long, val triggers: List<Long>, val boots: Int, val unansweredKey: List<Any>, val unanswered: Int)

    private var before: Before? = null
    private val sessions = IdentityHashMap<Session, String>()

    /** (client, relay, namespace) → its last refused store there. */
    private val lastRefusal = HashMap<List<String>, Refusal>()

    /** (client, relay, namespace) → whether the last store there that reached the relay was refused. */
    private val lastStore = HashMap<List<String>, Boolean>()

    fun lastStoreRefused(client: String, relay: String, namespaceHex: String): Boolean = lastStore[listOf(client, relay, namespaceHex)] == true

    fun install() {
        val inner = w.relayObserver
        w.relayObserver = { c, kind, info, reached ->
            inner?.invoke(c, kind, info, reached)
            observe(c, kind, info, reached)
        }
    }

    /**
     * What the client itself did that may re-put a refused credential: time triggers the wiring
     * scheduled, user sends ([ScnE.userSends]) and boots. Harness ground truth, never the relay's.
     */
    private fun triggers(c: Client): List<Long> =
        listOf(scenario.dm.clients[c]?.timeTriggers ?: -1, scenario.userSends[c.name] ?: 0L, c.boots.toLong())

    /** The write row's generation and state at [node] for [ns]: the credential the store presented (the lease read it, nothing ran since). */
    private fun credential(c: Client, node: RelayNode, ns: NamespaceId): Pair<Long, String> {
        var generation = -1L
        var state = "?"
        c.jdbc.query(
            "SELECT generation, state FROM relay_capability WHERE relay_id = ?1 AND namespace_id = ?2 AND kind = 'write'",
            listOf(c.id(node).value, ns.toByteArray()),
        ) {
            generation = it.long(0)
            state = it.string(1)
        }
        return generation to state
    }

    /** The credential, the client's triggers and its session (diagnostics). */
    private fun detail(c: Client, node: RelayNode, ns: NamespaceId): String {
        val (generation, state) = credential(c, node, ns)
        val (time, user, boots) = triggers(c)
        val dmc = scenario.dm.clients[c]
        val s = c.session
        return "credential g$generation $state; $time time triggers (${dmc?.timePasses} time-flagged passes, ${dmc?.hintPasses} hint passes), " +
            "$user user sends, boot $boots; session ${s?.kind} from ${s?.startedAt?.let { it / 1_000 }} s"
    }

    private fun sessionOf(c: Client): String {
        val s = c.session ?: return "${c.name}#none"
        return sessions.getOrPut(s) { "${c.name}#${sessions.size + 1}" }
    }

    private fun observe(c: Client, kind: EventKind, info: CallInfo, reached: Boolean) {
        if (info.kind == CallKind.CHECK && kind == EventKind.RELAY_AFTER_APPLY && reached) {
            checks += Check(c.name, info.relay, info.hashes, w.clock.millis)
            // A refusal of this CHECK is no refused store: [CredentialWatch] asks for a park only
            // when the last call of the pair that reached the relay was a refused store.
            lastStore[listOf(c.name, info.relay, info.namespace)] = false
            return
        }
        if (info.kind != CallKind.STORE) return
        val node = w.relays.firstOrNull { it.name == info.relay } ?: return
        val ns = NamespaceId(Bytes.unhex(info.namespace))
        val hash = BlobHash(Bytes.unhex(info.hashes.single()))
        when (kind) {
            EventKind.RELAY_BEFORE_SEND -> before = Before(c, ns, hash, node.model.charges[ns to hash] ?: 0, node.model.live(ns, hash, w.relayNow(node)))
            EventKind.RELAY_AFTER_APPLY -> {
                // The index this event is about to get on the armed client's bus: the store-fault
                // points of the sample (a store that reached the relay).
                if (reached && c === w.subject && w.bus.armed) scenario.storeEvents += w.bus.count + 1
                val b = before?.takeIf { it.client === c && it.ns == ns && it.hash == hash }
                before = null
                if (!reached || b == null) return
                val outcome = when {
                    (node.model.charges[ns to hash] ?: 0) > b.charges -> Outcome.ACCEPTED
                    b.held -> Outcome.ALREADY_HELD
                    else -> Outcome.REFUSED
                }
                val session = sessionOf(c)
                val detail = if (outcome == Outcome.REFUSED) detail(c, node, ns) else ""
                val attempt = Attempt(c.name, node.name, info.namespace, info.hashes.single(), w.clock.millis, session, outcome, detail)
                attempts += attempt
                lastStore[listOf(c.name, node.name, info.namespace)] = outcome == Outcome.REFUSED
                if (outcome == Outcome.REFUSED) refused(c, node, ns, hash, info.namespace, credential(c, node, ns).first)
            }
            else -> Unit
        }
    }

    private fun refused(c: Client, node: RelayNode, ns: NamespaceId, hash: BlobHash, namespaceHex: String, generation: Long) {
        val key = listOf(c.name, node.name, namespaceHex)
        val now = triggers(c)
        // Read before this call's own catch adds to it: the count this refusal must beat to have gone unheard.
        val unansweredKey = listOf<Any>(node.name, ns, hash)
        val refusal = Refusal(generation, now, c.boots, unansweredKey, w.records.unanswered[unansweredKey] ?: 0)
        val last = lastRefusal.put(key, refusal) ?: return
        val these = { attempts.filter { it.outcome == Outcome.REFUSED && listOf(it.client, it.relay, it.namespaceHex) == key }.takeLast(2) }
        if (last.generation != generation) {
            if (last.triggers == now) {
                violation(
                    "SCN-E: ${c.name}'s store into ${namespaceHex.take(8)} at ${node.name} was refused again under a credential put again with no " +
                        "time trigger, user send or reboot of ${c.name} in between — the relay's refusal itself made it retry (§21.2 point 7): ${these()}",
                )
            }
        } else {
            val unheard = (w.records.unanswered[last.unansweredKey] ?: 0) > last.unanswered
            if (!unheard && c.boots == last.boots) {
                violation(
                    "SCN-E: ${c.name}'s store into ${namespaceHex.take(8)} at ${node.name} was refused twice under credential generation $generation, " +
                        "the first refusal heard and no reboot in between — a refused credential must wait in wait_capability for a new " +
                        "generation (§15.3, §21.2 point 7): ${these()}",
                )
            }
        }
    }

    /** A line of what the record holds (a measurement, not a check). */
    fun summary(): String {
        val refused = attempts.filter { it.outcome == Outcome.REFUSED }
        val triples = refused.groupBy { listOf(it.client, it.relay, it.namespaceHex, it.session) }.values
        val bySession = triples.groupingBy { it.size }.eachCount().toSortedMap()
        val kind = Regex("session (\\w+) from")
        val repeatedIn = triples.filter { it.size > 1 }.groupingBy { kind.find(it.first().detail)?.groupValues?.get(1) ?: "?" }.eachCount()
        return "stores: ${attempts.size} reached a relay (${attempts.count { it.outcome == Outcome.ACCEPTED }} accepted, ${refused.size} refused, " +
            "${attempts.count { it.outcome == Outcome.ALREADY_HELD }} already held); refused by client ${refused.groupBy { it.client }.mapValues { it.value.size }}; " +
            "(relay, namespace, session) triples by refused stores in them: $bySession; those with more than one, by session kind: $repeatedIn; " +
            "${checks.size} CHECK calls reached a relay"
    }
}
