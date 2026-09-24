package org.ghost.messaging.entworld

import org.ghost.entitlement.engine.Counters
import org.ghost.entitlement.harness.EntConfig
import org.ghost.entitlement.harness.EntWorld
import org.ghost.messaging.api.AddContactResult
import org.ghost.messaging.api.CardSource
import org.ghost.messaging.api.ContactId
import org.ghost.messaging.api.Establishment
import org.ghost.messaging.api.MessageState
import org.ghost.messaging.api.SendResult
import org.ghost.messaging.api.TrustState
import org.ghost.network.EntitlementCrypto
import org.ghost.sync.api.Capabilities
import org.ghost.sync.api.Consumer
import org.ghost.sync.api.Namespaces
import org.ghost.sync.harness.CallInfo
import org.ghost.sync.harness.CallKind
import org.ghost.sync.harness.Client
import org.ghost.sync.harness.ClientSpec
import org.ghost.sync.harness.EventKind
import org.ghost.sync.harness.Invariants
import org.ghost.sync.harness.JournalMode
import org.ghost.sync.harness.ModelRelay
import org.ghost.sync.harness.World
import org.ghost.sync.harness.World.Companion.HOUR
import org.ghost.sync.harness.World.Companion.MINUTE
import org.ghost.sync.harness.foreground
import org.ghost.sync.harness.jobs
import java.util.concurrent.ConcurrentHashMap

/**
 * A mutation of the JD8 twin worlds: the entitlement-world half of a privacy mutant
 * (`dmworld/PrivacyMutants.kt`), implemented only in `src/test` as §15.7 requires. [rewrite] is a
 * statement rewrite on **every** client's executor — the one connection the sync engine, the
 * entitlement engine and the DM layer share — built per world, so it may read the world's clock;
 * [decorateCapabilities] and [decorateNamespaces] wrap the DM steps' own sync ports
 * (`DmDevice.HarnessOverride`), never the owner steps' and never the engines'.
 */
internal class EntMutation(
    val rewrite: ((World) -> (String, List<Any?>) -> Pair<String, List<Any?>>)? = null,
    val decorateCapabilities: ((Capabilities) -> Capabilities)? = null,
    val decorateNamespaces: ((Namespaces) -> Namespaces)? = null,
) {
    override fun toString(): String = "EntMutation"
}

/**
 * One twin of **JD8** (Phase 9 design §15.6: "JD8 redemptions and registrations depend only on own
 * namespaces and the week"; §14.1 T27: "a client's redemptions and registrations (count, minute,
 * relay, namespace) are identical in worlds that differ only in its DM activity, below quota
 * exhaustion"; §13.4's NI-K row: "a client's redemption and registration trace is identical with 0
 * and 30 contacts and any message volume").
 *
 * **The world.** The entitlement world of §15.1 variant (b) (§22.22): five clients, each with the
 * real entitlement engine (trial through the real issuer lane, the redeem lane against one
 * `ModelRedeemRelay` per ES slot) and the real DM stack over the same database, on four slot
 * relays. alice (armed), bob, carol and erin activate a trial at 1, 3, 5 and 7 minutes; dave is a
 * client **who never bought access** (`genesis`: his identity exists, he holds no token, so his
 * DM layer activates, publishes a card and registers nothing). Periodic jobs every 15 minutes carry
 * the lanes of all five, and every client has the **same foreground sessions in both twins** — the
 * user opens the app at the same minutes whether or not it writes. The world starts on the Friday
 * of access week 2975 at 08:00 and ends at `start(2976) + 3 h`, so each trace holds the first
 * redemptions (week 2975), the Friday capability's `c` and `c + 1` registrations, the renewal with
 * week-2976 tokens at the planner's EXPIRING PRF time on Sunday, and the renewal's `c + 1` rows
 * (week 2977): the week is part of what is compared.
 *
 * **The twins differ in exactly one thing, the DM activity.** In the [active] twin alice scans the
 * cards of bob, carol, erin and dave in person at 6 h and writes to each; the three who can be
 * reached accept and answer; alice writes again, sends bursts to bob and carol on Saturday, and all
 * Sunday — the renewal window — one of the three writes to her every hour and she answers half an
 * hour later (three texts each way every fourth hour), so the background sessions in which the
 * renewals run fetch and store messages too; after the boundary all four write once more — 95
 * texts, 94 of them to or from a reachable contact. dave's establishment runs its three attempt
 * windows out, because his bundle namespace has no FETCH registration: the relays refuse alice's
 * credential, so alice holds a **LOCAL need** — the need §13.4's planner must never redeem (PM-1b).
 * In the idle twin nobody adds anybody and nobody writes; the foreground sessions in which the
 * active twin's users write are opened in the idle twin too.
 *
 * **What is recorded.** The world's relay record (`EntDmWorld.relayEvents`, through
 * `World.relayObserver`, which the harness calls first at every relay event) gives every `REDEEM`
 * and `REGISTER` a relay saw, with the relay, the namespace and the world time; a `REDEEM`'s token
 * week is the issued token's (`EntRecords.issued`). A `RegisterKey` also names a period and a key
 * kind, which the record does not carry: they are read at the call's after-apply event from the
 * client's one `relay_key_registration` row of that (relay, namespace) whose lease is in flight
 * (`inflight = 1`; the lease transaction committed before the call and the result transaction
 * runs after it) — the arguments the call carried — and a call where that is not exactly one row is
 * counted ([Twin.unresolved]) and fails JD8.
 *
 * [everyCommit]: the entitlement world's every-commit check (`EntDmWorld.checkCommit`), on in the
 * report's run, which is also the control the JD8 kills are held against; the mutated worlds of
 * `DmPrivacyMutantTest` run with it off, because it stops PM-1b's world at the commit that installs
 * the capability ("alice: a redeemed capability on a LOCAL namespace", measured) before JD8 could
 * look. It is read-only, so a world runs the same with it on until the moment it would throw: the
 * control twins run with it off gave the same 186 calls at the same milliseconds (measured, §22.26).
 */
internal class Jd8Twin(
    val active: Boolean,
    private val entMutation: EntMutation?,
    private val everyCommit: Boolean,
) : EntDmScenario(if (active) "JD8/active" else "JD8/idle") {
    lateinit var carolDm: EntDmClient
    lateinit var erinDm: EntDmClient
    lateinit var daveDm: EntDmClient

    /** The clients in the order of their branches. */
    val all: List<EntDmClient> get() = listOf(aliceDm, bobDm, carolDm, erinDm, daveDm)

    /** The contacts alice can reach (they bought access), and the one she cannot. */
    val reachable: List<EntDmClient> get() = listOf(bobDm, carolDm, erinDm)

    /** alice's contact id for each peer she added (the active twin). */
    val contactIds = LinkedHashMap<String, ContactId>()

    /** Every text a user wrote, as (from, to, text), in order. */
    val written = ArrayList<Triple<String, String, String>>()

    /** `RegisterKey` arguments the record does not carry: index in `dm.relayEvents` → (period, kind). */
    val registrationKeys = HashMap<Int, Pair<Long, String>>()
    var unresolved = 0
        private set

    /** A generous trial, so a mutant that spends tokens on contacts does not starve the owner's own renewals. */
    override fun config(): EntConfig = configured(EntConfig(trialPerSlot = TRIAL_PER_SLOT))

    override fun build(w: World) {
        val relays = EntDmWorld.slotRelays(w)
        ent = EntWorld(w, relays, config())
        dm = EntDmWorld(w, ent)
        dm.checkEveryCommit = everyCommit
        dm.decorateCapabilities = entMutation?.decorateCapabilities
        dm.decorateNamespaces = entMutation?.decorateNamespaces
        val rewrite = entMutation?.rewrite?.invoke(w)
        fun client(name: String, armed: Boolean, genesis: Boolean, branch: Int): EntDmClient {
            val c = w.client(ClientSpec(name, armed = armed, rewrite = rewrite))
            c.directory(*relays.toTypedArray())
            return dm.attach(ent.attach(c, genesis), branch)
        }
        aliceDm = client("alice", armed = true, genesis = false, ALICE_BRANCH)
        alice = aliceDm.ent
        bobDm = client("bob", armed = false, genesis = false, BOB_BRANCH)
        bob = bobDm.ent
        carolDm = client("carol", armed = false, genesis = false, CAROL_BRANCH)
        erinDm = client("erin", armed = false, genesis = false, ERIN_BRANCH)
        daveDm = client("dave", armed = false, genesis = true, DAVE_BRANCH)

        // The registration arguments and the relay session of every event, read after
        // EntDmWorld's recorder appended the event.
        val recorder = w.relayObserver
        w.relayObserver = observer@{ c, kind, info, reached ->
            recorder?.invoke(c, kind, info, reached)
            // EntDmWorld records before-send and after-apply events only.
            if (kind == EventKind.RELAY_AFTER_RESPONSE) return@observer
            val index = dm.relayEvents.size - 1
            c.session?.let { s -> sessionOf[index] = sessions.getOrPut(s) { sessions.size } }
            if (kind == EventKind.RELAY_AFTER_APPLY && reached && info.kind == CallKind.REGISTER) registration(w, c, info, index)
        }

        // Identical in both twins: the trials, the jobs, and the user's foreground sessions.
        for ((i, dmc) in listOf(aliceDm, bobDm, carolDm, erinDm).withIndex()) w.trial(dmc.ent, dmc.c.name, (1 + 2 * i) * MINUTE)
        for ((i, dmc) in all.withIndex()) w.jobs(dmc.c, (25 + 2 * i) * MINUTE, END)
        for ((from, to) in ALICE_FOREGROUNDS) w.foreground(aliceDm.c, from, to)
        for (dmc in listOf(bobDm, carolDm, erinDm, daveDm)) for ((from, to) in PEER_FOREGROUNDS) w.foreground(dmc.c, from, to)
        for (h in SUNDAY_HOURS) {
            w.foreground(sundayPeer(h).c, SUNDAY + h * HOUR, SUNDAY + h * HOUR + 20 * MINUTE)
            w.foreground(aliceDm.c, SUNDAY + h * HOUR + 30 * MINUTE, SUNDAY + h * HOUR + 50 * MINUTE)
        }

        if (active) conversation(w)
        w.endMillis = END
    }

    /** Relay session of every recorded event (index in `dm.relayEvents` → session number). */
    val sessionOf = HashMap<Int, Int>()
    private val sessions = java.util.IdentityHashMap<org.ghost.sync.engine.Session, Int>()

    /** Sunday's peer at hour [h]: bob, carol and erin in turn. */
    private fun sundayPeer(h: Int): EntDmClient = reachable[h % reachable.size]

    private fun registration(w: World, c: Client, info: CallInfo, index: Int) {
        val node = w.relays.single { it.name == info.relay }
        val relayId = c.relayIds[node.index]?.value
        val rows = ArrayList<Pair<Long, String>>()
        if (relayId != null) {
            c.jdbc.query(
                "SELECT period_id, kind FROM relay_key_registration WHERE relay_id = ?1 AND namespace_id = ?2 AND inflight = 1",
                listOf(relayId, hexBytes(info.namespace)),
            ) { rows += it.long(0) to it.string(1) }
        }
        if (rows.size == 1) registrationKeys[index] = rows.single() else unresolved++
    }

    /** The active twin's user actions, each inside a foreground session both twins have. */
    private fun conversation(w: World) {
        // 6 h: alice scans four cards in person and writes to each (again at 6 h 20 for what is missing).
        for (t in listOf(6 * HOUR + MINUTE, 6 * HOUR + 20 * MINUTE)) {
            w.at(t, "alice adds her contacts and writes") {
                for (peer in listOf(bobDm, carolDm, erinDm, daveDm)) {
                    aliceDm.user { d ->
                        val name = peer.c.name
                        if (name !in contactIds) {
                            val before = d.engine.contacts().map { it.id }.toSet()
                            check(d.engine.addContact(peer.d().card(), CardSource.QR_IN_PERSON) == AddContactResult.ADDED) { "alice could not add $name's card" }
                            contactIds[name] = d.engine.contacts().single { it.id !in before }.id
                        }
                        write(d, "alice", name, "hello $name")
                    }
                }
            }
        }
        // 8 h, 9 h, 10 h: each peer who shows the request accepts it and answers once.
        for (t in listOf(8 * HOUR, 9 * HOUR, 10 * HOUR)) {
            for (peer in reachable) {
                w.at(t + 5 * MINUTE, "${peer.c.name} accepts and answers") {
                    peer.user { d ->
                        val request = d.engine.contacts().firstOrNull { it.trust == TrustState.REQUEST } ?: return@user
                        check(d.engine.acceptRequest(request.id)) { "${peer.c.name} could not accept alice's request" }
                        write(d, peer.c.name, "alice", "hi back from ${peer.c.name}")
                    }
                }
            }
        }
        // 11 h: alice writes once more to each peer whose answer arrived.
        for (t in listOf(11 * HOUR + 5 * MINUTE, 11 * HOUR + 20 * MINUTE)) {
            w.at(t, "alice writes again") {
                for (peer in reachable) {
                    val name = peer.c.name
                    if ("hi back from $name" !in inboundFrom(name)) continue
                    aliceDm.user { d -> write(d, "alice", name, "pair now $name") }
                }
            }
        }
        // Volume: Saturday bursts; all Sunday — the renewal window — a peer writes to alice every hour
        // and alice answers half an hour later, so every client's background sessions fetch or
        // store messages beside its renewal; Monday, after the boundary.
        rounds(w, 30 * HOUR, 31 * HOUR, mapOf("bob" to 8, "carol" to 2), mapOf("bob" to 4, "carol" to 1), "saturday")
        for (h in SUNDAY_HOURS) {
            val peer = sundayPeer(h)
            val name = peer.c.name
            val n = if (h % 4 == 0) 3 else 1
            w.at(SUNDAY + h * HOUR + 5 * MINUTE, "$name writes (sunday $h)") {
                peer.user { d -> for (i in 1..n) write(d, name, "alice", "sunday $h.$i from $name") }
            }
            w.at(SUNDAY + h * HOUR + 35 * MINUTE, "alice answers $name (sunday $h)") {
                aliceDm.user { d -> for (i in 1..n) write(d, "alice", name, "sunday $h.$i to $name") }
            }
        }
        rounds(w, BOUNDARY + HOUR, BOUNDARY + 2 * HOUR, mapOf("bob" to 1, "carol" to 1, "erin" to 1), mapOf("bob" to 1, "carol" to 1, "erin" to 1), "monday")
    }

    /** alice writes [out] texts to each peer at [aliceAt] + 5 min; each peer answers [back] at [peerAt] + 5 min. */
    private fun rounds(w: World, aliceAt: Long, peerAt: Long, out: Map<String, Int>, back: Map<String, Int>, label: String) {
        w.at(aliceAt + 5 * MINUTE, "alice writes ($label)") {
            for ((name, n) in out) aliceDm.user { d -> for (i in 1..n) write(d, "alice", name, "$label $i to $name") }
        }
        for ((name, n) in back) {
            val peer = reachable.single { it.c.name == name }
            w.at(peerAt + 5 * MINUTE, "$name answers ($label)") {
                peer.user { d -> for (i in 1..n) write(d, name, "alice", "$label $i back from $name") }
            }
        }
    }

    /** One text, once: queued through the facade and recorded as written. */
    private fun write(d: org.ghost.messaging.DmDevice, from: String, to: String, text: String) {
        if (written.any { it.first == from && it.third == text }) return
        val contact = if (from == "alice") checkNotNull(contactIds[to]) { "alice holds no contact $to" } else d.engine.contacts().single().id
        check(d.engine.send(contact, text, null) == SendResult.QUEUED) { "$from's '$text' was not queued" }
        written += Triple(from, to, text)
    }

    /** The texts alice shows from [peer] (her conversation with that contact), oldest first. */
    fun inboundFrom(peer: String): List<String> {
        val id = contactIds[peer] ?: return emptyList()
        return aliceDm.read { d -> d.engine.conversation(id, 500, null).reversed().filter { !it.outgoing }.mapNotNull { it.text } }.orEmpty()
    }

    /** What [dmc] shows of its one conversation: inbound texts and the states of its outgoing ones. */
    fun conversationOf(dmc: EntDmClient, contact: ContactId?): Pair<List<String>, Map<String, MessageState>> {
        val views = dmc.read { d ->
            val id = contact ?: d.engine.contacts().singleOrNull()?.id ?: return@read emptyList()
            d.engine.conversation(id, 500, null).reversed()
        }.orEmpty()
        return views.filter { !it.outgoing }.mapNotNull { it.text } to views.filter { it.outgoing && it.text != null }.associate { it.text!! to it.state }
    }

    companion object {
        const val CAROL_BRANCH = 0x61
        const val ERIN_BRANCH = 0x71
        const val DAVE_BRANCH = 0x81
        const val TRIAL_PER_SLOT = 8

        /** `start(2976)` in world milliseconds: the Friday 08:00 start plus 64 hours. */
        val BOUNDARY: Long = EntDmScenario.boundary(1)
        val END: Long = BOUNDARY + 3 * HOUR

        /** Sunday 00:00 of week 2975 (the renewal window is its hours 1 to 23), and the hours with traffic. */
        val SUNDAY: Long = BOUNDARY - 24 * HOUR
        val SUNDAY_HOURS: IntRange = 1..22

        val ALICE_FOREGROUNDS: List<Pair<Long, Long>> = listOf(6 * HOUR, 11 * HOUR, 30 * HOUR, BOUNDARY + HOUR)
            .map { it to it + 40 * MINUTE }
        val PEER_FOREGROUNDS: List<Pair<Long, Long>> = listOf(8 * HOUR, 9 * HOUR, 10 * HOUR, 31 * HOUR, BOUNDARY + 2 * HOUR)
            .map { it to it + 30 * MINUTE }

        fun hexBytes(hex: String): ByteArray = ByteArray(hex.length / 2) { hex.substring(2 * it, 2 * it + 2).toInt(16).toByte() }
    }
}

/**
 * **JD8**, the twin comparison and its report line (see [Jd8Twin] for the worlds).
 *
 * **Compared, per client who holds tokens** (alice, bob, carol and erin; dave, who holds none, must
 * have an empty trace in both twins): the multiset of the `REDEEM` and `REGISTER` calls relays saw,
 * each as `(kind, relay, namespace, token week or registration period, key kind)` — T27's count,
 * relay and namespace, and §15.6's week — which must be **equal** across the twins; and, in each
 * twin, every one of those calls on a namespace the client **owns** (the first half of §15.6's
 * sentence, and JD3's redeem-and-register clause). A failure prints the two multiset differences by
 * client, so the twin that holds the extra calls names the mutant.
 *
 * **T27's minute is measured and not compared** (§22.22 item 8 asked for the measurement, §22.26
 * records it). Each call of a key is paired with the same key's call of the other twin, in time
 * order, and the line reports how many pairs fall in the same minute and at the same millisecond,
 * and how many of the active twin's calls came after a message in their own relay session
 * ([Call.exposed]) — but a PASS does not require them equal, because they are not, in this world:
 * on three seeds the pairs agreed at the minute 186 of 186, 182 of 182 and 184 of 186 times. The
 * redeem lane waits between its steps with draws the harness hands out per call site in order
 * (`SiteRandom`), and DM work that holds a session open runs more lane steps (measured on the third
 * seed: alice's lane drew 927 waits in the active twin, 925 in the idle one), so every later wait,
 * and the step at which a renewal comes due, moves — two of alice's renewals by 17 s and 52 s,
 * across a minute. No registration came after a message in its session on any of the three seeds:
 * each runs in the first maintenance pass of a session, before that session's stores and fetches
 * (`WorkItem.Pass`, "registrations first"). The pairs a run moved are printed by `DmJd8Test`.
 *
 * **What makes it able to fail, and what keeps it from passing vacuously.** The twins must reach
 * their variable, or JD8 fails without comparing: the active twin's alice holds her four contacts,
 * every text of the three reachable ones was delivered and shows `SENT`, each of the four made relay
 * calls on its contacts' namespaces, dave's establishment did not complete, and every twin world ran
 * to its horizon with its end checks (structural invariants, `EntWorld.structural`, no DM pass
 * threw); the idle twin's clients hold no contact and made no such call; every `RegisterKey` had its
 * arguments read. Each compared trace must be non-empty and cover the week — token weeks 2975 and
 * 2976 and registration periods 2975, 2976 and 2977 — so a comparison over nothing, or over a world
 * that never renewed, fails; and alice's planner must have skipped a LOCAL need in the active twin,
 * so the path PM-1b mutates was taken. `Jd8SelfTest` holds the comparator to known answers, and the
 * mutants PM-1, PM-1b and PM-26 (`dmworld/PrivacyMutants.kt`) show it fails on a trace that depends
 * on DM activity.
 */
internal object Jd8 {

    /** One `REDEEM` or `REGISTER` a relay saw. [period]: the token's ACCESS week, or the registration period. */
    class Call(
        val client: String,
        val kind: CallKind,
        val relay: String,
        val namespaceHex: String,
        val period: Long,
        /** The registration's key kind (`deposit`, `read`, `fetch`); null for a `REDEEM`. */
        val keyKind: String?,
        val atMillis: Long,
        /**
         * The same client had moved a message — any call on a contact's namespace, or a fetch of its
         * own inbox — earlier in the **same relay session**: a call whose time the DM activity could
         * have moved (so true only in the active twin).
         */
        val exposed: Boolean = false,
    ) {
        val key: String get() = "$kind $relay ${namespaceHex.take(16)} p$period${keyKind?.let { " $it" } ?: ""}"

        override fun toString(): String = "$key at ${atMillis / MINUTE} min"
    }

    /** What one twin world left, read at its horizon. */
    class Twin(
        val active: Boolean,
        /** Client → the calls relays saw, in order. */
        val calls: Map<String, List<Call>>,
        /** Client → its own namespaces (hex). */
        val own: Map<String, Set<String>>,
        /** Client → relay calls it made on its contacts' DM namespaces (their inboxes and bundles). */
        val foreignDmCalls: Map<String, Int>,
        /** Client → contacts it holds. */
        val contacts: Map<String, Int>,
        /** Texts written whose recipient never showed them, or whose sender does not show them SENT. */
        val undelivered: List<String>,
        val delivered: Int,
        /** alice's establishment with dave (the active twin), or null. */
        val daveEstablishment: Establishment?,
        /** Decisions of alice's planner that skipped a need of a LOCAL namespace (`Counters.LOCAL_SKIPPED`). */
        val localSkipped: Long,
        /** `REGISTER` calls whose (period, kind) could not be read (JD8 fails on any). */
        val unresolved: Int,
        /** The world threw, or its end checks failed. */
        val failure: String?,
        val millis: Long,
    )

    class Result(val idle: Twin, val active: Twin) {
        /** The clients compared: the four who hold tokens. */
        val compared: List<String> get() = COMPARED

        /** Reasons the twins did not reach their variable (no comparison is then made). */
        val unreached: List<String> get() = reach(idle, active)

        /** Per compared client, the multiset differences ("N calls only in the active twin …"). */
        val differences: List<String> get() = differences(idle, active, compared)

        /** Calls on a namespace the caller does not own, in either twin. */
        val foreign: List<String> get() = foreign(idle) + foreign(active)

        /** What each compared trace lacks of the week it must cover, and dave's calls. */
        val coverage: List<String>
            get() = coverage(idle, compared) + coverage(active, compared) + dave(idle) + dave(active) +
                // The path PM-1b mutates: alice's planner met a LOCAL need (dave's refused FETCH
                // credential) and skipped it. Coverage, not reach: PM-1b's world skips none, and
                // that is the mutant's doing, not a world that missed its variable.
                (if (active.localSkipped > 0) emptyList() else listOf("alice's planner skipped no LOCAL need in the active twin"))

        /** Measured, reported, not compared (see [Jd8]'s note). */
        val timing: Timing get() = timing(idle, active, compared)

        val passed: Boolean
            get() = unreached.isEmpty() && differences.isEmpty() && foreign.isEmpty() && coverage.isEmpty() && timing.pairs > 0

        fun line(): String {
            val total = compared.sumOf { idle.calls[it].orEmpty().size }
            val perClient = compared.joinToString(", ") { name ->
                val calls = idle.calls[name].orEmpty()
                "$name ${calls.count { it.kind == CallKind.REDEEM }}+${calls.count { it.kind == CallKind.REGISTER }}"
            }
            val t = timing
            // A FAIL line says what was compared, not what a PASS would have shown.
            val head = "dm JD8: ${if (passed) "PASS" else "FAIL"} twins of 0 vs ${active.contacts["alice"] ?: 0} contacts " +
                "($WORLD_SHAPE), to start(${WEEK0 + 1}) + 3 h: redemptions and registrations of ${compared.size} clients " +
                "${if (passed) "equal" else "compared"} as (kind, relay, namespace, week or period, key kind) multisets over $total calls " +
                "($perClient redeem+register)" +
                (if (passed) ", every one on an own namespace" else "; own namespaces checked") +
                "; each ${if (passed) "covers" else "must cover"} token weeks {$WEEK0, ${WEEK0 + 1}} and periods {$WEEK0, ${WEEK0 + 1}, ${WEEK0 + 2}}"
            val reach = "; the twins differ in DM activity: active alice ${active.contacts["alice"] ?: 0} contacts, " +
                "${active.delivered} texts delivered, ${active.foreignDmCalls.values.sum()} relay calls on contacts' namespaces, " +
                "a LOCAL need skipped ${active.localSkipped} times by alice's planner (dave ${active.daveEstablishment}); " +
                "idle ${idle.contacts.values.sum()} contacts, ${idle.foreignDmCalls.values.sum()} such calls; " +
                "dave (no token) ${idle.calls["dave"].orEmpty().size} and ${active.calls["dave"].orEmpty().size} calls"
            val time = "; T27's minute measured, not compared (DM work moves the redeem lane's steps, §22.26): " +
                "${t.sameMinute} of ${t.pairs} pairs in the same minute, ${t.sameMillis} at the same millisecond, " +
                "${t.exposed} after a message in their relay session (${t.exposedRedeem} redemptions, ${t.exposed - t.exposedRedeem} registrations)"
            val problems = buildList {
                if (unreached.isNotEmpty()) add("the twins did not reach their variable: ${unreached.joinToString("; ")}")
                addAll(differences)
                if (foreign.isNotEmpty()) add("names a namespace it does not own: ${foreign.take(6).joinToString("; ")}")
                if (coverage.isNotEmpty()) add("coverage: ${coverage.take(6).joinToString("; ")}")
                if (t.pairs == 0) add("no paired call: compared nothing")
            }
            return head + reach + time + (if (problems.isEmpty()) "" else "; " + problems.joinToString("; "))
        }
    }


    /** The paired-call timing of the two twins (see [Jd8]'s note). */
    class Timing(
        val pairs: Int,
        val sameMinute: Int,
        val sameMillis: Int,
        /** Pairs whose active call was [Call.exposed], and of those the redemptions. */
        val exposed: Int,
        val exposedRedeem: Int,
        /** Pairs at different minutes, as lines. */
        val moved: List<String>,
    )

    const val WORLD_SHAPE: String = "5 clients of the entitlement world: 3 contacts reachable, 1 who holds no token"
    val COMPARED: List<String> = listOf("alice", "bob", "carol", "erin")
    val WEEK0: Long get() = EntDmScenario.WEEK0

    // ------------------------------------------------------------------ the comparison (pure)

    fun reach(idle: Twin, active: Twin): List<String> {
        val out = ArrayList<String>()
        if (idle.active || !active.active) out += "the twins are not one idle and one active world"
        idle.failure?.let { out += "the idle twin failed: $it" }
        active.failure?.let { out += "the active twin failed: $it" }
        if ((active.contacts["alice"] ?: 0) != 4) out += "active alice holds ${active.contacts["alice"] ?: 0} contacts, not 4"
        if (active.delivered == 0) out += "the active twin delivered no text"
        if (active.undelivered.isNotEmpty()) out += "the active twin did not deliver ${active.undelivered.take(3)}"
        for (name in COMPARED) {
            if ((active.foreignDmCalls[name] ?: 0) == 0) out += "active $name made no relay call on a contact's namespace"
        }
        if (active.daveEstablishment == null || active.daveEstablishment == Establishment.READY) out += "alice's establishment with dave is ${active.daveEstablishment}"
        if (idle.contacts.values.any { it != 0 }) out += "an idle client holds a contact: ${idle.contacts}"
        if (idle.foreignDmCalls.values.any { it != 0 }) out += "an idle client made relay calls on a DM namespace it does not own: ${idle.foreignDmCalls}"
        if (idle.unresolved != 0 || active.unresolved != 0) out += "${idle.unresolved + active.unresolved} RegisterKey calls whose period and kind could not be read"
        return out
    }

    private fun multiset(calls: List<Call>): List<String> = calls.map { it.key }

    fun differences(idle: Twin, active: Twin, clients: List<String>): List<String> = clients.mapNotNull { name ->
        val a = multiset(idle.calls[name].orEmpty())
        val b = multiset(active.calls[name].orEmpty())
        val onlyIdle = minusMultiset(a, b)
        val onlyActive = minusMultiset(b, a)
        if (onlyIdle.isEmpty() && onlyActive.isEmpty()) {
            null
        } else {
            "$name: ${describeCalls(onlyActive, "the active twin")}, ${describeCalls(onlyIdle, "the idle twin")}"
        }
    }

    fun foreign(twin: Twin): List<String> = twin.calls.flatMap { (name, calls) ->
        val own = twin.own[name].orEmpty()
        calls.filter { it.namespaceHex !in own }.map { "${if (twin.active) "active" else "idle"} $name $it" }
    }

    fun coverage(twin: Twin, clients: List<String>): List<String> = clients.flatMap { name ->
        val calls = twin.calls[name].orEmpty()
        val weeks = calls.filter { it.kind == CallKind.REDEEM }.map { it.period }.toSet()
        val periods = calls.filter { it.kind == CallKind.REGISTER }.map { it.period }.toSet()
        val where = if (twin.active) "active" else "idle"
        listOfNotNull(
            (setOf(WEEK0, WEEK0 + 1) - weeks).takeIf { it.isNotEmpty() }?.let { "$where $name redeemed no token of week(s) $it" },
            (setOf(WEEK0, WEEK0 + 1, WEEK0 + 2) - periods).takeIf { it.isNotEmpty() }?.let { "$where $name registered no period $it" },
        )
    }

    private fun dave(twin: Twin): List<String> {
        val n = twin.calls["dave"].orEmpty().size
        return if (n == 0) emptyList() else listOf("${if (twin.active) "active" else "idle"} dave, who holds no token, made $n calls")
    }

    /**
     * Each call of a key paired with the same key's call of the other twin, in time order: how many
     * pairs, how many in the same minute and millisecond, how many active calls came after a
     * message in their session, and every pair that fell at another minute.
     */
    fun timing(idle: Twin, active: Twin, clients: List<String>): Timing {
        var pairs = 0
        var sameMinute = 0
        var sameMillis = 0
        var exposed = 0
        var exposedRedeem = 0
        val moved = ArrayList<String>()
        for (name in clients) {
            val a = idle.calls[name].orEmpty().groupBy { it.key }
            val b = active.calls[name].orEmpty().groupBy { it.key }
            for ((key, left) in a) {
                val right = b[key].orEmpty()
                for ((x, y) in left.sortedBy { it.atMillis }.zip(right.sortedBy { it.atMillis })) {
                    pairs++
                    if (x.atMillis == y.atMillis) sameMillis++
                    if (x.atMillis / MINUTE == y.atMillis / MINUTE) {
                        sameMinute++
                    } else {
                        moved += "$name $key at minute ${x.atMillis / MINUTE} idle, ${y.atMillis / MINUTE} active"
                    }
                    if (y.exposed) {
                        exposed++
                        if (y.kind == CallKind.REDEEM) exposedRedeem++
                    }
                }
            }
        }
        return Timing(pairs, sameMinute, sameMillis, exposed, exposedRedeem, moved)
    }


    /**
     * Every paired call whose time differs between the twins, as a line for the test's output:
     * client, key, the two times (minute of the world and the millisecond remainder) and the
     * difference — the measurement behind the line's timing clause.
     */
    fun timingDetail(result: Result): List<String> {
        val out = ArrayList<String>()
        for (name in result.compared) {
            val a = result.idle.calls[name].orEmpty().groupBy { it.key }
            val b = result.active.calls[name].orEmpty().groupBy { it.key }
            for ((key, left) in a) {
                for ((x, y) in left.sortedBy { it.atMillis }.zip(b[key].orEmpty().sortedBy { it.atMillis })) {
                    if (x.atMillis == y.atMillis && !y.exposed) continue
                    out += "${if (y.exposed) "after a message: " else ""}$name $key idle ${x.atMillis / MINUTE} min +${x.atMillis % MINUTE} ms, active ${y.atMillis / MINUTE} min " +
                        "+${y.atMillis % MINUTE} ms, Δ ${(y.atMillis - x.atMillis) / 1_000.0} s"
                }
            }
        }
        return out
    }

    /** The calls of [a] that [b] lacks, as multisets. */
    fun minusMultiset(a: List<String>, b: List<String>): List<String> {
        val left = b.groupingBy { it }.eachCount().toMutableMap()
        return a.filter { e ->
            val n = left[e] ?: 0
            if (n > 0) {
                left[e] = n - 1
                false
            } else {
                true
            }
        }
    }

    /**
     * A multiset difference as the line names it. An empty side reads "none only in …", so the
     * phrase "calls only in the active twin" — what a JD8 kill expects — appears only when there are
     * such calls.
     */
    fun describeCalls(calls: List<String>, where: String): String {
        if (calls.isEmpty()) return "none only in $where"
        val kinds = calls.groupingBy { it.substringBefore(' ') }.eachCount().toSortedMap()
        return "${calls.size} calls only in $where ($kinds; first: ${calls.first()})"
    }

    // ------------------------------------------------------------------ running the twins

    /** The control of this JVM (the report's run, every-commit check on), computed once. */
    private val cache = ConcurrentHashMap<String, Result>()

    /**
     * JD8 over a twin pair of [seed]: the control ([mutation] null, the every-commit check on) or a
     * mutated pair (the check off; see [Jd8Twin]). Cached per [label].
     */
    fun run(seed: Long, label: String, mutation: EntMutation?): Result = cache.computeIfAbsent(label) {
        Result(twin(seed, false, mutation), twin(seed, true, mutation))
    }

    fun twin(seed: Long, active: Boolean, mutation: EntMutation?, everyCommit: Boolean = mutation == null): Twin {
        val s = Jd8Twin(active, mutation, everyCommit)
        val started = System.nanoTime()
        World(s.name, seed, JournalMode.WAL).use { w ->
            var failure: String? = null
            var built = false
            try {
                s.build(w)
                built = true
                w.driver.runUntil(w.endMillis)
                w.clients.forEach { Invariants.structural(it, "horizon") }
                s.ent.structural("horizon")
                s.dm.finalChecks()
            } catch (e: Exception) {
                failure = "${e.javaClass.simpleName}: ${e.message}"
            } catch (e: AssertionError) {
                failure = "${e.javaClass.simpleName}: ${e.message}"
            }
            try {
                if (!built) {
                    return Twin(active, emptyMap(), emptyMap(), emptyMap(), emptyMap(), emptyList(), 0, null, 0, 0, failure, 0)
                }
                return collect(s, w, failure, (System.nanoTime() - started) / 1_000_000)
            } finally {
                runCatching { s.dm.close() }
            }
        }
    }

    private fun collect(s: Jd8Twin, w: World, failure: String?, millis: Long): Twin {
        val world = s.dm
        val own = s.all.associate { dmc -> dmc.c.name to dmc.ownNamespaces().values.map(::hexOf).toSet() }
        // Each client's DM and bundle namespaces it registered and does not own (its contacts'), and its own inbox.
        val contactNamespaces = s.all.associate { dmc ->
            val dmNamespaces = HashSet<String>()
            dmc.c.jdbc.query("SELECT namespace_id FROM sync_namespace WHERE consumer IN (?1, ?2)", listOf(Consumer.DM.code, Consumer.PREKEYS.code)) {
                dmNamespaces += hexOf(it.blob(0))
            }
            dmc.c.name to (dmNamespaces - own.getValue(dmc.c.name))
        }
        val ownInbox = s.all.associate { dmc -> dmc.c.name to dmc.ownNamespaces()["inbox"]?.let(::hexOf) }

        // A message moved: any call on a contact's namespace, or a GET of the own inbox (a deposit fetched).
        fun traffic(e: EntDmWorld.RelayEvent): Boolean =
            e.namespaceHex in contactNamespaces[e.client].orEmpty() || (e.kind == CallKind.GET && e.namespaceHex == ownInbox[e.client])
        val calls = LinkedHashMap<String, MutableList<Call>>()
        for (dmc in s.all) calls[dmc.c.name] = ArrayList()
        val moved = HashSet<Pair<String, Int>>()
        for ((i, e) in world.relayEvents.withIndex()) {
            if (!e.seen) continue
            val session = s.sessionOf[i]
            if (session != null && traffic(e)) moved += e.client to session
            val exposed = session != null && (e.client to session) in moved
            val call = when (e.kind) {
                CallKind.REDEEM -> {
                    val week = world.ent.records.issued[e.hashes.single()]?.takeIf { it.kind == EntitlementCrypto.KIND_ACCESS }?.epoch ?: -1
                    Call(e.client, e.kind, e.relay, e.namespaceHex, week, null, e.atMillis, exposed)
                }
                CallKind.REGISTER -> {
                    val (period, kind) = s.registrationKeys[i] ?: (-1L to "?")
                    Call(e.client, e.kind, e.relay, e.namespaceHex, period, kind, e.atMillis, exposed)
                }
                else -> null
            } ?: continue
            calls.getOrPut(e.client) { ArrayList() } += call
        }
        // DM activity: relay calls a client made on its contacts' namespaces.
        val foreign = s.all.associate { dmc ->
            dmc.c.name to world.relayEvents.count { e ->
                e.seen && e.client == dmc.c.name && e.kind in setOf(CallKind.STORE, CallKind.LIST, CallKind.GET) &&
                    e.namespaceHex in contactNamespaces.getValue(dmc.c.name)
            }
        }
        val contacts = s.all.associate { dmc -> dmc.c.name to (dmc.read { d -> d.engine.contacts().size } ?: 0) }
        // Deliveries: every text written to a reachable peer shows SENT at its sender and arrived.
        val undelivered = ArrayList<String>()
        var delivered = 0
        for ((from, to, text) in s.written) {
            if (from == "alice" && to == "dave") continue
            val (sentState, arrived) = if (from == "alice") {
                val peer = s.reachable.single { it.c.name == to }
                s.conversationOf(s.aliceDm, s.contactIds[to]).second[text] to (text in s.conversationOf(peer, null).first)
            } else {
                val peer = s.reachable.single { it.c.name == from }
                s.conversationOf(peer, null).second[text] to (text in s.inboundFrom(from))
            }
            if (sentState == MessageState.SENT && arrived) delivered++ else undelivered += "$from->$to '$text' ($sentState, arrived=$arrived)"
        }
        val dave = s.contactIds["dave"]?.let { id -> s.aliceDm.read { d -> d.engine.contacts().singleOrNull { it.id == id }?.establishment } }
        val localSkipped = s.alice.engine?.counter(Counters.LOCAL_SKIPPED) ?: 0
        return Twin(s.active, calls, own, foreign, contacts, undelivered, delivered, dave, localSkipped, s.unresolved, failure, millis)
    }
}
