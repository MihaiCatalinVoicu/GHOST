package org.ghost.messaging.entworld

import org.ghost.entitlement.api.IdentityActivationHook
import org.ghost.entitlement.harness.Bytes
import org.ghost.entitlement.harness.EntClient
import org.ghost.entitlement.harness.EntWorld
import org.ghost.messaging.DmDevice
import org.ghost.messaging.MovableClock
import org.ghost.messaging.OwnerWorld
import org.ghost.messaging.api.ActivationOutcome
import org.ghost.messaging.api.MessageState
import org.ghost.messaging.port.EsSlot
import org.ghost.network.EntitlementCrypto
import org.ghost.sync.api.BlobHash
import org.ghost.sync.api.CapabilityNeed
import org.ghost.sync.api.CapabilitySource
import org.ghost.sync.api.Consumer
import org.ghost.sync.api.NamespaceId
import org.ghost.sync.api.SyncChange
import org.ghost.sync.engine.Session
import org.ghost.sync.harness.CallInfo
import org.ghost.sync.harness.CallKind
import org.ghost.sync.harness.Client
import org.ghost.sync.harness.EventKind
import org.ghost.sync.harness.ModelRelay
import org.ghost.sync.harness.RelayNode
import org.ghost.sync.harness.World
import org.ghost.sync.harness.violation
import java.security.MessageDigest
import org.ghost.sync.engine.SessionKind as SyncKind

/**
 * **The entitlement world of Phase 9 design §15.1 variant (b)**: DM clients whose capabilities come
 * from the real entitlement engine and whose keys are registered by the real `:sync` registration
 * lane, over the real Phase 7 transport — never from a "redeem fairy".
 *
 * > **Two capability variants:** (a) the *core world*, where a harness "redeem fairy" installs own
 * > write capabilities at the planner's times …; (b) the *entitlement world* on `EntHarness`, where
 * > the real redeem lane redeems trial tokens and the real work lane registers keys (JD8,
 * > week-boundary renewals, the registration healing rule). — §15.1
 *
 * **What is real here, layer by layer.** Every client is a Phase 7 harness [Client] (its own SQLite
 * file, the real `SyncEngine` with its lanes, leases, quorum, breakers and cursors, driven in virtual
 * time by the `HarnessDriver`) carrying the Phase 8 [EntClient] (the real `EntitlementEngine`: the
 * trial and purchase flows against the `ModelIssuer`, the **redeem lane** against one
 * `ModelRedeemRelay` per ES slot, the redeem hold, the quiet-run scheduler) **and** a real
 * `:messaging` stack — a [DmDevice] built over the *same* `SyncStores` (the one-stack-per-stores
 * rule `MessagingRuntime` states), with the real DM context in `ghost-dm-host`. So:
 *  - an own namespace's **write capability** exists only because the redeem lane presented a token
 *    of that relay's slot and week to that relay's `ModelRedeemRelay`, which verified the blind-RSA
 *    signature and the nullifier and minted a v2 capability under the relay's own MAC key;
 *  - a **key registration** (`RegisterKey`, §4.4) exists only because the `:sync` work lane ran a
 *    `relay_key_registration` row that REGROWS requested, with such a capability, at a
 *    [ModelRelay] that accumulates records exactly as `register.txt` pins;
 *  - a **deposit** into a contact's inbox is stored only because the relay found the owner's live
 *    DEPOSIT registration for the credential's verifier and charged the deposit to its allowance
 *    (`DepositLedger`, §4.5); a **read** of one's own inbox only because the READ verifier is
 *    registered; a **bundle fetch** only because the FETCH verifier is.
 *
 * **Checked while the world runs, not only at its end** ([checkCommit], [checkScopes]): after every
 * commit of every client, every capability row it holds is either a capability a `ModelRedeemRelay`
 * minted (for a REDEEM namespace, the one it names) or a bearer credential v3 the DM layer derived
 * (write-kind only as a contact's DEPOSIT credential); and after every store a relay applied, every
 * capability that relay has charged a store to is one a redeem relay minted. A shortcut that is
 * installed and replaced again between two checks would have to do so without a single commit.
 *
 * Nothing in this file installs a capability, runs a registration or moves a blob. What it does is
 * the wiring `:app` does on a device (`MessagingWiring`, `GhostApp`), in the driver's virtual time:
 *  - **the K20 hook** (§13.4): the entitlement engine calls [EntClient.activationHook] after a trial
 *    activation or a restore; like `MessagingWiring.activationHook` it **posts** the DM layer's
 *    ACTIVATE (a process action at the same instant, which a crash drops as it drops the wiring
 *    thread's queue) and returns, and §21.12 point 2's resume covers a post that never ran;
 *  - **the relay-session-start time trigger** (`MessagingWiring.sessionHooks`, §21.9 rule 1): a
 *    time-triggered DM pass when a relay session's transport is READY, posted before the
 *    entitlement participant starts, as the wiring orders it;
 *  - **the consumer tail** (§13.3 item 6): a time-triggered pass after every background session
 *    ends (lanes, redeem hold and transport close first) and after every quiet run, with the job
 *    budget's deadline — through `World.onSessionEnd`, which no scenario's `foreground` replaces;
 *  - **the inbox listener** (§13.7): `INBOX`, `OUTCOMES`, `CAPABILITIES` and `TOPOLOGY` hints post
 *    one coalesced hint pass, as `DmActor.onChange` does;
 *  - **the in-process timer** (§10.7 trigger 1, §21.9 rule 1): one resettable wake at
 *    `min(row deadlines, owner wake)`, which is `MessagingRuntime`'s `ExpirySchedule` arrangement;
 *  - **a database open** after a reboot is a time trigger (§21.12 point 2).
 * A pass that throws an `Exception` ends and is recorded ([swallowed]), which is what the actor
 * thread does on a device; an `Error` — an injected crash, an invariant violation — is not caught.
 * A timer that re-arms at once, or a hint that re-posts itself, more than [MAX_AT_ONE_INSTANT] times
 * at one virtual instant is a violation (an engine that never settles), not a hang.
 *
 * **What is a declared narrowing, not a shortcut** (see §22.22 of the design for the full list):
 *  - the DM context of a client opens from its MESSAGING branch bytes, as every DM world's does,
 *    not from the entitlement identity's root, so the K20 hook's *reopen* is not modelled — only its
 *    ACTIVATE; the context is treated as *closed* (no DM pass runs) while the entitlement identity
 *    does not exist, which is what `MessagingWiring` does with no stored identity;
 *  - the DM slot table is the entitlement schedule's slots mapped through the client's relay
 *    directory (`DirectoryEsSlots`' rule), fixed for the world: the harness schedule has one slot
 *    table for every week, so a slot-table change (§5.2) is not expressible here;
 *  - the "process" of a client lives from one crash to the next, so the in-process timer fires
 *    between jobs as if the app were alive; a device whose process the OS killed between jobs keeps
 *    only the session-start, database-open and alarm triggers.
 *
 * The relays are four ES slots over two operators, at the onions and operator ids every DM world
 * uses (`OwnerWorld.onion`), so `DmDevice`'s own relay directory rows and the entitlement schedule's
 * slot table name the same four relays; each [ModelRelay] serves its slot (§21.2 point 3), so a
 * bearer credential v3 naming another slot is refused.
 */
internal class EntDmWorld(val w: World, val ent: EntWorld) {
    val clients = LinkedHashMap<Client, EntDmClient>()

    /** Exceptions a DM pass threw that a device's actor thread would have swallowed, with their client. */
    val swallowed = ArrayList<String>()

    /**
     * The every-commit and every-store checks of the class note. On in every world; the one test
     * that turns it off ([EntDmConversation.fairyAt] without it) shows what the end checks alone
     * catch.
     */
    var checkEveryCommit: Boolean = true

    init {
        check(ent.w === w) { "the entitlement world belongs to another sync world" }
        val boot = w.onBoot
        w.onBoot = { c ->
            boot?.invoke(c)
            clients[c]?.boot()
        }
        // The DM time trigger first, then the entitlement participant: `sessionHooks` calls
        // `onRelaySessionStart()` before `participant.onRelaySession(session)`.
        val start = w.onSessionStart
        w.onSessionStart = { c, s ->
            clients[c]?.relaySessionStarted(s)
            start?.invoke(c, s)
        }
        val end = w.onSessionEnd
        w.onSessionEnd = { c, s ->
            end?.invoke(c, s)
            clients[c]?.sessionFinished(s)
        }
        val job = w.runJob
        w.runJob = { c ->
            val dm = clients[c]
            val quietBefore = dm?.ent?.quietRuns?.size
            job(c)
            dm?.afterJob(quietBefore)
        }
        check(w.relayObserver == null) { "the relay observer is taken" }
        w.relayObserver = { c, kind, info, reached -> observe(c, kind, info, reached) }
        // The DM layer, not the Phase 7 oracle, consumes the DM and bundle namespaces: IN-1 over
        // them is this world's own check ([quiescenceProblems]).
        val exempt = w.in1Exempt
        w.in1Exempt = { c, ns -> exempt(c, ns) || clients[c]?.consumesNamespace(ns) == true }
        // The relays' key registrations and deposit ledgers join the crash digest (ModelRelay's own
        // digest leaves them out). The DM layer's durable state is the client's database, which
        // `Invariants.dump` already reads table by table; its in-process counters are not state a
        // reboot keeps.
        val extra = w.extraState
        w.extraState = { extra() + w.relays.map { "relay-keys ${it.name} ${it.model.keysDigest()}" } }
    }

    /**
     * Adds the DM layer to [ec] (already attached to [ent]): a [DmDevice] over the client's own
     * executor and stores, on MESSAGING branch [branch], with the K20 hook wired.
     */
    fun attach(ec: EntClient, branch: Int): EntDmClient {
        check(ent.clients[ec.c] === ec) { "attach the entitlement engine first" }
        check(clients.values.none { it.branch == branch }) { "two clients on one MESSAGING branch" }
        val dm = EntDmClient(this, ec, branch)
        clients[ec.c] = dm
        dm.boot()
        return dm
    }

    fun dm(c: Client): EntDmClient = requireNotNull(clients[c]) { "${c.name} has no DM layer" }

    /**
     * The DM slot table of [c]: every slot of the entitlement schedule valid this week, served by the
     * relay directory entry at the slot's onion, with that relay's operator — `DirectoryEsSlots`'
     * rule on the schedule the entitlement engine accepted (the harness schedule is fixed).
     */
    fun esSlots(c: Client): List<EsSlot> {
        val week = ModelRelay.week(w.clock.epochSeconds())
        return ent.schedule.slots.filter { it.validIn(week) }.sortedBy { it.slot }.mapNotNull { slot ->
            val node = w.relays.firstOrNull { it.address == slot.onion } ?: return@mapNotNull null
            EsSlot(slot.slot, c.id(node), node.operatorId)
        }
    }

    // ------------------------------------------------------------------ the relay-side record

    /**
     * One relay event of one call, attributed to the client that made it: the raw material of the
     * relay-side view JD8, SCN-E and the OS suite will read. [client] is ground truth — a relay sees
     * a circuit, not a name — and every other field is what the call carried: the [event]
     * (`RELAY_BEFORE_SEND`: the call was about to leave, nothing applied; `RELAY_AFTER_APPLY`: it got
     * past the reachability check and its latency ran, and [reached] says whether the request
     * reached the relay before its deadline), the operation (`REDEEM`, `REGISTER`, `STORE`, `LIST`,
     * `GET`, `CHECK`, and `ISSUER` for the issuer), the relay, the namespace, the hashes the call
     * named (a REDEEM's token nullifier, a store's blob), and the times: [atMillis] in world
     * milliseconds and [relayEpochSeconds] on the relay's own clock — at after-apply, the instant the
     * relay applied it.
     *
     * Recorded through `World.relayObserver`, which the harness calls **first** at every relay event
     * — before the fault plan and before any scenario hook — so an injected crash or network fault
     * at after-apply, and a hook a scenario swaps in, hide nothing.
     */
    class RelayEvent(
        val client: String,
        val event: EventKind,
        val kind: CallKind,
        val relay: String,
        val namespaceHex: String,
        val hashes: List<String>,
        val atMillis: Long,
        val relayEpochSeconds: Long,
        val reached: Boolean,
    ) {
        /** The relay saw this call: its after-apply event, with the request in time. */
        val seen: Boolean get() = event == EventKind.RELAY_AFTER_APPLY && reached

        override fun toString(): String =
            "$kind@$relay/${namespaceHex.take(8)} by $client ${event.name.removePrefix("RELAY_").lowercase()}" +
                (if (event == EventKind.RELAY_AFTER_APPLY && !reached) " (lost)" else "") + " at ${atMillis / 60_000} min"
    }

    /** Every relay event of every client (before-send and after-apply), in order (see [RelayEvent]). */
    val relayEvents = ArrayList<RelayEvent>()

    /** Calls a relay saw, in order: [relayEvents] at after-apply with the request in time. */
    fun seen(): List<RelayEvent> = relayEvents.filter { it.seen }

    private fun observe(c: Client, kind: EventKind, info: CallInfo, reached: Boolean) {
        if (kind == EventKind.RELAY_AFTER_RESPONSE) return
        val node = w.relays.firstOrNull { it.name == info.relay }
        val relayNow = node?.let { w.relayNow(it) } ?: w.clock.trueEpochSeconds()
        relayEvents += RelayEvent(c.name, kind, info.kind, info.relay, info.namespace, info.hashes, w.clock.millis, relayNow, reached)
        if (info.kind == CallKind.STORE && node != null) {
            if (kind == EventKind.RELAY_BEFORE_SEND) scopesBefore = node.model.capabilityScopes()
            if (kind == EventKind.RELAY_AFTER_APPLY && reached) checkScopes(node, scopesBefore)
        }
    }

    // ------------------------------------------------------------------ checks

    private var mintedCount = -1
    private var mintedScopes: Set<BlobHash> = emptySet()

    /** The relay's quota-ledger scopes at the before-send event of the store in flight. */
    private var scopesBefore: Set<BlobHash> = emptySet()

    /** SHA-256 of every capability a `ModelRedeemRelay` minted (the relay's quota-ledger key). */
    private fun mintedScopes(): Set<BlobHash> {
        if (ent.records.minted.size != mintedCount) {
            mintedScopes = ent.records.minted.keys.map { ModelRelay.sha256(Bytes.unhex(it)) }.toSet()
            mintedCount = ent.records.minted.size
        }
        return mintedScopes
    }

    /**
     * After a client's store [node] applied: a capability the store was charged to that the relay's
     * quota ledger did not hold before it (its scope, SHA-256 of the token) is one a redeem relay
     * minted. A deposit is charged to a registration instead and adds no scope; `World.otherWrite`,
     * which stores straight into the model under a token of its own, is no client's store and is
     * never read here.
     */
    fun checkScopes(node: RelayNode, before: Set<BlobHash>) {
        if (!checkEveryCommit) return
        val minted = mintedScopes()
        val foreign = node.model.capabilityScopes().count { it !in before && it !in minted }
        if (foreign > 0) violation("no fairy: ${node.name} charged a client's store to a capability no redeem relay minted")
    }

    /**
     * After every commit of [dm]'s client: every `relay_capability` row is a capability a
     * `ModelRedeemRelay` minted for that row's own REDEEM namespace, or a bearer credential v3 the
     * DM layer derived for the row's namespace (a write row only as a contact's DEPOSIT
     * credential). Anything else — a capability `ModelRelay.mint` made, a v1 operator token, a
     * redeemed capability moved to another namespace — is a harness shortcut or an engine bug.
     */
    fun checkCommit(dm: EntDmClient) {
        if (!checkEveryCommit) return
        val c = dm.c
        val sources = HashMap<String, String>()
        c.jdbc.query("SELECT namespace_id, capability_source FROM sync_namespace") { sources[Bytes.hex(it.blob(0))] = it.string(1) }
        c.jdbc.query("SELECT namespace_id, kind, token FROM relay_capability") { r ->
            val ns = Bytes.hex(r.blob(0))
            val kind = r.string(1)
            val token = r.blob(2)
            val credential = ModelRelay.credential(token)
            if (credential != null) {
                if (Bytes.hex(credential.namespace.toByteArray()) != ns) violation("${c.name}: a bearer credential installed for another namespace")
                if (kind == "write" && credential.kind != ModelRelay.KIND_DEPOSIT) violation("${c.name}: a write row holds a bearer credential of kind ${credential.kind}")
                return@query
            }
            if (kind != "write") violation("no fairy: ${c.name} holds a read capability that is no bearer credential v3 (${ns.take(8)})")
            if (Bytes.hex(token) !in ent.records.minted) {
                violation("no fairy: ${c.name} holds a write capability for ${ns.take(8)} that no redeem relay minted")
            }
            val header = ModelRelay.header(token)
            if (header == null || Bytes.hex(header.namespace.toByteArray()) != ns) violation("${c.name}: a redeemed capability installed for another namespace")
            if (sources[ns] != CapabilitySource.REDEEM.name.lowercase()) violation("${c.name}: a redeemed capability on a LOCAL namespace")
        }
    }

    /**
     * Unmet quiescence conditions of the DM layer:
     *  - IN-1 over the namespaces the DM layer consumes (every live blob an honest relay holds in a
     *    listened DM or bundle namespace with a read path, other than the client's own, has been
     *    consumed — its `inbox_blob` row is `done`);
     *  - **nothing owed and nothing given up**, S10b's oracle (`DmScenario.nothingOwed`), over this
     *    world's tables: no pending send, no item waiting to be stored, no scheduled control, no DM
     *    outbox op the engine has not released, no DM inbox blob not consumed, no establishment in
     *    progress, no contact whose sessions lack a `current` slot, no control item that ended failed
     *    or indeterminate, and no outgoing message `FAILED` or `INDETERMINATE` outside
     *    [expectedFailures]. One exemption, the entitlement world's own: an op of an **own**
     *    namespace of a client the app shows as uncovered (`EntClient.uncovered`: no ACCESS token of
     *    this week or later, no pack in progress) waits for a purchase, which is the user's, not the
     *    engine's (the entitlement liveness premise waits for it the same way);
     *  - the DM side of the premise `EntWorld` skips: no **LOCAL** need waits (a contact's DEPOSIT or
     *    FETCH credential missing, refused or exhausted), since no token can meet one and only the DM
     *    layer can — a need that is expiring is not waiting;
     *  - no DM pass has thrown.
     */
    fun quiescenceProblems(expectedFailures: Set<String> = emptySet()): List<String> {
        val out = ArrayList<String>()
        if (swallowed.isNotEmpty()) out += "a DM pass threw: ${swallowed.first()}"
        val dmConsumers = listOf(Consumer.DM.code, Consumer.PREKEYS.code)
        for ((c, dm) in clients) {
            val listened = ArrayList<ByteArray>()
            c.jdbc.query("SELECT namespace_id FROM sync_namespace WHERE listening = 1 AND consumer IN (?1, ?2)", dmConsumers) { listened += it.blob(0) }
            val own = w.ops.values.filter { it.client === c }.map { it.namespace to it.hash }.toSet()
            for (ns in listened) {
                val relays = ArrayList<Long>()
                c.jdbc.query(
                    "SELECT nr.relay_id FROM namespace_relay nr JOIN relay_directory rd ON rd.relay_id = nr.relay_id " +
                        "WHERE nr.namespace_id = ?1 AND rd.state = 'active' AND EXISTS (SELECT 1 FROM relay_capability k " +
                        "WHERE k.relay_id = nr.relay_id AND k.namespace_id = nr.namespace_id AND ((k.kind = 'read' AND k.state = 'usable') " +
                        "OR (k.kind = 'write' AND k.state IN ('usable', 'exhausted'))) AND (k.expires_hour IS NULL OR k.expires_hour > ?2))",
                    listOf(ns, w.clock.epochSeconds()),
                ) { relays += it.long(0) }
                for (relayId in relays) {
                    val node = c.relayIds.entries.firstOrNull { it.value.value == relayId }?.let { w.relays[it.key] } ?: continue
                    if (!node.honest) continue
                    val namespace = NamespaceId(ns)
                    for (m in node.model.liveMembers(namespace, w.relayNow(node))) {
                        if ((namespace to m.hash) in own) continue
                        var state: String? = null
                        c.jdbc.query("SELECT state FROM inbox_blob WHERE namespace_id = ?1 AND blob_hash = ?2", listOf(ns, m.hash.toByteArray())) { state = it.string(0) }
                        if (state != "done") out += "${c.name}: DM IN-1: a live blob on ${node.name} in a listened DM namespace is ${state ?: "not listed"}"
                    }
                }
            }
            dm.owedProblems(out, expectedFailures)
        }
        return out
    }

    /** At the end of a run: nothing a DM pass threw was swallowed (a fault-free run owes none). */
    fun finalChecks() {
        if (swallowed.isNotEmpty()) violation("a DM pass threw ${swallowed.size} time(s); first: ${swallowed.first()}")
    }

    /**
     * Closes every client's DM context (native keys) and actor. `World.close` cannot reach them, so
     * whoever ends a run calls this once its checks are done ([EntDmScenario.finalChecks] does); a
     * run that stops early leaves them to the JVM's end.
     */
    fun close() {
        for (dm in clients.values) dm.close()
    }

    // ------------------------------------------------------------------ evidence

    /**
     * One `RedeemToken` request a relay received ([seen] `REDEEM` events): when it arrived, in world
     * milliseconds ([atMillis]) and on the relay's clock ([relayEpochSeconds], the time the redeem
     * model was called with), where, by whom, for which namespace, the token's nullifier, and the
     * ACCESS week of that token (−1 for bytes that are no ACCESS token the world issued).
     */
    class Redemption(
        val client: String,
        val atMillis: Long,
        val relayEpochSeconds: Long,
        val relay: String,
        val namespaceHex: String,
        val nullifier: String,
        val week: Long,
    ) {
        override fun toString(): String = "redeem@$relay/${namespaceHex.take(8)} by $client w$week at ${atMillis / 60_000} min"
    }

    /** Every redemption request a relay received, in order of arrival (see [Redemption]). */
    fun redemptions(): List<Redemption> = seen().filter { it.kind == CallKind.REDEEM }.map { e ->
        val nullifier = e.hashes.single()
        val week = ent.records.issued[nullifier]?.takeIf { it.kind == EntitlementCrypto.KIND_ACCESS }?.epoch ?: -1
        Redemption(e.client, e.atMillis, e.relayEpochSeconds, e.relay, e.namespaceHex, nullifier, week)
    }

    override fun toString(): String = "EntDmWorld"

    companion object {
        /** The world's ES slots: four relays over two operators, as every DM world has. */
        const val SLOTS: Int = 4
        const val OPERATORS: Int = 2

        /** Re-arms of the timer, or hint passes, at one virtual instant before it is a finding. */
        const val MAX_AT_ONE_INSTANT: Int = 256

        /**
         * The four slot relays, at the onions and operators `DmDevice` writes into its own relay
         * directory (`OwnerWorld.onion(i)`, `OwnerWorld.operatorId(i % 2)`), each serving its slot.
         * Keyed like `World.relay`, so a seed names the relays' MAC keys.
         */
        fun slotRelays(w: World): List<RelayNode> = (0 until SLOTS).map { i ->
            val name = "S$i"
            val key = MessageDigest.getInstance("SHA-256").digest("relay-key|${w.seed}|$name".toByteArray())
            val node = RelayNode(w.relays.size, name, OwnerWorld.onion(i), OwnerWorld.operatorId(i % OPERATORS), ModelRelay(name, key), null, 0)
            check(w.relays.none { it.address == node.address }) { "duplicate onion" }
            node.model.slot = i
            w.relays += node
            node
        }
    }
}

/**
 * One client's DM layer in an [EntDmWorld]: per process (rebuilt at every boot) a [DmDevice] over
 * the client's executor and `SyncStores`, its clock, and the triggers of [EntDmWorld]'s class note.
 */
internal class EntDmClient(val world: EntDmWorld, val ent: EntClient, val branch: Int) {
    val c: Client get() = ent.c
    private val w: World get() = ent.w

    /** The DM layer's clock: the world's device clock, copied in before every DM action. */
    val clock = MovableClock(w.clock.epochSeconds())

    var device: DmDevice? = null
        private set

    /** The running process's device. */
    fun d(): DmDevice = checkNotNull(device) { "${c.name} has no DM device" }

    private var hintPending = false
    private var timerToken = 0L
    private var zeroTimers = 0
    private var zeroAt = -1L
    private var hintsHere = 0
    private var hintsAt = -1L

    /** Passes run, by kind (diagnostics for a report line). */
    var timePasses: Long = 0
        private set
    var hintPasses: Long = 0
        private set

    /** What the K20 hook's ACTIVATE answered, in order. */
    val activations = ArrayList<ActivationOutcome>()

    /** A process start: the old context goes (a killed process closes nothing else), a new stack is built. */
    fun boot() {
        device?.close()
        device = null
        hintPending = false
        timerToken++
        zeroTimers = 0
        zeroAt = -1L
        hintsHere = 0
        hintsAt = -1L
        sync()
        val built = DmDevice(
            branch = branch,
            slotCount = EntDmWorld.SLOTS,
            operators = EntDmWorld.OPERATORS,
            startSeconds = clock.now,
            harness = DmDevice.HarnessOverride(c.sql, clock, c.boots - 1, stores = c.stores),
        )
        built.slots = world.esSlots(c)
        device = built
        installListener()
        // Posts and returns, as `MessagingWiring.activationHook` does (its wiring thread): the
        // engine's call is over before ACTIVATE runs, and a crash in between drops the post.
        ent.activationHook = IdentityActivationHook { restored ->
            w.driver.scheduleProcess(w.clock.millis, c, "dm-activate:${c.name}") { activated(restored) }
        }
        c.sql.onCommit += { world.checkCommit(this) }
        // §21.12 point 2: a database open is a time trigger.
        if (c.boots > 1) w.driver.scheduleProcess(w.clock.millis, c, "dm-db-open:${c.name}") { timePass() }
    }

    fun sync() {
        clock.now = w.clock.epochSeconds()
        clock.monotonic = w.clock.millis
    }

    /**
     * The one listener slot of the client's `SyncDatabase`: the Phase 7 oracle's drain (the rule
     * `Client.boot` installs, for namespaces a scenario registered through `Client.namespace`) and
     * the DM actor's hint (`DmActor.onChange`).
     */
    private fun installListener() {
        val client = c
        c.stores.inbox.setListener { changes ->
            if (SyncChange.INBOX in changes || SyncChange.OUTCOMES in changes) client.oracle.requestDrain()
            if (changes.any { it in HINTS }) hint()
            onHint?.invoke(this, changes)
        }
    }

    /**
     * Extra work a scenario hangs on the listener hint, after the wiring's own: null in every world
     * but a mutated one — SCN-E's MC-15, whose trigger substitution runs the contact KEEPER on every
     * `CAPABILITIES` hint (§22.25). A field of the client, not of the process, so it survives a reboot.
     */
    var onHint: ((EntDmClient, Set<SyncChange>) -> Unit)? = null

    private fun hint() {
        if (hintPending) return
        hintPending = true
        w.driver.scheduleProcess(w.clock.millis, c, "dm-hint:${c.name}") {
            hintPending = false
            // A pass that commits a hint every time would post itself for ever at one instant.
            if (w.clock.millis == hintsAt) hintsHere++ else hintsHere = 1
            hintsAt = w.clock.millis
            if (hintsHere > EntDmWorld.MAX_AT_ONE_INSTANT) violation("${c.name}: $hintsHere hint passes at one instant — a pass re-posts its own hint")
            pass(timeTriggered = false, deadline = null)
        }
    }

    /** The K20 hook's posted body: ACTIVATE in one actor turn (the reopen is not modelled; see the class note). */
    private fun activated(restored: Boolean) {
        val dev = device ?: return
        if (!ent.identity.exists) return
        sync()
        activations += if (restored) dev.engine.onRestored() else dev.engine.onActivated()
        armTimer()
    }

    /** A relay session started: a time-triggered pass once its transport is READY. */
    fun relaySessionStarted(s: Session) {
        awaitReady(s)
    }

    private fun awaitReady(s: Session) {
        w.driver.scheduleProcess(w.clock.millis + READY_POLL_MILLIS, c, "dm-session-start:${c.name}") {
            if (c.session !== s) return@scheduleProcess
            if (!s.online) {
                if (!s.isFinished()) awaitReady(s)
                return@scheduleProcess
            }
            timePass()
        }
    }

    /** A background session ended (lanes, redeem hold, transport close): the consumer tail. */
    fun sessionFinished(s: Session) {
        if (s.kind != SyncKind.BACKGROUND) return
        val policy = c.spec.policy
        val deadline = s.startedAt + policy.jobBudgetMillis - policy.consumerTailReserveMillis
        w.driver.scheduleProcess(w.clock.millis, c, "dm-consumer-tail:${c.name}") { timePass(deadline) }
    }

    /** After a periodic job: a quiet run that ran owes the consumer tail too (§13.3 item 6). */
    fun afterJob(quietBefore: Int?) {
        if (quietBefore == null || ent.quietRuns.size <= quietBefore) return
        val started = ent.quietRuns.last()[0]
        val policy = c.spec.policy
        val deadline = started + policy.jobBudgetMillis - policy.consumerTailReserveMillis
        w.driver.scheduleProcess(w.clock.millis, c, "dm-quiet-tail:${c.name}") { timePass(deadline) }
    }

    fun timePass(deadline: Long? = null) = pass(timeTriggered = true, deadline = deadline)

    private fun pass(timeTriggered: Boolean, deadline: Long?) {
        val dev = device ?: return
        // No stored identity, no DM context (MessagingWiring): the actor would sweep nothing and
        // return at `CRYPTO_UNAVAILABLE`.
        if (!ent.identity.exists) return
        sync()
        try {
            dev.actor.runPass(timeTriggered, deadline)
        } catch (e: Exception) {
            world.swallowed += "${c.name}: ${e.javaClass.simpleName}: ${e.message}"
        }
        if (timeTriggered) timePasses++ else hintPasses++
        armTimer()
    }

    /**
     * `MessagingRuntime`'s timer: one resettable wake at `min(row deadlines, owner wake)`. A
     * later arm replaces an earlier one, exactly as `ExpiryTimer.wakeIn` cancels the pending wake.
     */
    private fun armTimer() {
        val dev = device ?: return
        if (!ent.identity.exists) return
        sync()
        val rows = dev.sweeper.nextWake()?.delaySeconds
        val owner = dev.steps.nextOwnerWakeSeconds()?.let { maxOf(0L, it - clock.nowEpochSeconds()) }
        val token = ++timerToken
        val delay = listOfNotNull(rows, owner).minOrNull() ?: return
        // A wake that is due at once, again and again at one instant, is an engine that never
        // settles; on a device it would spin the actor. A finding, not a hang.
        if (delay == 0L) {
            if (w.clock.millis == zeroAt) zeroTimers++ else zeroTimers = 1
            zeroAt = w.clock.millis
            if (zeroTimers > EntDmWorld.MAX_AT_ONE_INSTANT) violation("${c.name}: the DM timer re-armed at once $zeroTimers times without time passing")
        }
        w.driver.scheduleProcess(w.clock.millis + delay * 1_000, c, "dm-timer:${c.name}") {
            if (token == timerToken) timePass()
        }
    }

    /**
     * A user action on the facade (§13.2): inline, as a facade call with no actor attached runs;
     * null while there is no identity (the app shows onboarding, not the conversation list). The
     * timer is re-armed after it, as the actor's `afterCommit` would.
     */
    fun <T> user(block: (DmDevice) -> T): T? {
        val out = read(block) ?: return null
        armTimer()
        return out
    }

    /** A read of the facade (contacts, a conversation) for a check: no timer is touched. */
    fun <T> read(block: (DmDevice) -> T): T? {
        val dev = device ?: return null
        if (!ent.identity.exists) return null
        sync()
        return block(dev)
    }

    /** True for a namespace the DM layer consumes (the DM inbox and bundle consumers). */
    fun consumesNamespace(ns: NamespaceId): Boolean {
        var consumer: String? = null
        c.jdbc.query("SELECT consumer FROM sync_namespace WHERE namespace_id = ?1", listOf(ns.toByteArray())) { consumer = it.string(0) }
        return consumer == Consumer.DM.code || consumer == Consumer.PREKEYS.code
    }

    /** The own DM namespaces (`dm_own_namespace`): role → namespace. */
    fun ownNamespaces(): Map<String, ByteArray> {
        val out = LinkedHashMap<String, ByteArray>()
        c.jdbc.query("SELECT role, namespace_id FROM dm_own_namespace ORDER BY role") { out[it.string(0)] = it.blob(1) }
        return out
    }

    private fun count(sql: String, args: List<Any?> = emptyList()): Long {
        var n = 0L
        c.jdbc.query(sql, args) { n = it.long(0) }
        return n
    }

    /** The "nothing owed" and LOCAL-need parts of [EntDmWorld.quiescenceProblems] for this client. */
    fun owedProblems(out: MutableList<String>, expectedFailures: Set<String>) {
        val dmConsumers = listOf(Consumer.DM.code, Consumer.PREKEYS.code)
        val uncovered = ent.uncovered()
        for ((what, query) in OWED) {
            val n = count(query, if ("?1" in query) dmConsumers else emptyList())
            if (n != 0L) out += "${c.name} still owes work at quiescence — $n × $what"
        }
        // DM outbox ops: those of an own namespace wait for a purchase while the app shows uncovered.
        val ownWaiting = count(
            "SELECT count(*) FROM outbox_op o JOIN dm_own_namespace d ON d.namespace_id = o.namespace_id WHERE o.released = 0",
        )
        val otherWaiting = count(
            "SELECT count(*) FROM outbox_op o JOIN sync_namespace n ON n.namespace_id = o.namespace_id " +
                "WHERE o.released = 0 AND n.consumer IN (?1, ?2) AND o.namespace_id NOT IN (SELECT namespace_id FROM dm_own_namespace)",
            dmConsumers,
        )
        if (otherWaiting != 0L) out += "${c.name} still owes work at quiescence — $otherWaiting × DM outbox ops the engine has not released"
        if (ownWaiting != 0L && !uncovered) out += "${c.name} still owes work at quiescence — $ownWaiting × own-namespace outbox ops, with tokens held"
        if (ent.identity.exists && device != null) {
            val gaveUp = read { d ->
                d.engine.contacts().flatMap { contact ->
                    d.engine.conversation(contact.id, 200, null)
                        .filter { it.outgoing && (it.state == MessageState.FAILED || it.state == MessageState.INDETERMINATE) }
                        .map { it.text ?: TIMER_ROW }
                }
            }.orEmpty().filter { it !in expectedFailures }
            if (gaveUp.isNotEmpty()) out += "${c.name} gave up on $gaveUp — FAILED or INDETERMINATE at quiescence"
        }
        for (need in c.stores.capabilities.needed()) {
            if (need.source != CapabilitySource.LOCAL || need.reason == CapabilityNeed.Reason.EXPIRING) continue
            out += "${c.name}: a LOCAL ${need.kind} need waits (${need.reason}): a contact's credential only the DM layer can supply"
        }
    }

    fun close() {
        device?.close()
        device = null
        timerToken++
    }

    override fun toString(): String = "EntDmClient(${c.name})"

    private companion object {
        const val READY_POLL_MILLIS = 1_000L
        const val TIMER_ROW = "<timer change>"
        val HINTS = setOf(SyncChange.INBOX, SyncChange.OUTCOMES, SyncChange.CAPABILITIES, SyncChange.TOPOLOGY)

        /**
         * S10b's "nothing owed" counts (`DmCrashRunner.OWED`) over this world's tables. The inbox
         * clause reads the DM consumers only ([?1], [?2]), since the entitlement engine's drop
         * namespaces are Phase 8's to check; outbox ops are counted apart ([owedProblems]).
         */
        val OWED: List<Pair<String, String>> = listOf(
            "pending sends" to "SELECT count(*) FROM dm_pending_send",
            "items not yet stored" to "SELECT count(*) FROM dm_outbound_item WHERE state IN ('pending', 'enqueued')",
            "scheduled controls" to "SELECT count(*) FROM dm_scheduled",
            "DM inbox blobs not consumed" to
                "SELECT count(*) FROM inbox_blob b JOIN sync_namespace n ON n.namespace_id = b.namespace_id " +
                "WHERE b.state <> 'done' AND n.consumer IN (?1, ?2)",
            "establishments in progress" to "SELECT count(*) FROM dm_contact WHERE establishment = 'fetching'",
            "contacts whose sessions have no 'current' slot" to
                "SELECT count(*) FROM (SELECT contact_id FROM olm_session GROUP BY contact_id " +
                "HAVING sum(CASE WHEN slot = 'current' THEN 1 ELSE 0 END) = 0)",
            "control items that ended failed or indeterminate" to
                "SELECT count(*) FROM dm_outbound_item WHERE control IS NOT NULL AND state IN ('failed', 'indeterminate')",
        )
    }
}

/** Hex of a namespace, for evidence lines. */
internal fun hexOf(bytes: ByteArray): String = Bytes.hex(bytes)
