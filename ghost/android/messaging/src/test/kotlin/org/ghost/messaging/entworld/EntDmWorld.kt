package org.ghost.messaging.entworld

import org.ghost.entitlement.api.IdentityActivationHook
import org.ghost.entitlement.harness.Bytes
import org.ghost.entitlement.harness.EntClient
import org.ghost.entitlement.harness.EntWorld
import org.ghost.messaging.DmDevice
import org.ghost.messaging.MovableClock
import org.ghost.messaging.OwnerWorld
import org.ghost.messaging.api.ActivationOutcome
import org.ghost.messaging.port.EsSlot
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
 * Nothing in this file installs a capability, runs a registration or moves a blob. What it does is
 * the wiring `:app` does on a device (`MessagingWiring`, `GhostApp`), in the driver's virtual time:
 *  - **the K20 hook** (§13.4): the entitlement engine calls the DM layer's ACTIVATE through
 *    [EntClient.activationHook] after a trial activation or a restore, exactly as
 *    `EntitlementWiring.activationHook = messagingWiring.activationHook` wires it;
 *  - **the relay-session-start time trigger** (`MessagingWiring.sessionHooks`, §21.9 rule 1): a
 *    time-triggered DM pass when a relay session's transport is READY, posted before the
 *    entitlement participant starts, as the wiring orders it;
 *  - **the consumer tail** (§13.3 item 6): a time-triggered pass after every background session
 *    ends (lanes, redeem hold and transport close first) and after every quiet run, with the job
 *    budget's deadline;
 *  - **the inbox listener** (§13.7): `INBOX`, `OUTCOMES`, `CAPABILITIES` and `TOPOLOGY` hints post
 *    one coalesced hint pass, as `DmActor.onChange` does;
 *  - **the in-process timer** (§10.7 trigger 1, §21.9 rule 1): one resettable wake at
 *    `min(row deadlines, owner wake)`, which is `MessagingRuntime`'s `ExpirySchedule` arrangement;
 *  - **a database open** after a reboot is a time trigger (§21.12 point 2).
 * A pass that throws an `Exception` ends and is recorded ([swallowed]), which is what the actor
 * thread does on a device; an `Error` — an injected crash, an invariant violation — is not caught.
 *
 * **What is a declared narrowing, not a shortcut** (see §22.23 of the design for the full list):
 *  - the DM context of a client opens from its MESSAGING branch bytes, as every DM world's does,
 *    not from the entitlement identity's root; the context is treated as *closed* (no DM pass runs)
 *    while the entitlement identity does not exist, which is what `MessagingWiring` does with no
 *    stored identity;
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

    /** The session-end hook this world installed last (see [ensureFinishHook]). */
    private var finishHook: ((Client, Session) -> Unit)? = null

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
        val job = w.runJob
        w.runJob = { c ->
            val dm = clients[c]
            val quietBefore = dm?.ent?.quietRuns?.size
            job(c)
            dm?.afterJob(quietBefore)
        }
        // The DM layer, not the Phase 7 oracle, consumes the DM and bundle namespaces: IN-1 over
        // them is this world's own check ([quiescenceProblems]).
        val exempt = w.in1Exempt
        w.in1Exempt = { c, ns -> exempt(c, ns) || clients[c]?.consumesNamespace(ns) == true }
        // Nothing is added to the crash digest: the DM layer's durable state is the client's own
        // database, which `Invariants.dump` already reads table by table, and its in-process
        // counters are not state a reboot keeps.
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

    /**
     * One relay call that was **sent** (it passed its before-send event and the reachability check,
     * so its after-apply event ran), attributed to the client that made it: the raw material of the
     * relay-side view JD8, SCN-E and the OS suite will read. [client] is ground truth — a relay sees a
     * circuit, not a name — and every other field is what the relay saw: the operation (`REDEEM`,
     * `REGISTER`, `STORE`, `LIST`, `GET`, `CHECK`, and `ISSUER` for the issuer), the relay, the
     * namespace, and the world time in milliseconds once the call's latency ran. A request the latency
     * model lost to its deadline (`latency / 2 > deadline`) is recorded too, since the harness raises
     * the after-apply event either way; in a run without such losses (the PoC's) every event reached
     * the relay, and a check that must exclude them reads the relay model's own effect instead.
     */
    class RelayEvent(val client: String, val kind: CallKind, val relay: String, val namespaceHex: String, val atMillis: Long) {
        override fun toString(): String = "$kind@$relay/${namespaceHex.take(8)} by $client at ${atMillis / 60_000} min"
    }

    /** Every relay call of every client that was sent, in order (see [RelayEvent]). */
    val relayEvents = ArrayList<RelayEvent>()

    private var viewHook: ((Client, EventKind, CallInfo) -> String?)? = null

    /**
     * Records [relayEvents] through `World.relayHook`, which every relay call of the harness
     * (`HarnessRelayPort` for the Phase 7 calls and `RegisterKey`, `HarnessCalls` for `RedeemToken`)
     * passes at each of its three events. A scenario assigns its own hook while it builds, so the
     * recorder is wrapped around whatever is installed at every session start: every one of those
     * calls happens inside a relay session (the redeem lane, the read and work lanes), so none is
     * made before the wrap. The scenario's hook runs first and its answer is kept; a call that
     * reached its after-apply event reached the relay whatever the hook then answers.
     */
    fun ensureViewHook() {
        val current = w.relayHook
        if (current != null && current === viewHook) return
        val wrapped: (Client, EventKind, CallInfo) -> String? = { c, kind, info ->
            val category = current?.invoke(c, kind, info)
            if (kind == EventKind.RELAY_AFTER_APPLY) relayEvents += RelayEvent(c.name, info.kind, info.relay, info.namespace, w.clock.millis)
            category
        }
        viewHook = wrapped
        w.relayHook = wrapped
    }

    /**
     * The driver keeps one session-end callback, and `World.foreground` replaces it whenever a
     * scenario schedules a window. So the consumer-tail hook is re-wrapped around whatever is there
     * at every session start, which is before any session this world could owe a tail can end.
     */
    fun ensureFinishHook() {
        val current = w.driver.onSessionFinished
        if (current != null && current === finishHook) return
        val wrapped: (Client, Session) -> Unit = { c, s ->
            current?.invoke(c, s)
            clients[c]?.sessionFinished(s)
        }
        finishHook = wrapped
        w.driver.onSessionFinished = wrapped
    }

    // ------------------------------------------------------------------ checks

    /**
     * Unmet quiescence conditions of the DM layer: IN-1 over the namespaces the DM layer consumes
     * (every live blob an honest relay holds in a listened DM or bundle namespace with a read path,
     * other than the client's own, has been consumed — its `inbox_blob` row is `done`), and no DM
     * pass has thrown.
     */
    fun quiescenceProblems(): List<String> {
        val out = ArrayList<String>()
        if (swallowed.isNotEmpty()) out += "a DM pass threw: ${swallowed.first()}"
        for ((c, dm) in clients) {
            val now = w.clock.epochSeconds()
            val listened = ArrayList<ByteArray>()
            c.jdbc.query(
                "SELECT namespace_id FROM sync_namespace WHERE listening = 1 AND consumer IN (?1, ?2)",
                listOf(Consumer.DM.code, Consumer.PREKEYS.code),
            ) { listened += it.blob(0) }
            val own = w.ops.values.filter { it.client === c }.map { it.namespace to it.hash }.toSet()
            for (ns in listened) {
                val relays = ArrayList<Long>()
                c.jdbc.query(
                    "SELECT nr.relay_id FROM namespace_relay nr JOIN relay_directory rd ON rd.relay_id = nr.relay_id " +
                        "WHERE nr.namespace_id = ?1 AND rd.state = 'active' AND EXISTS (SELECT 1 FROM relay_capability k " +
                        "WHERE k.relay_id = nr.relay_id AND k.namespace_id = nr.namespace_id AND ((k.kind = 'read' AND k.state = 'usable') " +
                        "OR (k.kind = 'write' AND k.state IN ('usable', 'exhausted'))) AND (k.expires_hour IS NULL OR k.expires_hour > ?2))",
                    listOf(ns, now),
                ) { relays += it.long(0) }
                for (relayId in relays) {
                    val node = c.relayIds.entries.firstOrNull { it.value.value == relayId }?.let { w.relays[it.key] } ?: continue
                    if (!node.honest) continue
                    val namespace = NamespaceId(ns)
                    for (m in node.model.liveMembers(namespace, w.relayNow(node))) {
                        if ((namespace to m.hash) in own) continue
                        var state: String? = null
                        c.jdbc.query(
                            "SELECT state FROM inbox_blob WHERE namespace_id = ?1 AND blob_hash = ?2",
                            listOf(ns, m.hash.toByteArray()),
                        ) { state = it.string(0) }
                        if (state != "done") {
                            out += "${c.name}: DM IN-1: a live blob on ${node.name} in a listened DM namespace is ${state ?: "not listed"}"
                        }
                    }
                }
            }
            dm.quiescenceProblems(out)
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
     * One `RedeemToken` request as the relay received it (`EntRecords.relayLog`, every byte NI-1
     * reads): when (world milliseconds), where, for which namespace, and the ACCESS week of the
     * token presented (−1 for bytes that are no token of the schedule).
     */
    class Redemption(val atMillis: Long, val relay: String, val namespaceHex: String, val week: Long) {
        /** The relay's true time of arrival, epoch seconds. */
        val atEpochSeconds: Long get() = World.T0 + atMillis / 1_000

        override fun toString(): String = "redeem@$relay/${namespaceHex.take(8)} w$week at ${atMillis / 60_000} min"
    }

    /**
     * Every redemption request any client of the world sent to a relay, in order (the log is written
     * after the reachability check and before the latency model decides whether it arrives).
     */
    fun redemptions(): List<Redemption> = ent.records.relayLog.mapNotNull { line ->
        val f = line.split('|')
        if (f.size < 6 || f[1] != "redeem") return@mapNotNull null
        val token = Bytes.unhex(f[4])
        val week = if (token.size == org.ghost.entitlement.harness.TestSchedule.TOKEN_BYTES) {
            ent.schedule.verify(token, org.ghost.network.EntitlementCrypto.KIND_ACCESS)?.epoch ?: -1
        } else {
            -1
        }
        Redemption(f[0].removePrefix("t=").toLong(), f[2], f[3], week)
    }

    override fun toString(): String = "EntDmWorld"

    companion object {
        /** The world's ES slots: four relays over two operators, as every DM world has. */
        const val SLOTS: Int = 4
        const val OPERATORS: Int = 2

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
        ent.activationHook = IdentityActivationHook { restored -> activated(restored) }
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
        }
    }

    private fun hint() {
        if (hintPending) return
        hintPending = true
        w.driver.scheduleProcess(w.clock.millis, c, "dm-hint:${c.name}") {
            hintPending = false
            pass(timeTriggered = false, deadline = null)
        }
    }

    /** The K20 hook's body: `reopenAndActivate` on a device, one actor turn, inline. */
    private fun activated(restored: Boolean) {
        val dev = device ?: return
        sync()
        activations += if (restored) dev.engine.onRestored() else dev.engine.onActivated()
        armTimer()
    }

    /** A relay session started: a time-triggered pass once its transport is READY. */
    fun relaySessionStarted(s: Session) {
        world.ensureFinishHook()
        world.ensureViewHook()
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
            if (zeroTimers > MAX_ZERO_TIMERS) violation("${c.name}: the DM timer re-armed at once $zeroTimers times without time passing")
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

    fun quiescenceProblems(out: MutableList<String>) {
        if (!ent.identity.exists || device == null) return
        var fetched = 0L
        c.jdbc.query(
            "SELECT count(*) FROM inbox_blob b JOIN sync_namespace n ON n.namespace_id = b.namespace_id " +
                "WHERE b.state = 'fetched' AND n.consumer IN (?1, ?2)",
            listOf(Consumer.DM.code, Consumer.PREKEYS.code),
        ) { fetched = it.long(0) }
        if (fetched > 0) out += "${c.name}: $fetched fetched DM blob(s) not consumed"
    }

    fun close() {
        device?.close()
        device = null
        timerToken++
    }

    override fun toString(): String = "EntDmClient(${c.name})"

    private companion object {
        const val READY_POLL_MILLIS = 1_000L
        const val MAX_ZERO_TIMERS = 256
        val HINTS = setOf(SyncChange.INBOX, SyncChange.OUTCOMES, SyncChange.CAPABILITIES, SyncChange.TOPOLOGY)
    }
}

/** Hex of a namespace, for evidence lines. */
internal fun hexOf(bytes: ByteArray): String = Bytes.hex(bytes)
