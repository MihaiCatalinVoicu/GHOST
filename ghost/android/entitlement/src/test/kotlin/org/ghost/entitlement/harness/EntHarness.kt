package org.ghost.entitlement.harness

import org.ghost.entitlement.android.ParticipantSessionPort
import org.ghost.entitlement.engine.EngineDeps
import org.ghost.entitlement.engine.EntitlementEngine
import org.ghost.entitlement.engine.Grid
import org.ghost.entitlement.engine.RedeemPlanner
import org.ghost.entitlement.port.EntitlementClock
import org.ghost.entitlement.port.EntitlementRandom
import org.ghost.entitlement.port.IdentityPort
import org.ghost.entitlement.port.SealPort
import org.ghost.entitlement.port.SecureEntitlementRandom
import org.ghost.entitlement.port.SessionPort
import org.ghost.entitlement.port.TokenCryptoPort
import org.ghost.entitlement.port.UserCallPort
import org.ghost.entitlement.store.PurchaseStore
import org.ghost.identity.DropSeal
import org.ghost.identity.Invite
import org.ghost.identity.InviteKeys
import org.ghost.identity.RootEntropy
import org.ghost.network.EntitlementCrypto
import org.ghost.network.NetworkException
import org.ghost.sync.api.CapabilityNeed
import org.ghost.sync.api.NamespaceId
import org.ghost.sync.engine.KeyedRandomSources
import org.ghost.sync.engine.QuietRunScheduler
import org.ghost.sync.engine.RedeemHold
import org.ghost.sync.engine.Session
import org.ghost.sync.harness.Client
import org.ghost.sync.harness.RelayNode
import org.ghost.sync.harness.World
import org.ghost.sync.harness.foreground
import org.ghost.sync.harness.violation
import org.ghost.sync.port.EntitlementCalls
import org.ghost.sync.port.TransportLease
import org.ghost.sync.port.TransportState
import org.ghost.sync.store.Time
import java.security.SecureRandom
import org.ghost.sync.api.SessionKind as ParticipantKind
import org.ghost.sync.engine.SessionKind as SyncKind

/**
 * How a `:entitlement` harness world differs from the honest default: the harness schedule's counts
 * (design §19.17 point 3: S = 3, access_per_slot = 4, trial_per_slot = 2), the issuer's randomness
 * and answer times (NI-1 worlds vary them within one L-cell), injected issuer unavailability, and the
 * substitutions of mutants (implemented only here, in test sources, design §13.5).
 */
internal data class EntConfig(
    val accessPerSlot: Int = 4,
    val trialPerSlot: Int = 2,
    val issuerSeed: Long = 0,
    val firstMinor: Int = 1,
    /** Answer time of the n-th issuer call, ms (issuer randomness). */
    val issuerLatencyMillis: (Int) -> Long = { 700L },
    /** The n-th issuer call is answered UNAVAILABLE without reaching the issuer's state. */
    val issuerUnavailable: (Int) -> Boolean = { false },
    /** The issuer states an amount this much above the ES price (a hostile issuer). */
    val issuerAmountOffset: Long = 0,
    /** The native layer compares invoice amounts with the ES (off: the hostile-issuer mode test of EM8 checks the Kotlin engine alone). */
    val nativeChecksAmounts: Boolean = true,
    /** A substituted quiet-run decision (mutant M20); null: the production [QuietRunScheduler]. */
    val quietOverride: ((EntClient, Long, Boolean) -> Boolean)? = null,
    /** A substituted token-crypto port for the engine (mutants EM8, M8); null: [TestTokenCrypto]. */
    val cryptoFor: ((TestTokenCrypto) -> TokenCryptoPort)? = null,
    /**
     * Every n-th periodic relay job of the harness is a 5-minute foreground session instead (the user
     * opens the app about once a day at the 15-minute cadence, n = 96); 0: background only. A
     * background session that starts with a pending write need is held until the redeem lane's first
     * step (Q29, [RedeemHold]), so a client whose capabilities all lapsed recovers in the background
     * ([ScenarioLapsed] runs with 0); one without a read pair and with read needs only still ends
     * before that step (READY + U[0, 30 s]) and redeems in the foreground or in a longer session.
     */
    val dailyForegroundJobs: Int = 96,
) {
    override fun toString(): String = "EntConfig"
}

/**
 * Harness bookkeeping the entitlement invariants read (never sent anywhere). Every change bumps
 * [version], which is part of the crash-point classification key (through the world's extension).
 */
internal class EntRecords {
    var version: Long = 0
        private set

    fun bump() {
        version++
    }

    /** Token (by nullifier hex) → every (relay, namespace) it was presented at (R8 / RED-2). */
    val presented = HashMap<String, MutableSet<String>>()

    /** Capability hex → the nullifier hex of the token a model relay minted it for. */
    val minted = HashMap<String, String>()

    /** Tokens a relay refused, or the native layer refused before any I/O. */
    val refused = HashSet<String>()

    class Issued(val kind: Int, val epoch: Long, val invoice: String?)

    /** Every token the native layer finalized from an issuer answer (MS-6, token accounting). */
    val issued = LinkedHashMap<String, Issued>()

    /** Secrets the native layer saw (T3 canaries): seeds, claim keys, invoice ids, tokens. */
    val secrets = LinkedHashSet<String>()

    /** Issuer calls as the issuer sees them: time, operation, flow, request size (NI-2). */
    val issuerLog = ArrayList<String>()

    /** Redemptions as the relays see them: time, relay, namespace, token, request id (NI-1: every byte of the request). */
    val relayLog = ArrayList<String>()

    /** Device times at which a pack's signatures reached the engine (the activation slots of NI-1). */
    val finalizedAt = ArrayList<Long>()

    /** Every distinct `eligible_minute` the client stored a token with (NI-1: worlds whose tokens activate alike). */
    val eligible = java.util.TreeSet<Long>()

    // What the client made durable, from committed transactions only ([EntClient.uncommitted]): MS-6 and
    // the token accounting read it at the end.

    /** Claim hash (hex) of every flow the client wrote ahead with a claim key → its purchase id (hex). */
    val purchaseOfClaim = HashMap<String, String>()

    /** Invoice id (hex) the client recorded (prepared → invoiced) → its purchase id (hex): the invoices MS-6 holds it to. */
    val invoiced = HashMap<String, String>()

    /** Per purchase id (hex): its committed call write-aheads, as "state|attempt before" (the attempts the engine spent). */
    val writeAheads = HashMap<String, MutableSet<String>>()

    /** The terminal state each purchase (id hex) ended in. */
    val ended = HashMap<String, String>()

    /** CREDIT tokens (nullifier hex) the client sealed into a drop blob. */
    val sealed = HashSet<String>()

    /** INVITE tokens (nullifier hex) the client embedded in an invite of its own. */
    val embedded = HashSet<String>()

    /** Token (nullifier hex) → the `eligible_minute` the client stored it with (activation slots, Q30). */
    val eligibleOf = HashMap<String, Long>()

    fun present(nullifier: String, pair: String) {
        val pairs = presented.getOrPut(nullifier) { LinkedHashSet() }
        if (pairs.add(pair)) version++
        if (pairs.size > 1) violation("RED-2: a token was presented at ${pairs.size} (relay, namespace) pairs (R8)")
    }

    /** The write-aheads purchase [purchase] committed in [state] (`prepared`: `RequestInvoice`, `invoiced`: `BlindSign`). */
    fun writeAheads(purchase: String, state: String): Int = writeAheads[purchase]?.count { it.startsWith("$state|") } ?: 0

    fun digest(): String =
        "v$version p${presented.size} m${minted.size} r${refused.size} i${issued.size} c${purchaseOfClaim.size} k${invoiced.size} " +
            "a${writeAheads.values.sumOf { it.size }} e${ended.size} s${sealed.size} n${embedded.size}"

    override fun toString(): String = "EntRecords"
}

/**
 * The `:entitlement` harness world (Phase 8 design §11.9, §13.2): a Phase 7 sync harness [World]
 * whose clients carry the real entitlement engine as their session participant, over the real sync
 * engine, stores and schema; the [ModelIssuer] and one [ModelRedeemRelay] per ES slot relay (its
 * capabilities are v2 under the relay's own MAC key, so the sync [org.ghost.sync.harness.ModelRelay]
 * accepts them); [HarnessCalls] as the native layer with fault events on the client's bus.
 * [slotRelays] hold ES slots 0, 1, 2 … in order.
 */
internal class EntWorld(val w: World, val slotRelays: List<RelayNode>, val config: EntConfig = EntConfig()) {
    val schedule = TestSchedule(
        config.accessPerSlot, config.trialPerSlot,
        slotRelays.mapIndexed { i, r -> EntitlementCrypto.Slot(i, TestSchedule.FIRST_WEEK, 0, r.address) },
    )
    val crypto = TestTokenCrypto(schedule)
    val enginePort: TokenCryptoPort = config.cryptoFor?.invoke(crypto) ?: crypto
    val issuer = ModelIssuer(schedule, config.issuerSeed, config.firstMinor)
    val records = EntRecords()
    val clients = LinkedHashMap<Client, EntClient>()
    private val redeemRelays: Map<Int, ModelRedeemRelay>
    private var minted = 0

    init {
        redeemRelays = slotRelays.mapIndexed { i, r ->
            r.index to ModelRedeemRelay.open(schedule, i, r.address, { r.model.key() }, ModelRedeemRelay.Disk(), ModelRedeemRelay.Mode.CREATE, w.relayNow(r))
        }.toMap()
        w.onBoot = { c -> clients[c]?.boot() }
        w.onSessionStart = { c, s -> clients[c]?.relaySession(s) }
        val plainJob = w.runJob
        w.runJob = { c -> clients[c]?.job() ?: plainJob(c) }
        w.extraMutations = { issuer.mutations + redeemRelays.values.sumOf { it.disk.mutations } + records.version }
        w.extraState = {
            listOf("issuer ${issuer.digest()}") + redeemRelays.values.map { "redeem ${it.slot} ${it.disk.digest()}" } + "ent-records ${records.digest()}"
        }
        w.in1Exempt = { c, ns -> clients[c]?.dropNamespace(ns) == true }
        w.sessionHold = { c, s -> clients[c]?.holds(s) == true }
        issuer.tick(issuerNow())
    }

    /** Installs the entitlement engine on [c] (its first boot); [genesis]: the identity exists already. */
    fun attach(c: Client, genesis: Boolean = true): EntClient =
        EntClient(this, c).also {
            clients[c] = it
            it.identity.exists = genesis
            it.boot()
        }

    /** The issuer's clock: true time. */
    fun issuerNow(): Long = w.clock.trueEpochSeconds()

    fun redeemRelay(node: RelayNode): ModelRedeemRelay? = redeemRelays[node.index]

    /** Pays [amount] to [invoiceId]'s subaddress (a pool transfer). */
    fun pay(invoiceId: ByteArray, amount: Long) = issuer.pay(issuer.minorOf(invoiceId), amount)

    /** Mines [n] blocks (the pool first) and runs the scanner. */
    fun mine(n: Long) {
        issuer.mine(n)
        issuer.tick(issuerNow())
    }

    /** A token minted directly with the test key (setup of a scenario; never through the issuer). */
    fun mint(kind: Int, epoch: Long, slot: Int? = null): ByteArray = schedule.mint(kind, epoch, "harness-mint/${w.seed}/${minted++}", slot)

    /** True when some redeem relay holds [nullifier] (the token is spent there). */
    fun bound(nullifier: String, epoch: Long): Boolean {
        val row = Bytes.hex(Bytes.u64(epoch)) + nullifier
        return redeemRelays.values.any { it.disk.rows.containsKey(row) }
    }

    // ------------------------------------------------------------------ invariants

    private fun count(c: Client, sql: String, args: List<Any?> = emptyList()): Long {
        var n = 0L
        c.jdbc.query(sql, args) { n = it.long(0) }
        return n
    }

    /**
     * After every commit that changed a capability, outbox or topology row: a capability a relay
     * minted for one of this world's tokens is never installed while that token is still held, so
     * `Capabilities.put` and the token's deletion were one transaction (design §11.5, §13.2).
     */
    fun checkCommit(ec: EntClient) {
        val c = ec.c
        val installed = ArrayList<String>()
        c.jdbc.query("SELECT token FROM relay_capability") { installed += Bytes.hex(it.blob(0)) }
        for (cap in installed) {
            val n = records.minted[cap] ?: continue
            if (count(c, "SELECT count(*) FROM ent_token WHERE nullifier = ?1", listOf(Bytes.unhex(n))) > 0) {
                violation("a redeemed capability is installed while its token is still held: Capabilities.put and the token's deletion are not one transaction")
            }
        }
    }

    /** Safety invariants checked after every reboot and at the end (design §13.2). */
    fun structural(where: String) {
        for ((c, _) in clients) {
            // R10: no secret column is non-null in a terminal state (CHECK-enforced; read here).
            val leaked = count(
                c,
                "SELECT count(*) FROM ent_purchase WHERE state IN ('finalized', 'expired', 'failed', 'lost') AND (seed IS NOT NULL OR claim_key IS NOT NULL " +
                    "OR invoice_id IS NOT NULL OR subaddress IS NOT NULL OR input_token IS NOT NULL OR created_hour IS NOT NULL OR receipt_minute IS NOT NULL)",
            )
            if (leaked > 0) violation("[$where] R10: $leaked terminal purchase(s) keep a secret")
        }
        // R8 / RED-2: no token is presented at two (relay, namespace) pairs.
        records.presented.entries.firstOrNull { it.value.size > 1 }?.let { violation("[$where] RED-2: a token was presented at ${it.value.size} (relay, namespace) pairs") }
        // MS-1: every BlindSign request the issuer ever received for one invoice has the same digest.
        issuer.history.values.firstOrNull { it.requestDigests.size > 1 }?.let { violation("[$where] MS-1: an invoice received ${it.requestDigests.size} different BlindSign requests") }
        for ((c, _) in clients) checkAmounts(c, where)
    }

    /** An invoice is recorded only with the schedule's price (§7.8: the engine never trusts the issuer's amount). */
    fun checkAmounts(c: Client, where: String) {
        c.jdbc.query("SELECT base_week, amount_atomic FROM ent_purchase WHERE kind = 'pack' AND pay_with = 'xmr' AND amount_atomic IS NOT NULL") {
            if (schedule.price(Grid.priceEpoch(it.long(0))) != it.long(1)) {
                violation("[$where] an invoice was recorded with an amount other than the schedule's price (the issuer's amount was trusted)")
            }
        }
    }

    /**
     * Unmet quiescence conditions of the entitlement engine: no purchase, claim or trial still live,
     * and the liveness premise (design §11.9): a WRITE or READ need is never left waiting while an
     * eligible fresh token of its relay's slot and week exists.
     */
    fun quiescenceProblems(): List<String> {
        val out = ArrayList<String>()
        for ((c, _) in clients) {
            val live = count(c, "SELECT count(*) FROM ent_purchase WHERE state IN ('prepared', 'invoiced')")
            if (live > 0) out += "${c.name}: $live live purchase(s)"
            val claims = count(c, "SELECT count(*) FROM ent_claim WHERE state = 'prepared'")
            if (claims > 0) out += "${c.name}: $claims open claim(s)"
            val now = w.clock.epochSeconds()
            if (RedeemPlanner.nearBoundary(now)) continue
            val week = Grid.week(now)
            for (need in c.stores.capabilities.needed()) {
                if (need.reason == CapabilityNeed.Reason.EXPIRING) continue
                val onion = c.relayIds.entries.firstOrNull { it.value == need.relay }?.let { w.relays[it.key].address } ?: continue
                val slots = RedeemPlanner.slotsFor(schedule.summary, onion, week)
                if (slots.isEmpty()) continue
                val marks = slots.indices.joinToString(", ") { "?${it + 3}" }
                val eligible = count(
                    c,
                    "SELECT count(*) FROM ent_token WHERE kind = 'access' AND state = 'fresh' AND epoch = ?1 AND eligible_minute <= ?2 AND slot IN ($marks)",
                    listOf<Any?>(week, Time.floorMinute(now)) + slots,
                )
                if (eligible > 0) out += "${c.name}: liveness: a ${need.kind} ${need.reason} need waits although $eligible eligible token(s) exist"
            }
        }
        return out
    }

    /**
     * At the end (design §13.2): MS-6, the token accounting and the T3 canaries.
     *
     * MS-6 (a paid invoice ends with its N tokens when retries are allowed): every invoice the issuer
     * holds CONFIRMED or ISSUED belongs to a flow the client wrote ahead (by invoice id, else by claim
     * hash). One the client recorded ends with its purchase `finalized` and all N tokens the native layer
     * finalized from its signatures, unless the engine spent its whole `BlindSign` plan (5 attempts, 4
     * when the invoice came on the `RequestInvoice` retry, E5) without them: a note. One the client never
     * learned of (a credits invoice, confirmed at once, every answer lost) is a note only once both capped
     * `RequestInvoice` attempts were spent: its credits are lost by design (§11.4, `failPrepared`).
     * Attempts count committed write-aheads, not sends: a crash between a write-ahead and its send spends
     * an attempt that never reaches the wire (§11.5), which a double crash of E-D does.
     *
     * Token accounting (fresh + reserved + spent = finalized) for every kind the native layer finalized:
     * an ACCESS token is held, spent at a relay, refused, or past its window, and a token a relay recorded
     * is never fresh again; a CREDIT token is held, used at the issuer (discount, payout, refresh), sealed
     * into a drop blob, or of an epoch GC drops (before c_now − 4, §19.8); an INVITE token is held,
     * embedded in an invite, redeemed at the issuer, or of an epoch GC drops (before e_now − 1). Two
     * states stay exempt by design: an ACCESS token a relay recorded may stay reserved for its identical
     * retry until GC, and a credit a failed flow released is held again although the issuer may have
     * spent it (§11.4).
     */
    fun finalChecks() {
        structural("end")
        ms6()
        val now = w.clock.trueEpochSeconds()
        val week = Grid.week(now)
        for ((c, ec) in clients) {
            val held = HashMap<String, String>()
            c.jdbc.query("SELECT nullifier, state FROM ent_token") { held[Bytes.hex(it.blob(0))] = it.string(1) }
            for ((n, info) in records.issued) {
                val present = n in held
                when (info.kind) {
                    EntitlementCrypto.KIND_ACCESS -> {
                        val atRelay = bound(n, info.epoch)
                        val over = now >= Grid.start(info.epoch + 1) + 3_600
                        // A token a relay recorded stays reserved for its identical retry (or until GC when its
                        // pair's need is gone, a drop namespace retired, say); it is never fresh again (R8).
                        if (atRelay && held[n] == "fresh") violation("a token a relay recorded is fresh again (a reservation was released after the redemption)")
                        if (!present && !atRelay && n !in records.refused && !over) {
                            violation("MS-6: an issued token of week ${info.epoch} is neither held, spent nor out of its window")
                        }
                    }
                    EntitlementCrypto.KIND_CREDIT -> {
                        val over = info.epoch < Grid.creditEpoch(week) - CREDIT_EPOCHS_KEPT
                        if (!present && !issuer.creditUsed(info.epoch, n) && n !in records.sealed && !over) {
                            violation("token accounting: an issued CREDIT token of epoch ${info.epoch} is neither held, used at the issuer, sealed into a drop nor out of its window")
                        }
                    }
                    EntitlementCrypto.KIND_INVITE -> {
                        val over = info.epoch < Grid.inviteEpoch(week) - 1
                        if (!present && n !in records.embedded && !issuer.inviteUsed(info.epoch, n) && !over) {
                            violation("token accounting: an issued INVITE token of epoch ${info.epoch} is neither held, in an invite, redeemed at the issuer nor out of its window")
                        }
                    }
                    else -> violation("token accounting: a finalized token of unknown kind ${info.kind}")
                }
            }
            // T3: nothing the engine emits carries a secret the native layer saw.
            val emitted = listOf(ec.engine.toString(), ec.engine?.status().toString(), ec.engine?.activationState().toString())
            for (text in emitted) {
                for (s in records.secrets) if (s.length >= 16 && text.contains(s.substring(0, 16))) violation("T3: a secret reached an emitted string")
            }
        }
    }

    /** MS-6 over every paid invoice at the issuer (see [finalChecks]). */
    private fun ms6() {
        for (inv in issuer.history.values) {
            if (inv.state != ModelIssuer.State.CONFIRMED && inv.state != ModelIssuer.State.ISSUED) continue
            val recorded = records.invoiced[Bytes.hex(inv.id)]
            val purchase = recorded ?: records.purchaseOfClaim[Bytes.hex(inv.claimHash)]
                ?: violation("MS-6: a paid invoice belongs to no flow the client wrote ahead (purchases ${alicePurchases()})")
            val requests = records.writeAheads(purchase, PurchaseStore.PREPARED)
            val signs = records.writeAheads(purchase, PurchaseStore.INVOICED)
            val ended = records.ended[purchase]
            val where = "${if (inv.xmr) "xmr" else "credits"} invoice ${inv.state}, its purchase ${ended ?: "live"} after $requests RequestInvoice " +
                "and $signs BlindSign attempts; purchases ${alicePurchases()}"
            if (recorded == null) {
                if (requests >= CAPPED_CALL_ATTEMPTS) {
                    w.notes += "a paid invoice never reached the client, both capped RequestInvoice attempts spent ($where): its credits are lost (§11.4)"
                } else {
                    violation("MS-6: a paid invoice never reached the client although a RequestInvoice retry was left ($where)")
                }
                continue
            }
            val n = schedule.positions(if (inv.xmr) EntitlementCrypto.PRODUCT_PACK_XMR else EntitlementCrypto.PRODUCT_PACK_CREDITS, inv.baseWeek)?.size
            if (ended == PurchaseStore.FINALIZED && inv.state == ModelIssuer.State.ISSUED && inv.finalized.size == n) continue
            // Five attempts, the first window skipped when the invoice came on the RequestInvoice retry (E5).
            val plan = BLIND_SIGN_PLAN - (requests - 1).coerceIn(0, BLIND_SIGN_PLAN - 1)
            if (ended != PurchaseStore.FINALIZED && signs >= plan) {
                w.notes += "a paid invoice's whole BlindSign plan ended without its signatures reaching the engine ($where)"
            } else {
                violation("MS-6: a paid invoice did not end with its $n tokens although a BlindSign attempt was left ($where; ${inv.finalized.size} finalized)")
            }
        }
    }

    private fun alicePurchases(): String = clients.values.joinToString { ec -> ec.purchaseStates().toString() }

    override fun toString(): String = "EntWorld"

    private companion object {
        /** `BlindSign` attempts per invoice (design §19.11). */
        const val BLIND_SIGN_PLAN = 5

        /** A capped issuer call: the planned attempt and at most one identical retry (§11.5, §19.11). */
        const val CAPPED_CALL_ATTEMPTS = 2

        /** Own credits are accepted in their epoch and the four following ones (§19.8); GC drops older ones. */
        const val CREDIT_EPOCHS_KEPT = 4L
    }
}

/**
 * One client of an [EntWorld]: the identity (it survives crashes: it lives outside the database),
 * and per process (rebuilt at every boot) the entitlement engine, its randomness, the production
 * [QuietRunScheduler] over the process's own random key, and the participant sessions it drives.
 */
internal class EntClient(val ent: EntWorld, val c: Client) {
    val w: World get() = ent.w
    val identity = HarnessIdentity(RootEntropy.fromRaw(Bytes.sha256(Bytes.ascii("root|${ent.w.seed}|${c.name}")))) { ent.records.bump() }
    val calls = HarnessCalls(this)
    private val userCalls = HarnessUserCalls(this)

    var engine: EntitlementEngine? = null
        private set
    lateinit var scheduler: QuietRunScheduler
        private set
    private var quietIndex = 0L
    private var flows = 0L
    private val flowIndex = HashMap<String, Long>()

    /** Quiet runs of this client: start time and issuer calls made in each (J9: at most one). */
    val quietRuns = ArrayList<LongArray>()

    /** The running relay session's redeem hold (Q29): the production [RedeemHold], as SyncRuntime keeps it. */
    private var hold: Pair<Session, RedeemHold>? = null

    /**
     * [s], whose lanes have finished, stays the client's session (SyncRuntime's `held`): its hold is
     * armed, no lane step yet, before the job's deadline, its transport online, no foreground waiting.
     */
    fun holds(s: Session): Boolean {
        val (session, h) = hold ?: return false
        return session === s && !c.foregroundPending && s.online && h.holds(w.clock.millis)
    }

    fun boot() {
        val boot = c.boots
        val key = Bytes.sha256(Bytes.ascii("ent-random|${w.seed}|${c.name}|$boot"))
        scheduler = QuietRunScheduler(KeyedRandomSources(Bytes.sha256(Bytes.ascii("quiet|${w.seed}|${c.name}|$boot"))), w.clock)
        quietIndex = 0
        flows = 0
        flowIndex.clear()
        hold = null
        val stores = c.stores
        val deps = EngineDeps(ent.enginePort, HarnessEntClock(w), SiteRandom(key), identity, HarnessSeal(this, key), userCalls) { c.mode }
        engine = EntitlementEngine(deps) { stores }
        uncommitted.clear()
        c.sql.onCommit += { ent.checkCommit(this) }
        c.sql.onUpdate += { sql, args, changed ->
            if (changed == 1 && sql.startsWith("INSERT INTO outbox_op(")) registerEngineOp(args)
            if (changed == 1 && sql.startsWith("INSERT INTO ent_token(")) ent.records.eligible += (args[6 - 1] as Number).toLong()
            if (changed == 1) track(sql, args)
        }
        c.sql.onTransactionEnd += { committed ->
            if (committed) uncommitted.forEach { it() }
            uncommitted.clear()
        }
        if (boot > 1) ent.structural("reboot")
    }

    /** Bookkeeping of the open transaction: applied to [EntWorld.records] when it commits, dropped when it rolls back. */
    val uncommitted = ArrayList<() -> Unit>()

    /** What the engine writes ahead and ends (MS-6 and the token accounting), kept once its transaction commits. */
    private fun track(sql: String, args: List<Any?>) {
        val r = ent.records
        fun hex(i: Int) = Bytes.hex(args[i] as ByteArray)
        when {
            sql.startsWith("INSERT INTO ent_purchase(") -> (args[4] as? ByteArray)?.let { claimKey ->
                val purchase = hex(0)
                val claim = Bytes.hex(Batch.claimHash(claimKey))
                uncommitted += { r.purchaseOfClaim[claim] = purchase }
            }
            sql.startsWith("UPDATE ent_purchase SET sent = 1,") -> {
                val purchase = hex(2)
                val attempt = "${args[3]}|${args[4]}"
                uncommitted += { r.writeAheads.getOrPut(purchase) { LinkedHashSet() } += attempt }
            }
            sql.startsWith("UPDATE ent_purchase SET state = 'invoiced', invoice_id = ?1") -> {
                val invoice = hex(0)
                val purchase = hex(7)
                uncommitted += { r.invoiced[invoice] = purchase }
            }
            sql.startsWith("UPDATE ent_purchase SET state = ?1, terminal_day = ?2") -> {
                val purchase = hex(2)
                val to = args[0] as String
                uncommitted += { r.ended[purchase] = to }
            }
            sql.startsWith("INSERT INTO ent_token(") -> {
                val nullifier = hex(0)
                val eligible = (args[5] as Number).toLong()
                uncommitted += { r.eligibleOf[nullifier] = eligible }
            }
            // An invite of this client embeds its token; a drop a restore scans has no payload (§8.4).
            sql.startsWith("INSERT INTO ent_invite(") -> (args[1] as? ByteArray)?.takeIf { it.size == Invite.PAYLOAD_BYTES }?.let { payload ->
                val nullifier = Bytes.hex(TestSchedule.nullifier(payload.copyOfRange(1, 1 + Invite.TOKEN_BYTES)))
                uncommitted += { r.embedded += nullifier }
            }
        }
    }

    /**
     * An op the engine enqueued itself (a drop blob, design §9.3) becomes an op of the Phase 7
     * records, so the relay port's OUT-3 check knows its frozen payload.
     */
    private fun registerEngineOp(args: List<Any?>) {
        val id = org.ghost.sync.api.OperationId(args[0] as ByteArray)
        if (w.ops.values.any { it.operationId == id }) return
        val ttl = org.ghost.sync.api.TtlBucket.entries.first { it.seconds.toLong() == (args[4] as Number).toLong() }
        val label = "engine-op-${w.ops.size}"
        w.ops[label] = org.ghost.sync.harness.OpRecord(label, c, id, NamespaceId(args[1] as ByteArray), (args[3] as ByteArray).copyOf(), ttl, null)
    }

    /**
     * Scenario setup (before the armed phase): [count] fresh tokens of ([kind], [epoch], [slot]) minted
     * with the test keys, as a finalized batch leaves them, eligible from [eligibleMinute].
     */
    fun addTokens(kind: String, epoch: Long, slot: Int?, count: Int, eligibleMinute: Long): List<ByteArray> {
        val ctx = checkNotNull(e().context()) { "no engine context" }
        val code = org.ghost.entitlement.store.Kinds.of(kind)
        val tokens = List(count) { ent.mint(code, epoch, slot) }
        c.tx { tx -> tokens.forEach { t -> ctx.tokens.insertFresh(tx, TestSchedule.nullifier(t), kind, epoch, slot, t, eligibleMinute) } }
        tokens.forEach { ent.records.issued.putIfAbsent(Bytes.hex(TestSchedule.nullifier(it)), EntRecords.Issued(code, epoch, null)) }
        return tokens
    }

    /** The engine of the running process (a process always has one once attached). */
    fun e(): EntitlementEngine = checkNotNull(engine) { "no entitlement engine" }

    /** Live purchase ids of this client (read from the database, as the app's UI would). */
    fun livePurchases(): List<ByteArray> {
        val out = ArrayList<ByteArray>()
        c.jdbc.query("SELECT purchase_id FROM ent_purchase WHERE state IN ('prepared', 'invoiced') ORDER BY purchase_id") { out += it.blob(0) }
        return out
    }

    /** Every purchase row's (kind, state), for scenario checks. */
    fun purchaseStates(): List<Pair<String, String>> {
        val out = ArrayList<Pair<String, String>>()
        c.jdbc.query("SELECT kind, state FROM ent_purchase ORDER BY purchase_id") { out += it.string(0) to it.string(1) }
        return out
    }

    /**
     * The user pays every invoiced XMR purchase from its payment instructions (all disclosures
     * acknowledged), the outstanding amount, then the chain confirms it ([blocks] blocks).
     */
    fun payInvoiced(blocks: Long = 10, fraction: Double = 1.0) {
        val e = engine ?: return
        var paid = false
        for (raw in livePurchases()) {
            val id = org.ghost.entitlement.api.PurchaseId(raw)
            e.acknowledge(id, org.ghost.entitlement.api.Disclosure.entries.toSet())
            val instructions = e.paymentInstructions(id) ?: continue
            val invoice = ent.issuer.bySubaddress(instructions.subaddress) ?: continue
            if (instructions.outstandingAtomic <= 0) continue
            ent.issuer.pay(invoice.minor, maxOf(1L, (instructions.outstandingAtomic * fraction).toLong()))
            paid = true
        }
        if (paid) ent.mine(blocks)
    }

    /**
     * True when an invoiced XMR pack's invoice is not paid in full at the issuer: what the user's own
     * wallet knows (read from the model issuer, never through the engine, so asking costs no event).
     */
    fun unpaidInvoice(): Boolean {
        val subaddresses = ArrayList<String>()
        c.jdbc.query("SELECT subaddress FROM ent_purchase WHERE kind = 'pack' AND pay_with = 'xmr' AND state = 'invoiced' AND subaddress IS NOT NULL") {
            subaddresses += it.string(0)
        }
        return subaddresses.any { s ->
            val inv = ent.issuer.bySubaddress(s)
            inv != null && (inv.state == ModelIssuer.State.CREATED || (inv.state == ModelIssuer.State.SEEN && inv.credited + inv.seen < inv.amount))
        }
    }

    /**
     * What the app shows as uncovered (read without the engine, so asking costs no event): an
     * identity with an op still waiting, no pack in progress, and no ACCESS token of this week or a
     * later one held.
     */
    fun uncovered(): Boolean {
        if (!identity.exists || engine == null) return false
        fun count(sql: String, args: List<Any?> = emptyList()): Long {
            var n = 0L
            c.jdbc.query(sql, args) { n = it.long(0) }
            return n
        }
        if (count("SELECT count(*) FROM outbox_op WHERE released = 0") == 0L) return false
        if (count("SELECT count(*) FROM ent_purchase WHERE kind = 'pack' AND state IN ('prepared', 'invoiced')") > 0) return false
        return count("SELECT count(*) FROM ent_token WHERE kind = 'access' AND epoch >= ?1", listOf(org.ghost.entitlement.engine.Grid.week(w.clock.epochSeconds()))) == 0L
    }

    fun newFlow(): ByteArray {
        val flow = Bytes.sha256(Bytes.ascii("flow|${w.seed}|${c.name}|${c.boots}|$flows")).copyOf(16)
        flowIndex[Bytes.hex(flow)] = flows++
        return flow
    }

    fun flowIndex(flow: ByteArray): Long = flowIndex[Bytes.hex(flow)] ?: -1

    /**
     * The participant's view of a relay session: waits for READY, then the redeem lane at its own pace.
     * A background session's redeem hold (Q29) is decided here from the pending write needs at its
     * start, as SyncRuntime does; the driver keeps the session while [holds] says so, and a no-op
     * action at the deadline makes it look again.
     */
    fun relaySession(s: Session) {
        val e = engine ?: return
        val foreground = s.kind == SyncKind.FOREGROUND
        if (foreground) e.onForeground()
        val policy = c.spec.policy
        val deadline = if (foreground) Long.MAX_VALUE else s.startedAt + policy.backgroundSessionMillis
        val h = if (foreground) RedeemHold.none() else RedeemHold.background(RedeemHold.pendingWriteNeeds(c.stores), deadline)
        hold = s to h
        if (h.armed) w.driver.scheduleProcess(deadline, c, "redeem-hold-deadline:${c.name}") { }
        val lease = HarnessLease(this) { c.session !== s || (s.isFinished() && !holds(s)) }
        val session = scheduler.session(
            if (foreground) ParticipantKind.FOREGROUND else ParticipantKind.BACKGROUND, lease, deadline,
            { c.engine.clockTrusted() }, { c.stores.database.inTransaction }, { h.stepDone() },
        )
        awaitReady(s, e, ParticipantSessionPort(session), lease)
    }

    private fun awaitReady(s: Session, e: EntitlementEngine, port: SessionPort, lease: HarnessLease) {
        w.driver.scheduleProcess(w.clock.millis + READY_POLL_MILLIS, c, "participant-ready:${c.name}") {
            if (lease.closed || engine !== e) return@scheduleProcess
            if (!s.online) {
                awaitReady(s, e, port, lease)
                return@scheduleProcess
            }
            val lane = e.redeemLane()
            if (lane == null) {
                // An inert engine runs no lane: its pass reports the empty step at once (onRelaySession).
                e.relayPass(port)
                return@scheduleProcess
            }
            pass(e, port, lane.firstWait())
        }
    }

    private fun pass(e: EntitlementEngine, port: SessionPort, wait: Long) {
        w.driver.scheduleProcess(w.clock.millis + wait, c, "redeem-lane:${c.name}") {
            if (port.closed || engine !== e) return@scheduleProcess
            e.relayPass(port)
            val lane = e.redeemLane() ?: return@scheduleProcess
            pass(e, port, lane.nextWait())
        }
    }

    /**
     * One periodic job (SyncRuntime.runJob, design §12.2, §19.14): every job draws its quiet-run
     * decision from the production scheduler, whatever becomes of it; a job while a session runs
     * ends at once; a quiet job makes the transport READY for the participant alone.
     */
    fun job() {
        val index = quietIndex++
        val drawn = scheduler.quiet(index)
        val quiet = ent.config.quietOverride?.invoke(this, index, drawn) ?: drawn
        if (c.session != null) return
        if (quiet && engine != null) {
            quietRun()
            return
        }
        jobs++
        if (ent.config.dailyForegroundJobs > 0 && jobs % ent.config.dailyForegroundJobs == 0L) {
            // The user opens the app about once a day (a foreground session of a few minutes).
            w.foreground(c, w.clock.millis, w.clock.millis + FOREGROUND_MILLIS)
            return
        }
        c.startSession(SyncKind.BACKGROUND)
    }

    private var jobs = 0L

    /** A quiet run now (the scheduler's decision, or a scenario's scripted one). */
    fun quietRun() {
        val e = engine ?: return
        val policy = c.spec.policy
        val start = w.clock.millis
        val deadline = start + policy.backgroundSessionMillis
        val lease = HarnessLease(this) { false }
        val run = longArrayOf(start, 0)
        quietRuns += run
        val state = c.transport.ensureReady(minOf(start + policy.bootstrapMillis, deadline - policy.deadlineReserveMillis))
        if (state == TransportState.READY) {
            c.engine.markReady()
            val session = scheduler.session(ParticipantKind.QUIET, lease, deadline, { c.engine.clockTrusted() }, { c.stores.database.inTransaction })
            calls.onIssuerCall = { run[1]++ }
            try {
                e.onQuietRun(ParticipantSessionPort(session))
            } finally {
                calls.onIssuerCall = null
            }
        }
        lease.close()
        c.transport.abort()
        if (run[1] > 1) violation("J9: ${run[1]} issuer calls in one quiet run")
        ent.checkAmounts(c, "quiet run")
    }

    /** A user issuer call (design §8.3, §12.2): only while the app is visible, else on a closed session. */
    fun userCall(block: (SessionPort) -> Unit) {
        if (engine == null) return
        val policy = c.spec.policy
        val visible = c.foregroundUntil > w.clock.millis
        val lease = HarnessLease(this) { false }
        var own = false
        if (!visible) {
            lease.close()
        } else if (c.session == null) {
            val state = c.transport.ensureReady(w.clock.millis + policy.bootstrapMillis)
            if (state == TransportState.READY) c.engine.markReady() else lease.close()
            own = true
        }
        val session = scheduler.session(
            ParticipantKind.USER_ISSUER_CALL, lease, w.clock.millis + policy.bootstrapMillis + USER_CALL_MILLIS,
            { c.engine.clockTrusted() }, { c.stores.database.inTransaction },
        )
        block(ParticipantSessionPort(session))
        lease.close()
        if (own && c.session == null) c.transport.abort()
    }

    /** True for a drop namespace of this client (its engine, not the oracle, consumes it). */
    fun dropNamespace(ns: NamespaceId): Boolean {
        var found = false
        c.jdbc.query("SELECT 1 FROM ent_invite WHERE drop_namespace = ?1", listOf(ns.toByteArray())) { found = true }
        c.jdbc.query("SELECT 1 FROM ent_drop_target WHERE drop_namespace = ?1", listOf(ns.toByteArray())) { found = true }
        return found
    }

    override fun toString(): String = "EntClient(${c.name})"

    private companion object {
        const val READY_POLL_MILLIS = 1_000L
        const val USER_CALL_MILLIS = 120_000L
        const val FOREGROUND_MILLIS = 5 * 60_000L
    }
}

/**
 * The engine's randomness in the harness: deterministic per process, with one stream per drawing
 * call site of the engine (the class and method that draws), so the number of draws one flow makes
 * (a finalization's activation offset, a re-prepared purchase's seed) never shifts the values
 * another flow draws (the redeem lane's waits and request ids). Production draws are independent
 * CSPRNG outputs ([SecureEntitlementRandom]); a single seeded stream would couple them, which only
 * a deterministic harness can see, and which would make the NI-K comparisons compare draw counts.
 * The PRF is HMAC-SHA-256 under a per-process key, as in production.
 */
internal class SiteRandom(private val key: ByteArray) : EntitlementRandom {
    private val counters = HashMap<String, Long>()
    private val prfKey = Bytes.sha256(key, Bytes.ascii("prf"))

    private fun site(): String {
        val frame = Thread.currentThread().stackTrace.firstOrNull { f ->
            f.className.startsWith("org.ghost.") && !f.className.startsWith(SiteRandom::class.java.name)
        }
        return frame?.let { "${it.className.substringBefore('$')}#${it.methodName}" } ?: "unknown"
    }

    @Synchronized
    override fun bytes(size: Int): ByteArray {
        require(size in 1..64) { "random size out of range" }
        val s = site()
        val n = counters.merge(s, 1L, Long::plus)
        return Bytes.sha256(key, Bytes.ascii(s), Bytes.u64(checkNotNull(n))).let { h -> if (size <= 32) h.copyOf(size) else h + Bytes.sha256(h).copyOf(size - 32) }
    }

    override fun uniform(): Double = (java.nio.ByteBuffer.wrap(bytes(8)).long ushr 11) * (1.0 / (1L shl 53))

    override fun prf(domain: Int, input: ByteArray): Double {
        val out = Bytes.hmac(prfKey, java.nio.ByteBuffer.allocate(4).putInt(domain).array(), input)
        return (java.nio.ByteBuffer.wrap(out, 0, 8).long ushr 11) * (1.0 / (1L shl 53))
    }

    override fun toString(): String = "SiteRandom"
}

/** A lease of the harness transport for one participant activity (SyncRuntime's leases). */
internal class HarnessLease(private val owner: EntClient, private val ended: () -> Boolean) : TransportLease {
    private var open = true

    override val closed: Boolean get() = !open || ended()

    override fun awaitReady(deadlineMonotonicMillis: Long): Boolean = !closed

    override fun close() {
        open = false
    }

    override fun <T> use(block: (EntitlementCalls) -> T): T {
        if (closed) throw NetworkException("closed")
        return block(owner.calls)
    }

    override fun newFlow(): ByteArray = owner.newFlow()

    override fun endFlow(flow: ByteArray) = owner.calls.endFlow(flow)

    override fun toString(): String = "HarnessLease"
}

/**
 * The identity lifecycle; it lives outside the database and survives crashes. A restore calls
 * [restored], so a crash after it classifies apart from one before it (design §8.4 crash cases).
 */
internal class HarnessIdentity(val root: RootEntropy, private val restored: () -> Unit = {}) : IdentityPort {
    var exists = false
    val log = ArrayList<String>()

    override fun hasIdentity(): Boolean = exists

    override fun restore(mnemonic: List<String>) {
        check(!exists) { "identity exists" }
        check(RootEntropy.fromMnemonic(mnemonic).toMnemonic() == root.toMnemonic()) { "the backup of another identity" }
        exists = true
        log += "restore"
        restored()
    }

    override fun create(invite: Invite?) {
        check(!exists) { "identity exists" }
        exists = true
        log += if (invite == null) "create-resumed" else "create"
    }

    override fun wipe() {
        exists = false
        log += "wipe"
    }

    override fun inviteKeys(index: Int): InviteKeys = root.inviteKeys(index)

    override fun toString(): String = "HarnessIdentity"
}

/** Real drop sealing with a per-process deterministic random stream (crash classification needs identical bytes). */
internal class HarnessSeal(private val owner: EntClient, key: ByteArray) : SealPort {
    private val random = SecureRandom.getInstance("SHA1PRNG").apply { setSeed(Bytes.sha256(key, Bytes.ascii("seal"))) }

    /** Seals [creditToken]; the token accounting learns it left in a drop blob once the engine's transaction commits. */
    override fun sealCredit(creditToken: ByteArray, dropKey: ByteArray, dropNamespace: ByteArray): ByteArray {
        val nullifier = Bytes.hex(TestSchedule.nullifier(creditToken))
        owner.uncommitted += { owner.ent.records.sealed += nullifier }
        return DropSeal.sealCredit(creditToken, dropKey, dropNamespace, random)
    }

    override fun sealDummy(dropKey: ByteArray, dropNamespace: ByteArray): ByteArray = DropSeal.sealDummy(dropKey, dropNamespace, random)

    override fun open(inviteIndex: Int, blob: ByteArray, dropNamespace: ByteArray): DropSeal.Opened =
        DropSeal.open(blob, owner.identity.root.inviteDropKeyPair(inviteIndex), dropNamespace)

    override fun toString(): String = "HarnessSeal"
}

/** The device wall clock and the monotonic clock of the harness world. */
internal class HarnessEntClock(private val w: World) : EntitlementClock {
    override fun epochSeconds(): Long = w.clock.epochSeconds()

    override fun monotonicMillis(): Long = w.clock.millis

    override fun sleep(millis: Long): Boolean {
        w.clock.advance(millis)
        return true
    }

    override fun toString(): String = "HarnessEntClock"
}

/** User calls run as actions of the client's process; the payment screen is only recorded. */
internal class HarnessUserCalls(private val owner: EntClient) : UserCallPort {
    val log = ArrayList<String>()

    override fun runUserIssuerCall(block: (SessionPort) -> Unit) {
        val c = owner.c
        owner.w.driver.scheduleProcess(owner.w.clock.millis, c, "user-call:${c.name}") { owner.userCall(block) }
    }

    override fun paymentScreenShown() {
        log += "shown"
    }

    override fun paymentScreenHidden() {
        log += "hidden"
    }

    override fun toString(): String = "HarnessUserCalls"
}
