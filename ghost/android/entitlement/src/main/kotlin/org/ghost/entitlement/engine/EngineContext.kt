package org.ghost.entitlement.engine

import org.ghost.entitlement.port.EntitlementClock
import org.ghost.entitlement.port.EntitlementRandom
import org.ghost.entitlement.port.IdentityPort
import org.ghost.entitlement.port.SealPort
import org.ghost.entitlement.port.TokenCryptoPort
import org.ghost.entitlement.port.UserCallPort
import org.ghost.entitlement.store.ClaimStore
import org.ghost.entitlement.store.InviteStore
import org.ghost.entitlement.store.KeyStore
import org.ghost.entitlement.store.PurchaseStore
import org.ghost.entitlement.store.StateStore
import org.ghost.entitlement.store.SyncTables
import org.ghost.entitlement.store.TokenStore
import org.ghost.network.EntitlementCrypto.ScheduleSummary
import org.ghost.sync.api.CapabilityNeed
import org.ghost.sync.api.NamespaceId
import org.ghost.sync.api.PrivacyMode
import org.ghost.sync.api.SyncTransaction
import org.ghost.sync.store.SyncStores
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong

/** The engine's ports (design §11.1 `port/`); production wiring: `android.EntitlementWiring`. */
class EngineDeps(
    val crypto: TokenCryptoPort,
    val clock: EntitlementClock,
    val random: EntitlementRandom,
    val identity: IdentityPort,
    val seal: SealPort,
    val userCalls: UserCallPort,
    val privacyMode: () -> PrivacyMode,
) {
    override fun toString(): String = "EngineDeps"
}

/** In-process counters (design §11.6, §12.4, §5.7): counts only, never persisted or sent. */
internal object Counters {
    const val NO_SLOT = "no_slot"
    const val TOKENS_REPLAYED = "tokens_replayed"
    const val TOKENS_REFUSED_LOCALLY = "tokens_refused_locally"
    const val REFRESH_REPLAYED = "refresh_replayed"
    const val CREDIT_DROPPED = "credit_dropped"
    const val DROP_DUMMY = "drop_dummy"
    const val DROP_INVALID = "drop_invalid"
}

/**
 * What the engine keeps in memory for the life of the process only (design §11.3 "never persisted"):
 * the relay-facing clock estimate, flows with a call in flight, the one identical retry after a
 * malformed answer, `WRONG_PERIOD` waits of reservations, first sightings of needs, the moment
 * `ENTITLEMENT_NEEDED` arose, the GC pace and counters. A restart forgets all of it, which costs at
 * most identical retries.
 */
internal class EngineMemory {
    val clock = ClockEstimate()
    val trialCall = AtomicBoolean()

    /** A payment screen is visible: shown and neither hidden nor hidden with the app since (§19.11). */
    val paymentScreenOpen = AtomicBoolean()
    private val malformed: MutableSet<List<Byte>> = ConcurrentHashMap.newKeySet()
    private val inFlight: MutableSet<List<Byte>> = ConcurrentHashMap.newKeySet()
    private val retryAfter = ConcurrentHashMap<List<Byte>, Long>()
    private val firstSeen = ConcurrentHashMap<CapabilityNeed, Long>()
    private val counters = ConcurrentHashMap<String, AtomicLong>()

    @Volatile
    private var neededSince: Long? = null

    private var lastGcMillis: Long? = null

    /** True the first time a flow meets a malformed answer: it gets one identical retry (design §5.7). */
    fun firstMalformed(id: ByteArray): Boolean = malformed.add(id.toList())

    fun clearMalformed(id: ByteArray) {
        malformed.remove(id.toList())
    }

    fun inFlight(id: ByteArray): Boolean = inFlight.contains(id.toList())

    /** Runs [block] unless a call of flow [id] is already in flight (no two calls of one flow at once). */
    fun flight(id: ByteArray, block: () -> Unit) {
        val key = id.toList()
        if (!inFlight.add(key)) return
        try {
            block()
        } finally {
            inFlight.remove(key)
        }
    }

    fun retryAfter(nullifier: ByteArray): Long? = retryAfter[nullifier.toList()]

    fun setRetryAfter(nullifier: ByteArray, at: Long) {
        retryAfter[nullifier.toList()] = at
    }

    fun clearRetryAfter(nullifier: ByteArray) {
        retryAfter.remove(nullifier.toList())
    }

    /** The first time [need] was seen in this process (READ MISSING timing, §12.4). */
    fun firstSeen(need: CapabilityNeed, now: Long): Long = firstSeen.putIfAbsent(need, now) ?: now

    fun forgetNeeds(current: Collection<CapabilityNeed>) {
        firstSeen.keys.retainAll(current.toSet())
    }

    fun needUnmet(now: Long) {
        if (neededSince == null) neededSince = now
    }

    fun needMet() {
        neededSince = null
    }

    fun neededSince(): Long? = neededSince

    /** At most one GC pass per [GC_INTERVAL_MILLIS]. */
    @Synchronized
    fun gcDue(nowMillis: Long): Boolean {
        val last = lastGcMillis
        if (last != null && nowMillis - last in 0 until GC_INTERVAL_MILLIS) return false
        lastGcMillis = nowMillis
        return true
    }

    fun count(name: String) {
        counters.computeIfAbsent(name) { AtomicLong() }.incrementAndGet()
    }

    fun counter(name: String): Long = counters[name]?.get() ?: 0L

    override fun toString(): String = "EngineMemory"

    private companion object {
        const val GC_INTERVAL_MILLIS = 60 * 60_000L
    }
}

/**
 * Everything one engine instance needs over one open database: the sync stores, the accepted
 * schedule, the ports, the entitlement stores and the step components. A new database (after a wipe)
 * gets a new context; [accepted] is false while the built-in schedule conflicts with the remembered
 * one, and every step then stays inert.
 */
internal class EngineContext(val sync: SyncStores, val summary: ScheduleSummary, val deps: EngineDeps, val memory: EngineMemory) {
    val purchases = PurchaseStore()
    val tokens = TokenStore()
    val invites = InviteStore()
    val claims = ClaimStore()
    val state = StateStore()
    val keys = KeyStore()

    @Volatile
    var accepted: Boolean = false

    val crypto: TokenCryptoPort get() = deps.crypto
    val random: EntitlementRandom get() = deps.random
    val clock: EntitlementClock get() = deps.clock
    val identity: IdentityPort get() = deps.identity
    val seal: SealPort get() = deps.seal

    val purchaseSteps: PurchaseSteps by lazy { PurchaseSteps(this) }
    val trialSteps: TrialSteps by lazy { TrialSteps(this) }
    val claimSteps: ClaimSteps by lazy { ClaimSteps(this) }
    val dropSteps: DropSteps by lazy { DropSteps(this) }
    val restoreScan: RestoreScan by lazy { RestoreScan(this) }
    val redeemLane: RedeemLane by lazy { RedeemLane(this) }
    val quietRunWork: QuietRunWork by lazy { QuietRunWork(this) }
    val gc: Gc by lazy { Gc(this) }

    fun now(): Long = deps.clock.epochSeconds()

    fun mode(): PrivacyMode = deps.privacyMode()

    /** One short sync transaction (design §11.5); never with a network call inside. */
    fun <T> tx(block: (SyncTransaction) -> T): T = sync.database.transaction(block)

    fun alarm(tx: SyncTransaction, bit: Int) {
        state.raiseAlarm(tx, bit)
    }

    /** The schedule covers weeks [week] .. [week] + [weeks] − 1. */
    fun covers(week: Long, weeks: Int): Boolean = week >= summary.firstWeek && week + weeks - 1 <= summary.lastWeek

    /** A purchase may start: the schedule reaches at least [HORIZON_WEEKS] weeks ahead (else `UPDATE_REQUIRED`). */
    fun purchasable(now: Long): Boolean {
        val week = Grid.week(now)
        return summary.lastWeek - week >= HORIZON_WEEKS && covers(week, Layouts.PACK_WEEKS)
    }

    /**
     * Stops a drop namespace (design §8.5, §9.3): removed when nothing refers to it, otherwise it stops
     * listening and loses its relay set, so it raises no capability need and makes no relay traffic.
     */
    fun retireNamespace(tx: SyncTransaction, ns: NamespaceId) {
        if (!SyncTables.namespaceRegistered(tx, ns)) return
        if (sync.namespaces.remove(tx, ns)) return
        sync.namespaces.setRelays(tx, ns, emptySet())
        sync.namespaces.setListening(tx, ns, false)
    }

    override fun toString(): String = "EngineContext"

    companion object {
        const val HORIZON_WEEKS = 5L
        const val ID_BYTES = 16
        const val SECRET_BYTES = 32
    }
}
