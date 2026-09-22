package org.ghost.app

import org.ghost.entitlement.api.IdentityActivationHook
import org.ghost.identity.RootEntropy
import org.ghost.messaging.api.Messaging
import org.ghost.messaging.engine.DmKeys
import org.ghost.messaging.engine.MessagingRuntime
import org.ghost.sync.api.ConsumerTail
import org.ghost.sync.api.ParticipantSession
import org.ghost.sync.api.SessionParticipant
import org.ghost.sync.api.SyncController
import org.ghost.sync.api.SyncListener
import org.ghost.sync.store.SyncStores
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.RejectedExecutionException

/**
 * What [MessagingWiring] needs of one DM stack: `MessagingRuntime`'s surface, behind an interface so
 * the wiring's decisions are tested on the JVM against a recording stack (`MessagingWiringTest`)
 * and end to end against the real one (`MessagingWiringRuntimeTest`).
 */
internal interface DmStack : AutoCloseable {
    /** The sync stores this stack was built over; a new database means a new stack. */
    val stores: SyncStores
    val messaging: Messaging
    val listener: SyncListener
    val consumerTail: ConsumerTail
    fun onTimeTrigger()
    fun unlock(root: () -> RootEntropy?): DmKeys.Opened
    fun lock()
    fun cancelWakes()
}

/** [DmStack] over the real `MessagingRuntime`. */
internal class RuntimeStack(private val runtime: MessagingRuntime) : DmStack {
    override val stores: SyncStores get() = runtime.stores
    override val messaging: Messaging get() = runtime.messaging
    override val listener: SyncListener get() = runtime.listener
    override val consumerTail: ConsumerTail get() = runtime.consumerTail

    override fun onTimeTrigger() = runtime.onTimeTrigger()

    override fun unlock(root: () -> RootEntropy?): DmKeys.Opened = runtime.unlock(root)

    override fun lock() = runtime.lock()

    override fun cancelWakes() = runtime.cancelWakes()

    override fun close() = runtime.close()

    override fun toString(): String = "RuntimeStack"
}

/**
 * **`MessagingWiring`** (Phase 9 design §13.7 "Wiring", §13.1's `:app` row, §13.4; slice S12): the
 * app's DM decisions, free of Android types, as [SyncWiring] is for sync.
 *
 * > `MessagingWiring` (in `:app`) creates the actor after the sync controller, sets the listener
 * > and the tail at process start, wires the `IdentityActivationHook` (§13.4), and runs a sweep,
 * > R-K1 and the resumable ACTIVATE check (§21.12) at the first database open. Lock and wipe close
 * > the DM context (`ctxClose` zeroises the native keys, §2.5) and zeroize the Kotlin-side key
 * > material; wipe also cancels the alarm.
 *
 * What each of those is here:
 *  - **The actor after the sync controller.** The DM stack — engine, actor, timer and context — is
 *    built over the sync runtime's own [SyncStores], once they exist ([ensureStack]): the DM layer
 *    must share the sync engine's `SyncDatabase`, whose lock serializes every transaction and whose
 *    listener slot is the one `Inbox.setListener` fills. A second database object over the same file
 *    would interleave transactions and never hear a hint.
 *  - **The tail at process start** ([onProcessStart]); **the listener at the first database
 *    open**, which is when there is an `Inbox` to set it on — it is a slot of the open database's
 *    stores, not of the process (a recorded deviation, §22.17).
 *  - **The first database open** ([onDatabaseOpen]): the stack is built, the Inbox listener set, the
 *    DM context opened from the stored identity, and a **time-triggered** pass posted: SWEEP first,
 *    then — with an identity and no `dm_self` row — the resumable ACTIVATE of §21.12 point 2 and
 *    the owner steps. R-K1 has already run by then: it is `GhostDatabase.finishOpen`'s, before the
 *    first read of the connection (§22.14 item 7).
 *  - **The K20 hook** ([activationHook]): the identity changed (a trial, a restore, or — through
 *    the `gate` key-change hook — a bound new Olm identity), so the context is **reopened** from the
 *    identity now stored and ACTIVATE runs with the hook's own `restored` flag. It never throws and
 *    never blocks the entitlement thread that calls it: the work is posted to one wiring thread,
 *    because the hook is a prompt and §21.12 point 2 is the guarantee (§22.11 item 11).
 *  - **Relay session start** ([onRelaySessionStart], through [sessionHooks]) and **the alarm**
 *    ([onAlarm]): time triggers (§21.9 rule 1, §10.7 triggers 3 and 5).
 *  - **Lock** ([onLock]) closes the context and drops the Kotlin-side keys; **wipe** ([onWipe]) does
 *    the same, cancels the in-process timer and the alarm, unsets the listener and stops the stack.
 */
internal class MessagingWiring(
    private val controller: SyncController,
    /** The open database's sync stores (`AndroidSyncController.stores`), or null. */
    private val stores: () -> SyncStores?,
    /** `AndroidSyncController.runWhenStoresOpen`: runs the block on its own thread once the stores exist. */
    private val whenStoresOpen: (() -> Unit) -> Unit,
    /** Builds the DM stack over a database's stores (the Android ports live in `GhostApp`). */
    private val stackFor: (SyncStores) -> DmStack,
    /** The stored identity, unwrapped; null when there is none or it cannot be unwrapped now. */
    private val identity: () -> RootEntropy?,
    /**
     * Has the entitlement engine accept the schedule for the open database, outside any
     * transaction, so `DirectoryEsSlots` finds it from inside the DM steps' own (it never opens one).
     */
    private val primeSchedule: () -> Unit,
    /** Installs (or, with null, removes) the alarm receiver's hand-off (`ExpiryAlarmReceiver.onAlarm`). */
    private val setAlarmHandler: ((() -> Unit)?) -> Unit,
    /** The wiring thread the K20 hook posts to; injectable so a test can run it inline. */
    private val hookExecutor: ExecutorService = Executors.newSingleThreadExecutor { r ->
        Thread(r, THREAD_NAME).apply { isDaemon = true }
    },
) {
    private val lock = Any()

    @Volatile
    private var stack: DmStack? = null

    /** The facade of §13.2 over the open database, or null before the first database open. */
    val messaging: Messaging? get() = stack?.messaging

    /**
     * Process start (§13.7): the consumer tail and the alarm hand-off are installed before anything
     * can start a background session or deliver the alarm; with a database key, the database is
     * opened for the DM layer as it is for the payment hold (`SyncWiring`), so the first open's pass
     * runs without waiting for a session.
     */
    fun onProcessStart(keyExists: Boolean) {
        controller.setConsumerTail(tail)
        setAlarmHandler(::onAlarm)
        if (keyExists) whenStoresOpen(::onDatabaseOpen)
    }

    /** The database key was just created (onboarding): the first database open follows. */
    fun onKeyCreated() {
        whenStoresOpen(::onDatabaseOpen)
    }

    /**
     * The app became visible. A database opened by a background job or after an unlock gets its
     * stack here if it has none yet; an existing stack is left as it is (a relay session start is
     * the foreground's time trigger, through [sessionHooks]).
     */
    fun onVisible() {
        whenStoresOpen(::onDatabaseOpen)
    }

    /**
     * The first database open (§13.7): build the stack over the runtime's stores and run what the
     * open owes. Runs on the thread `runWhenStoresOpen` gives it, outside any transaction.
     */
    fun onDatabaseOpen() {
        primeSchedule()
        ensureStack()
    }

    /**
     * The stack of the open database, built on first use. A new stack is wired and opened here, in
     * this order: the Inbox listener, the context, then the database-open time trigger (§21.12
     * point 2, §10.7 trigger 2). Null when no database is open.
     */
    fun ensureStack(): DmStack? = synchronized(lock) {
        val open = stores() ?: return@synchronized null
        stack?.let { if (it.stores === open) return@synchronized it }
        stack?.let(::tearDown)
        val built = stackFor(open)
        open.inbox.setListener(built.listener)
        built.unlock(identity)
        stack = built
        built.onTimeTrigger()
        built
    }

    /** The consumer tail of §13.3 item 6, installed once at process start. */
    private val tail = ConsumerTail { kind, deadline -> ensureStack()?.consumerTail?.run(kind, deadline) }

    /** A relay session is READY (§21.9 rule 1's "relay session start"). Posts; never blocks the session. */
    fun onRelaySessionStart() {
        ensureStack()?.onTimeTrigger()
    }

    /**
     * The alarm fired (§10.7 trigger 5). The receiver's `goAsync()` window is short, so this posts
     * and returns: with no stack yet — a process started for the broadcast — the database open it
     * triggers runs the same pass.
     */
    fun onAlarm() {
        val current = stack
        if (current != null) current.onTimeTrigger() else whenStoresOpen(::onDatabaseOpen)
    }

    /**
     * The K20 hook of §13.4, which `EntitlementWiring.activationHook` is set to. See the class note:
     * it posts and returns, and what it posts reopens the context before ACTIVATE.
     */
    val activationHook: IdentityActivationHook = IdentityActivationHook { restored ->
        try {
            hookExecutor.execute { activate(restored) }
        } catch (e: RejectedExecutionException) {
            // A wiring shut down with the process: §21.12 point 2's resume runs ACTIVATE at the next
            // database open instead.
            Unit
        }
    }

    /** The hook's body, on the wiring thread. */
    private fun activate(restored: Boolean) {
        val current = ensureStack() ?: return
        if (current.unlock(identity) != DmKeys.Opened.OPENED) return
        if (restored) current.messaging.onRestored() else current.messaging.onActivated()
    }

    /**
     * The participant the sync runtime runs (Phase 8 design §11.6), with the DM layer's relay
     * session start in front of it. The entitlement engine stays the one participant; this only
     * adds the time trigger, which posts to the DM actor and returns, so the session never waits for
     * the DM layer.
     */
    fun sessionHooks(participant: SessionParticipant): SessionParticipant = object : SessionParticipant {
        override fun onRelaySession(session: ParticipantSession) {
            onRelaySessionStart()
            participant.onRelaySession(session)
        }

        override fun onQuietRun(session: ParticipantSession) = participant.onQuietRun(session)

        override fun toString(): String = "MessagingSessionHooks"
    }

    /**
     * Lock (§2.5, §13.7): the DM context closes — `ctxClose` zeroises the native keys — and the
     * Kotlin-side key material goes with it. The facade then answers `CRYPTO_UNAVAILABLE` until
     * the next unlock ([onUnlock]).
     */
    fun onLock() {
        stack?.lock()
    }

    /** Unlock: the context is reopened from the stored identity. */
    fun onUnlock(): DmKeys.Opened? = stack?.unlock(identity)

    /**
     * Wipe (§13.7, §10.7): the context closes as at lock, the in-process timer and the one alarm are
     * cancelled — "cancelled … at wipe", §22.14 item 11 — the Inbox listener is removed and the
     * stack stops. Call it **before** the sync controller's wipe drops the stores.
     */
    fun onWipe() = synchronized(lock) {
        stack?.let(::tearDown)
        stack = null
    }

    private fun tearDown(old: DmStack) {
        old.lock()
        old.cancelWakes()
        old.stores.inbox.setListener(null)
        old.close()
    }

    override fun toString(): String = "MessagingWiring"

    companion object {
        /** The thread the K20 hook's work runs on. */
        const val THREAD_NAME: String = "ghost-dm-wiring"
    }
}
