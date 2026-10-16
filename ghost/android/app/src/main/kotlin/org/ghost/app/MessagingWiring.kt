package org.ghost.app

import org.ghost.entitlement.api.IdentityActivationHook
import org.ghost.identity.RootEntropy
import org.ghost.messaging.api.ActivationOutcome
import org.ghost.messaging.api.Messaging
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
 *
 * Every context operation takes a `wanted` predicate that the stack asks **on the DM actor, in the
 * turn that would open the context** (S12 review): that is what keeps a lock or a wipe the wiring
 * recorded after the request was made from being undone by it.
 */
internal interface DmStack : AutoCloseable {
    /** The sync stores this stack was built over; a new database means a new stack. */
    val stores: SyncStores
    val messaging: Messaging
    val listener: SyncListener
    val consumerTail: ConsumerTail

    /**
     * Posts a time-triggered pass (§21.9 rule 1). [sessionStart] is true for a relay session start
     * alone: the one trigger that may open the next bundle-fetch attempt (§21.7 point 5).
     */
    fun onTimeTrigger(sessionStart: Boolean = false)

    /** Posts: the context reopened from [root] in one actor turn, if [wanted] still holds there. */
    fun open(root: () -> RootEntropy?, wanted: () -> Boolean)

    /**
     * The K20 hook's body in one actor turn — reopen from [root], then ACTIVATE with [restored] —
     * and waits for it. Null when [wanted] did not hold on the actor or the context did not open.
     */
    fun openAndActivate(root: () -> RootEntropy?, restored: Boolean, wanted: () -> Boolean): ActivationOutcome?

    /** Posts the context's close: `ctxClose` and the Kotlin-side keys (§2.5). Returns at once. */
    fun lock()

    /**
     * The app lifecycle's ON_START/ON_STOP (§6.5's foreground half of the on-screen signal; slice
     * S6). Default no-op: stacks without the media pipeline have nothing to tell.
     */
    fun onForeground(visible: Boolean) = Unit

    /** §13.7's lock half for the media layer: the preview cache and the on-screen signal go. */
    fun onMediaLock() = Unit

    /**
     * Stops the stack for good: no pass that has not started runs, the context closes and both
     * wakes are cancelled in the actor's last turn, then the actor and the timer stop. Blocks for as
     * long as the pass in flight takes.
     */
    override fun close()
}

/** [DmStack] over the real `MessagingRuntime`. */
internal class RuntimeStack(private val runtime: MessagingRuntime) : DmStack {
    override val stores: SyncStores get() = runtime.stores
    override val messaging: Messaging get() = runtime.messaging
    override val listener: SyncListener get() = runtime.listener
    override val consumerTail: ConsumerTail get() = runtime.consumerTail

    override fun onTimeTrigger(sessionStart: Boolean) = runtime.onTimeTrigger(sessionStart)

    override fun open(root: () -> RootEntropy?, wanted: () -> Boolean) = runtime.requestUnlock(root, wanted)

    override fun openAndActivate(root: () -> RootEntropy?, restored: Boolean, wanted: () -> Boolean): ActivationOutcome? =
        runtime.reopenAndActivate(root, restored, wanted)

    override fun lock() = runtime.requestLock()

    override fun onForeground(visible: Boolean) = runtime.onForeground(visible)

    override fun onMediaLock() = runtime.onMediaLocked()

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
 *    identity now stored and ACTIVATE runs with the hook's own `restored` flag, in one actor turn.
 *    It never throws and never blocks the entitlement thread that calls it: the work is posted to
 *    one wiring thread, because the hook is a prompt and §21.12 point 2 is the guarantee (§22.11
 *    item 11).
 *  - **Relay session start** ([onRelaySessionStart], through [sessionHooks]) and **the alarm**
 *    ([onAlarm]): time triggers (§21.9 rule 1, §10.7 triggers 3 and 5).
 *  - **Lock** ([onLock]) closes the context and drops the Kotlin-side keys; **wipe** ([onWipe]) stops
 *    the stack for good — the listener removed first, then the context closed and both wakes
 *    cancelled in the actor's last turn — and cancels the alarm itself as well.
 *
 * **Lock and wipe are sticky** (S12 review). Both are recorded here before anything is posted, and
 * every context open asks for them on the actor, in the turn that would open it ([contextWanted]):
 * a K20 hook, a new database or an unlock posted before the lock can no longer reopen a context the
 * app reports locked, and nothing builds a stack over a database being wiped until the next
 * database key exists ([onKeyCreated]).
 *
 * **Nothing here throws into the thread that calls it** (S12 review): the hook thread, the sync
 * runtime's callback thread and the consumer tail's all end the process on an uncaught exception
 * (Phase 7 design §11.2 #11). A stack that cannot be built or opened leaves the facade answering
 * `CRYPTO_UNAVAILABLE`, and the next trigger tries again.
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
    /**
     * Cancels the one inexact alarm (`ExpiryAlarm.wakeIn(null)`) whether or not a stack exists: an
     * alarm set by an earlier process is in the system's table before this one built anything, and
     * §10.7 cancels it at wipe all the same.
     */
    private val cancelAlarm: () -> Unit,
    /** The wiring thread the K20 hook posts to; injectable so a test can run it inline. */
    private val hookExecutor: ExecutorService = Executors.newSingleThreadExecutor { r ->
        Thread(r, THREAD_NAME).apply { isDaemon = true }
    },
) {
    private val lock = Any()

    @Volatile
    private var stack: DmStack? = null

    /** The app is locked (§2.5): no context opens until [onUnlock]. */
    @Volatile
    private var locked = false

    /**
     * The app's foreground state (§6.5's signal): kept here, not in the stack, because ON_START
     * can precede the first stack; every stack is handed the flag when built.
     */
    @Volatile
    private var foreground = false

    /** Local data is being wiped: no stack is built and no context opens until [onKeyCreated]. */
    @Volatile
    private var wiped = false

    /** The facade of §13.2 over the open database, or null before the first database open. */
    val messaging: Messaging? get() = stack?.messaging

    /** What every context open asks on the actor, in the turn that would open it. */
    private fun contextWanted(): Boolean = !locked && !wiped

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

    /**
     * The database key was just created (onboarding): the first database open follows. It is also
     * what lifts a wipe — the only database a wiped app can open again is the one this key opens.
     */
    fun onKeyCreated() {
        synchronized(lock) { wiped = false }
        setAlarmHandler(::onAlarm)
        whenStoresOpen(::onDatabaseOpen)
    }

    /**
     * The app became visible. A database opened by a background job or after an unlock gets its
     * stack here if it has none yet; an existing stack is left as it is (a relay session start is
     * the foreground's time trigger, through [sessionHooks]). The foreground flag itself is kept
     * here, in the wiring, and handed to every stack as it is built (slice S6): ON_START can fire
     * before the first stack exists.
     */
    fun onVisible() {
        foreground = true
        stack?.onForeground(true)
        whenStoresOpen(::onDatabaseOpen)
    }

    /**
     * ON_STOP (the ProcessLifecycleOwner observer): the zero-click gate shuts at once — no
     * preview decodes while the app is in the background (§9.3, T46). A stack built later is
     * handed the flag at build.
     */
    fun onHidden() {
        foreground = false
        stack?.onForeground(false)
    }

    /**
     * The first database open (§13.7): build the stack over the runtime's stores and run what the
     * open owes. Runs on the thread `runWhenStoresOpen` gives it, outside any transaction.
     */
    fun onDatabaseOpen() {
        if (wiped) return
        try {
            primeSchedule()
        } catch (e: RuntimeException) {
            // The acceptance transaction failed (a database closing under a wipe): the DM steps
            // then find no slot table and answer NO_RELAYS until a later trigger primes it.
            Unit
        }
        ensureStack()
    }

    /**
     * The stack of the open database, built on first use. A new stack is wired and opened here, in
     * this order: the Inbox listener, the context (posted, and only if [contextWanted]), then the
     * database-open time trigger (§21.12 point 2, §10.7 trigger 2) — posted after the open, so the
     * actor runs them in that order. Null when no database is open, while a wipe is in progress, or
     * when the stack could not be built.
     */
    fun ensureStack(): DmStack? {
        var replaced: DmStack? = null
        val result = synchronized(lock) {
            if (wiped) return@synchronized null
            val open = stores() ?: return@synchronized null
            stack?.let { if (it.stores === open) return@synchronized it }
            // A new database (the runtime reopened it): the old one's stack stops below.
            replaced = stack
            stack = null
            replaced?.let { it.stores.inbox.setListener(null) }
            val built = try {
                stackFor(open)
            } catch (e: RuntimeException) {
                // The database is closing, or a port could not be built: no stack, and no orphan —
                // nothing was started. The next trigger tries again.
                return@synchronized null
            }
            try {
                open.inbox.setListener(built.listener)
                stack = built
                built.onForeground(foreground)
                built.open(identity, ::contextWanted)
                built.onTimeTrigger()
                built
            } catch (e: RuntimeException) {
                // Never left half-installed: a stack the wiring does not hold must not keep a
                // listener, an actor or a timer (§7.9: one actor per database).
                stack = null
                open.inbox.setListener(null)
                stopQuietly(built)
                null
            }
        }
        // Stopped outside the lock: the last turn waits for the old stack's pass in flight.
        replaced?.let(::stopQuietly)
        return result
    }

    /** The consumer tail of §13.3 item 6, installed once at process start. */
    private val tail = ConsumerTail { kind, deadline -> ensureStack()?.consumerTail?.run(kind, deadline) }

    /** A relay session is READY (§21.9 rule 1's "relay session start"). Posts; never blocks the session. */
    fun onRelaySessionStart() {
        ensureStack()?.onTimeTrigger(sessionStart = true)
    }

    /**
     * The alarm fired (§10.7 trigger 5). The receiver's `goAsync()` window is short, so this posts
     * and returns: with no stack yet — a process started for the broadcast — the database open it
     * triggers runs the same pass. A stack that is being stopped drops the trigger.
     */
    fun onAlarm() {
        val current = stack
        if (current != null) current.onTimeTrigger() else if (!wiped) whenStoresOpen(::onDatabaseOpen)
    }

    /**
     * The K20 hook of §13.4, which `EntitlementWiring.activationHook` is set to. See the class note:
     * it posts and returns, and what it posts reopens the context and runs ACTIVATE in one turn.
     */
    val activationHook: IdentityActivationHook = IdentityActivationHook { restored ->
        try {
            hookExecutor.execute {
                try {
                    activate(restored)
                } catch (e: RuntimeException) {
                    // An uncaught exception on this thread would end the process; §21.12 point 2's
                    // resume runs ACTIVATE at the next time-triggered pass instead.
                    Unit
                }
            }
        } catch (e: RejectedExecutionException) {
            // A wiring shut down with the process: §21.12 point 2's resume runs ACTIVATE at the next
            // database open instead.
            Unit
        }
    }

    /**
     * The hook's body: reopen the context from the identity now stored, then ACTIVATE — one actor
     * turn. Runs on the wiring thread for the hook, and on the caller's for a caller that needs the
     * answer (the `gate` variant's instrumentation after its key-change switch). Null when there is
     * no database, the app is locked or being wiped, or the context did not open.
     */
    fun activate(restored: Boolean): ActivationOutcome? {
        val current = ensureStack() ?: return null
        if (!contextWanted()) return null
        return try {
            current.openAndActivate(identity, restored, ::contextWanted)
        } catch (e: IllegalStateException) {
            // The facade's INTERNAL, or a stack stopped under the call (a wipe): nothing activated.
            null
        }
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
     * [onUnlock]. The lock is recorded first and the close is posted, so this returns at once on the
     * main thread, every facade call made after it queues behind the close, and no open posted
     * before it can undo it.
     */
    fun onLock() {
        locked = true
        stack?.onMediaLock()
        stack?.lock()
    }

    /** Unlock: the context is reopened from the stored identity (posted, behind anything queued). */
    fun onUnlock() {
        locked = false
        stack?.open(identity, ::contextWanted)
    }

    /**
     * Wipe (§13.7, §10.7): recorded first, so nothing builds a stack or opens a context again until
     * [onKeyCreated]; then the stack stops — the Inbox listener removed, the context closed and both
     * wakes cancelled in the actor's last turn, after the pass in flight — and the one alarm is
     * cancelled and the receiver's hand-off cleared whether or not there was a stack. Call it
     * **before** the sync controller's wipe drops the stores, and not on the main thread: it waits
     * for the pass in flight.
     */
    fun onWipe() {
        val old = synchronized(lock) {
            wiped = true
            stack.also { stack = null }
        }
        old?.let(::stopQuietly)
        cancelAlarm()
        setAlarmHandler(null)
    }

    /** Listener first, so no hint can post a pass behind the last turn; then the stack stops. */
    private fun stopQuietly(old: DmStack) {
        try {
            old.stores.inbox.setListener(null)
        } catch (e: RuntimeException) {
            Unit
        }
        try {
            old.close()
        } catch (e: RuntimeException) {
            // The last turn failed (the database closing): the actor has stopped all the same, and
            // the alarm is cancelled by the caller.
            Unit
        }
    }

    override fun toString(): String = "MessagingWiring"

    companion object {
        /** The thread the K20 hook's work runs on. */
        const val THREAD_NAME: String = "ghost-dm-wiring"
    }
}
