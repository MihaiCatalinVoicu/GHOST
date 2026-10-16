package org.ghost.messaging.engine

import org.ghost.messaging.channel.engine.ChannelPassSteps
import org.ghost.messaging.port.DmClock
import org.ghost.messaging.store.ContactStore
import org.ghost.messaging.store.HeldStore
import org.ghost.messaging.store.MessageStore
import org.ghost.messaging.store.SessionStore
import org.ghost.storage.StorageFullException
import org.ghost.sync.api.BlobHash
import org.ghost.sync.api.Consumer
import org.ghost.sync.api.NamespaceId
import org.ghost.sync.api.SessionKind
import org.ghost.sync.api.SyncChange
import org.ghost.sync.api.SyncDatabase
import java.util.concurrent.Callable
import java.util.concurrent.ExecutionException
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.Future
import java.util.concurrent.RejectedExecutionException
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean

/**
 * The **DM actor** (Phase 9 design §13.7, §21.9): one process-wide single-thread executor that
 * owns every `:messaging` transaction and every session call.
 *
 * > One process-wide single-thread executor (`ghost-dm`) owns every `:messaging` transaction and
 * > every `DmNative` session call (§7.9). It is woken by: listener hints (`SyncChange.INBOX`,
 * > `OUTCOMES`, `CAPABILITIES`, `TOPOLOGY`), facade calls, the in-process expiry timer, the alarm
 * > receiver, the database open, and the `ConsumerTail`. Hints carry no payload and the actor
 * > re-reads state, so a lost or duplicated hint is harmless.
 *
 * **Why one thread and not a lock.** Two reasons the design names. The value-state rule of §7.9
 * point 3 — "the DM actor is the only thread that calls `DmNative` session functions; the context
 * handle is not shared with other threads" — and the two-phase shape of SEND and the
 * establishment steps, which read, prepare outside a transaction and then write: that is sound
 * **because** nothing else can write DM state in between.
 *
 * **No work on lane threads** (§13.7). `Inbox.setListener` fires on the committing thread, which
 * can be a lane thread; the listener only posts a coalesced flag here and returns.
 *
 * **The pass, and the two kinds of it** (§21.9 rule 1, mutant PM-30). Every pass runs the steps
 * that answer what is already in the database: SWEEP, OUTCOME, the bundle claims, the peek order
 * and `RECV`. Only a **time-triggered** pass — the actor timer, a database open, a relay session
 * start — also runs the steps whose *timing* must not depend on what arrived: the owner's
 * OWNER-WEEK, KEEPER and REGROWS, the contact KEEPER, `EST-READY`, `EST-END` and the expired
 * pending items. A card holder that deposits a probe during this device's session must not make a
 * bundle, a registration or an establishment follow it. SWEEP is on the first list because §21.9
 * rule 2 puts it there by name, and it carries the pair-key ratchet of §21.3 point 5 with it —
 * neither writes anything a relay can see.
 *
 * **SWEEP and the wakes arrived with slice S9.** Every pass begins with SWEEP (§13.7's pass order)
 * and ends by rescheduling the in-process timer and the one inexact alarm to the next due minute
 * (§10.7 triggers 1 and 5), and by publishing the unread count the pass changed (§7.2's "After
 * commit" column). Three of §10.7's five sweep triggers are passes that already existed — the
 * database open and the relay session start are [onTimeTrigger], the `ConsumerTail` is
 * [consumerTail] — so what S9 added to this file is the step, not a new road to it.
 */
internal class DmActor(
    private val database: SyncDatabase,
    private val sync: DmSyncPorts,
    private val establishment: EstablishmentSteps,
    private val bundleStep: BundleStep,
    private val sendStep: SendStep,
    private val receiveStep: ReceiveStep,
    private val outcomeStep: OutcomeStep,
    private val heldReplay: HeldReplay,
    private val scheduledSteps: ScheduledSteps,
    private val contactKeeper: ContactKeeper,
    /** SWEEP (§7.2, §10.6): the first step of every pass, whatever triggered it. */
    private val sweeper: Sweeper,
    /**
     * §7.2's "After commit" column: the unread count, and the in-process timer and the one inexact
     * alarm moved to the next due minute (§10.7 triggers 1 and 5). Null cancels both, which is what
     * keeps a stale expiry minute out of the system's alarm table (L7-D7).
     */
    private val schedule: ExpirySchedule,
    private val ownerMaintenance: () -> Unit,
    /**
     * §21.12 point 2's safety net: **ACTIVATE, again**, for an activated identity that has no
     * `dm_self` row. It runs on a time-triggered pass only (see [runPass]).
     *
     * It is a lambda for the same reason [ownerMaintenance] is: the actor names the work, not the
     * step object that does it, and the wiring binds `OwnerSteps.activate(restored = true)` to it
     * followed by `SelfContexts.invalidate()`.
     *
     * **Why `restored = true` and not the caller's own flag.** The flag decides one thing —
     * whether `dm_self.accept_after_minute` is set to this minute — and nothing here can know it:
     * the K20 hook's `restored` argument died with the process (or with the failed call) that did
     * not write the row. `true` is the side that is safe in both cases. An identity that really
     * was restored keeps the one guard §7.6 has left against pre-restore-authored content, now
     * that `dm_seen` and the pair keys are gone; an identity that was not cannot lose anything by
     * it, because without a `dm_self` row it has published no bundle, registered no namespace and
     * could not have been written to at all.
     */
    private val resumeActivation: () -> Unit,
    private val peekOrder: PeekOrder,
    private val material: ContactMaterial,
    private val clock: DmClock,
    private val contexts: SelfContexts,
    /**
     * Where the actor's turns run. Null, which every production caller passes, is the one daemon
     * thread of §13.7 ([THREAD_NAME]). A world of the test harness that runs in virtual time passes
     * an executor of its own, which runs each posted turn on the caller's thread, one at a time and
     * in the order posted, so that it drives [onTimeTrigger], [onChange] and [consumerTail] — the
     * entry points `MessagingRuntime` exposes and `MessagingWiring` calls — instead of calling
     * [runPass] with a trigger of its own choosing (phase review MD-2: the privacy world's own
     * reading of which pass is a relay session start had drifted from the wiring's).
     */
    turns: ExecutorService? = null,
    /**
     * The channel engine's pass (Phase 10 design §7.7, D16: the one actor drains `Consumer.CHANNEL` as it drains
     * `Consumer.DM`), run at the end of every pass with the pass's own trigger, and its next wake among the timer's terms
     * ([nextReadySeconds]). Null where no channel engine is wired (every Phase 9 world).
     */
    private val channels: ChannelPassSteps? = null,
    /**
     * The sender pipeline's pass (Phase 11 §13.5): `MEDIA-OUTCOME` and `MEDIA-FEED` after F9's
     * OUTCOME (they read the outbox it released), `MEDIA-DEADLINE` on time-triggered passes
     * (§21.9 rule 1's shape: nothing a media outcome arrives can cause timer-visible work).
     */
    private val media: MessagingRuntime.MediaPassSteps? = null,
) : AutoCloseable {

    private val contacts = ContactStore()
    private val messages = MessageStore()
    private val sessions = SessionStore()
    private val held = HeldStore()
    private val expiry = ExpiryClock(database, clock)

    /**
     * The actor's own thread, recorded by the thread factory so [call] can tell whether it is
     * already on it (slice S12). A single-thread executor makes exactly one thread for its whole
     * life, so the reference never changes once set. It stays null under an executor passed as
     * `turns`, whose turns run on the thread that posted them.
     */
    @Volatile
    private var actorThread: Thread? = null

    private val executor: ExecutorService = turns ?: Executors.newSingleThreadExecutor { runnable ->
        Thread(runnable, THREAD_NAME).apply { isDaemon = true }.also { actorThread = it }
    }

    /** A wake that arrived while a pass was running; coalesced, because hints carry no payload. */
    private val pending = AtomicBoolean(false)

    /** When a bundle candidate was first stored, so `EST-READY` waits two minutes (§21.7 point 4). */
    private val candidateSince = HashMap<List<Byte>, Long>()

    /**
     * The second the last **time-triggered** pass began — the one kind of pass that may run
     * `EST-READY` (§21.9 rule 1). A candidate whose `EST-READY` fell due at or before it has been
     * offered that pass, whatever the pass made of it, so [nextReadySeconds] stops waking for it.
     * **Actor thread only**, like [candidateSince].
     */
    private var lastTimeTriggeredSecond: Long = Long.MIN_VALUE

    /**
     * Seconds until the first `EST-READY` a stored candidate waits for, or null: §21.9 rule 1's
     * "next EST timer" in the actor timer's minimum (phase review MD-3). Without it nothing woke
     * the actor at candidate + 2 min — in a foreground session the relay session had started
     * already — and the first message went out at the fetch window's end, about 15 minutes after
     * the send. **Actor thread only**, like every reader of [candidateSince]:
     * [ExpirySchedule.afterCommit] runs there.
     *
     * **A due `EST-READY` keeps its wake until a time-triggered pass has run** (design §22.39). Every
     * pass ends by re-arming the timer with this minimum, and a pass a listener hint ran may not run
     * `EST-READY`. The first version kept future terms only ("a candidate already due is left to the
     * pass that is due anyway"), so a hint pass at or after the due second — a fetch or a store
     * outcome of the same relay round — re-armed the timer without the term and **cancelled the wake
     * that was due**: `EST-READY` then waited for the next time trigger, the fetch window's end at
     * the earliest (MD-3's own symptom) and later when the app was hidden by then, and a timer change
     * made meanwhile went out as a pending TIMER_SET (§22.21 item 2's open path). The privacy world
     * on production's triggers met it at the gate scale: its relay rounds fall on the minute and the
     * delay is two minutes, so the round at the due second ran first whenever it fetched or stored
     * anything. On a device the race is narrower (the timer fires within the second it is due) and
     * the same. A due term is now a wake at once, until a time-triggered pass begins at or after it;
     * from then on it is left to the passes that come anyway, so a candidate a pass could not use —
     * or one whose contact stopped fetching — wakes the actor once and never turns into a wake loop.
     */
    fun nextReadySeconds(): Long? {
        // The channel engine's next wake (a settle point, a scheduled pass, a gap hold) is a term of the same minimum:
        // the timer's, never the alarm's (§10.7: the alarm exists for deletion).
        val channelWake = channels?.nextWakeSeconds()
        if (candidateSince.isEmpty()) return channelWake
        val now = clock.nowEpochSeconds()
        val ready = candidateSince.values
            .map { it + EstablishmentSteps.READY_DELAY_SECONDS }
            .filter { due -> due > now || due > lastTimeTriggeredSecond }
            .map { due -> maxOf(0L, due - now) }
            .minOrNull()
        return listOfNotNull(ready, channelWake).minOrNull()
    }

    /**
     * §21.12 point 1's **storage-full latch** (phase review ENG-2): the blobs whose `RECV` or
     * `BUNDLE` transaction rolled back on a full disk and whose `Inbox.defer` could not be written
     * either. While it is not empty no `DM` or `PREKEYS` blob is claimed; each claim step first
     * writes the deferrals it owes, and the first one that commits opens it again. In memory,
     * like the offer counter's reason to exist: a process death is exactly what R2 counts.
     */
    private val owedDefers = ArrayList<Pair<NamespaceId, BlobHash>>()

    /**
     * Set by [retire] before its final turn is queued: from then on a posted turn — a pass, a
     * posted lock or unlock — that has not started yet **does nothing** when it reaches the thread
     * (S12 review). Without it a pass queued by a hint, the in-process timer or the alarm before
     * the wipe ran after the final turn had cancelled the alarm, and its `afterCommit` put the alarm
     * back into the system's table (§10.7: "cancelled … at wipe").
     */
    @Volatile
    private var retiring = false

    /** Set on the actor thread at the end of [retire]'s final turn: facade calls answer `INTERNAL` after it. */
    @Volatile
    private var stopped = false

    /**
     * Runs [body] on the actor thread and waits for it: the facade's contract (§13.2).
     *
     * **On the actor thread itself it runs [body] inline** (found when slice S12 first attached an
     * actor to a real engine). A time-triggered pass calls `ownerMaintenance`, which the wiring
     * binds to `Messaging.runOwnerMaintenance()`, and every facade method posts here: submitting to
     * a single-thread executor from its only thread and then waiting on the future is a deadlock
     * that stops the actor for the life of the process. Every test world before S12 drove the pass
     * directly with no actor attached to the engine, so none could reach it.
     *
     * **The body's own exception is what the caller sees**, not the executor's
     * `ExecutionException` wrapper: the facade's contract is that an `INTERNAL` answer is an
     * `IllegalStateException` (§2.6), and a wrapper would make every caller unwrap it.
     *
     * **After [retire]** it throws `IllegalStateException` — the facade's `INTERNAL` — and never the
     * executor's `RejectedExecutionException`, which no caller of the facade is told to expect (S12
     * review): a call queued behind the final turn, or made after the executor shut down, has no
     * context and no database left to answer from.
     */
    fun <T> call(body: () -> T): T {
        if (Thread.currentThread() === actorThread) return body()
        val future = try {
            executor.submit(
                Callable {
                    check(!stopped) { STOPPED }
                    body()
                },
            )
        } catch (e: RejectedExecutionException) {
            throw IllegalStateException(STOPPED, e)
        }
        return try {
            future.get()
        } catch (e: ExecutionException) {
            throw e.cause ?: e
        }
    }

    /**
     * Posts [body] without waiting; used by the listener hand-off, which must not block a lane.
     * Null after [retire]: a hint that arrives while the wiring is tearing the actor down (a wipe) is
     * dropped rather than thrown into the lane thread that committed it (slice S12). A turn posted
     * before [retire] that has not started when it begins does nothing (see [retiring]).
     */
    fun post(body: () -> Unit): Future<*>? = try {
        executor.submit {
            if (!retiring) body()
        }
    } catch (e: RejectedExecutionException) {
        null
    }

    /**
     * Stops the actor (§13.7 "Lock and wipe"; S12 review): no posted turn that has not started runs
     * any more, [finalTurn] runs on the actor thread **after** the pass in flight, if any, has ended,
     * then the in-memory caches are dropped there — on the thread that uses them — and the executor
     * shuts down. Returns when all of that is done. Idempotent.
     *
     * The order is what makes a wipe final: a pass that was already running can still reschedule
     * the alarm in its `afterCommit`, but it ends before [finalTurn] — the wiring's context close
     * and wake cancel — begins, and nothing queued behind it can run a pass again.
     *
     * It blocks for as long as that pass takes, so it must not be called on the main thread.
     */
    fun retire(finalTurn: () -> Unit) {
        synchronized(this) {
            if (retiring) return
            retiring = true
        }
        val last: () -> Unit = {
            try {
                finalTurn()
            } finally {
                stopped = true
                peekOrder.clear()
                candidateSince.clear()
            }
        }
        try {
            if (Thread.currentThread() === actorThread) {
                last()
            } else {
                val future = try {
                    executor.submit(last)
                } catch (e: RejectedExecutionException) {
                    null
                }
                try {
                    future?.get()
                } catch (e: ExecutionException) {
                    // The final turn failed (a database closing under the wipe): the actor stops
                    // all the same, and what the turn owed is the wiring's to finish (it cancels
                    // the alarm itself).
                    Unit
                }
            }
        } finally {
            executor.shutdown()
        }
    }

    /**
     * The inbox and outcome listener hand-off (§13.7).
     *
     * It returns without touching the database: the hint is a coalesced flag and the pass reads
     * state for itself, so a lost or duplicated hint is harmless and a lane thread is never held.
     */
    fun onChange(change: SyncChange) {
        when (change) {
            SyncChange.INBOX, SyncChange.OUTCOMES, SyncChange.CAPABILITIES, SyncChange.TOPOLOGY ->
                wake(timeTriggered = false)
            else -> Unit
        }
    }

    /**
     * A relay session start, a database open or the actor timer: the three triggers §21.9 rule 1
     * gives the time-triggered steps.
     *
     * [sessionStart] says which of them it is (phase review MD-2). Every time-triggered step runs
     * on each, except one: the next **attempt** of a bundle fetch, which §21.7 point 5 opens "at
     * the first relay session start at least 6 h later". Opened by the alarm or the in-process
     * timer instead, an attempt's 15-minute window could open and close with no relay session to
     * list `P_c` in it, and three such windows made a contact unreachable and failed its first
     * message about 13 hours after the send, whatever its 7-day deadline.
     */
    fun onTimeTrigger(sessionStart: Boolean = false) {
        wake(timeTriggered = true, sessionStart = sessionStart)
    }

    /**
     * The `ConsumerTail` body (§13.3 item 6, G-8, SC-7): local work at the end of a background
     * run, after the lanes, the redeem hold and the **transport close**.
     *
     * Because it runs after the close, relay session close times and issuer-call times cannot
     * depend on how much there was to consume (NI-DM1, mutant PM-25). It has no transport access,
     * and it returns by the deadline — the job's end never waits past it.
     */
    fun consumerTail(kind: SessionKind, deadlineMonotonicMillis: Long) {
        // Both kinds do the same work: a background session's tail runs after its lanes, its
        // redeem hold and the transport close, and a quiet run's after the issuer call returned
        // and its transport closed — and in both the local work owed is the same pass. The
        // distinction is the sync runtime's, which is what decides **when** to call this.
        require(kind == SessionKind.BACKGROUND || kind == SessionKind.QUIET) {
            "the tail runs in background sessions and quiet runs only (§13.3 item 6)"
        }
        val future = post {
            // A relay session start is one of §21.9 rule 1's three triggers, and so is its end —
            // but the end is not a **start**: a fetch attempt opened here would wait for a session
            // that may begin after its window closed (phase review MD-2).
            runPass(
                timeTriggered = true,
                deadlineMonotonicMillis = deadlineMonotonicMillis,
                sessionStart = false,
            )
        } ?: return
        val remaining = deadlineMonotonicMillis - clock.monotonicMillis()
        if (remaining <= 0) return
        try {
            future.get(remaining, TimeUnit.MILLISECONDS)
        } catch (e: ExecutionException) {
            // A pass that threw has ended, and that is all it did (§22.15's closing note: the
            // actor swallows what a pass throws, because the work is owed again at the next
            // trigger). The tail runs on a sync callback thread whose uncaught exception ends the
            // process (Phase 7 design §11.2 #11), so reading the future here must not turn the one
            // pass that failed into a crash the listener-driven passes never cause (slice S12).
            Unit
        } catch (e: java.util.concurrent.TimeoutException) {
            // The pass keeps going on the actor thread; the job's end does not wait past the
            // deadline, which is the contract `ConsumerTail` states.
            Unit
        }
    }

    private fun wake(timeTriggered: Boolean, sessionStart: Boolean = false) {
        if (!pending.compareAndSet(false, true) && !timeTriggered) return
        post {
            pending.set(false)
            runPass(timeTriggered, deadlineMonotonicMillis = null, sessionStart = sessionStart)
        }
    }

    /**
     * One pass, in the order §13.7 fixes.
     *
     * The order is not arbitrary: OUTCOME releases the ops whose results are already in, so the
     * bundle claims and `RECV` see a settled outbox; the bundle claims feed `EST-READY`, which
     * flushes the pending items a send left behind; and the peek order runs last, because it is
     * the only step that reads a whole batch and its ordering must see every session those steps
     * created.
     */
    @Suppress("ReturnCount")
    fun runPass(
        timeTriggered: Boolean,
        deadlineMonotonicMillis: Long?,
        /**
         * Whether the trigger was a relay session start ([onTimeTrigger]). A caller that drives
         * passes itself — the worlds of the test harness that do not run the production triggers —
         * gets the old reading by default: every time-triggered pass it runs stands for a session
         * start. The privacy and entitlement worlds go through [onTimeTrigger], [onChange] and
         * [consumerTail] instead (design §22.36).
         */
        sessionStart: Boolean = timeTriggered,
    ) {
        var failure: Throwable? = null
        try {
            pass(timeTriggered, deadlineMonotonicMillis, sessionStart)
        } catch (e: Throwable) {
            failure = e
            throw e
        } finally {
            // §7.2's "After commit" column and §10.7 triggers 1 and 5, in a `finally` because they
            // are owed by a pass that ended early as much as by one that ran to the end: a pass
            // that returned at `CRYPTO_UNAVAILABLE` or at the tail deadline has still swept, and
            // an alarm that was not rescheduled is a device that never sweeps again until it is
            // opened by hand.
            //
            // **It must not replace the failure that brought us here** (S9 review).
            // `afterCommit` opens two transactions of its own, and the states that make a pass
            // throw — a database closing under a wipe, a full disk, a lock — are exactly the
            // states that make those two throw as well. A bare `finally` would then report the
            // second exception and lose the first, which is the one that says what happened. The
            // schedule's own failure is attached as suppressed instead, and it is raised on its
            // own only when the pass itself succeeded.
            try {
                schedule.afterCommit()
            } catch (e: Throwable) {
                if (failure == null) throw e
                failure.addSuppressed(e)
            }
        }
    }

    @Suppress("ReturnCount")
    private fun pass(timeTriggered: Boolean, deadlineMonotonicMillis: Long?, sessionStart: Boolean) {
        // Recorded before anything can return early, so a time-triggered pass that cannot run
        // `EST-READY` (no DM context) still spends the wake [nextReadySeconds] kept for it.
        if (timeTriggered) lastTimeTriggeredSecond = clock.nowEpochSeconds()
        // SWEEP first (§13.7's pass order). It runs before the activation check and before every
        // other step, because it is the one step that needs nothing to be true: a device whose DM
        // context is locked, whose identity is half-activated or whose native library is missing
        // still owes the user the deletion of what has expired. `Sweeper` reads `dm_self` for the
        // expiry clock and falls back to the wall clock when there is none (R-T7).
        sweeper.sweep()
        if (contexts.get() == null) {
            // §21.12 point 2: "at every actor start and database open, an activated identity with
            // no `dm_self` row runs ACTIVATE". This is that call, and until the S8 review it did
            // not exist anywhere in the tree while two KDocs named it as their safety net.
            //
            // It matters most for the one path that has no second tap: `Messaging.onRestored()`
            // runs from the K20 hook exactly once, and `activate(restored = true)` answers
            // `NO_RELAYS` without writing anything when the ES schedule facts have not synced yet
            // — which is the normal state of a fresh install a second after a restore. Without a
            // resume the restored identity is mute for good: no `dm_self`, no registration, no
            // bundle, and no `accept_after_minute`.
            //
            // **Time-triggered only** (§21.9 rule 1, T28). ACTIVATE publishes a bundle, so a pass
            // driven by an arriving blob must not be able to cause one. The three triggers §21.12
            // point 2 names — the actor timer, a database open and a relay session start — are
            // all time-triggered, so nothing is lost by the restriction.
            if (!timeTriggered) return
            resumeActivation()
            if (contexts.get() == null) return
        }
        outcomeStep.run()
        // Phase 11 §13.5's `MEDIA-OUTCOME`/`MEDIA-FEED`: after F9's OUTCOME released the ops.
        media?.runOutcomesAndFeed()
        // Phase 11 §13.5's recipient half (slice S6): `MEDIA-INGEST` claims what Phase 7 fetched
        // into M_0, `MEDIA-BIND` meets manifests and descriptors, `MEDIA-VERIFY` validates
        // complete objects — every pass, after the outbox steps they read nothing of.
        media?.runIngestBindVerify()
        claimBundles()
        // §22.8.1 rule 3: HELD runs **before** the peek and the RECV claims. Rule 2 makes either
        // order correct — a session a RECV pass created first is matched by `session_id` and
        // decrypts on its slot — but this order is the one the rule names, and it keeps a released
        // hold from being ordered against blobs that arrived after the user's decision.
        //
        // It is not time-triggered: it is local work on ciphertext this device already holds, and
        // the decision that released it was the user's. What §21.9 rule 1 confines to a
        // time-triggered pass is work whose **timing** would otherwise follow an arrival, and a
        // replay produces no relay-visible event at all (T28, §21.7 point 7).
        replayReleasedHolds()
        if (timeTriggered) {
            ownerMaintenance()
            contactKeeper.run()
            // The pair-key ratchet is no longer here: §21.3 point 5 puts it inside SWEEP, in the
            // same transaction as the erasure it must precede (mutant MC-21), and SWEEP is the
            // first step of every pass above.
            runEstablishment(sessionStart)
            // §21.9 rule 1 names "due scheduled controls" among the time-triggered steps, and this
            // is the whole of PM-30 for them: a card holder must not be able to deposit a probe
            // during this device's session and watch a reconnect or revocation notice follow.
            scheduledSteps.runDue()
            // §6.4's deadline: time-triggered, like the steps above.
            media?.runDeadline()
            // §7.5's `MEDIA-GC`: declared losses, pooled retention, unnamed sealed garbage.
            media?.runGc()
        }
        consumeInbox(deadlineMonotonicMillis)
        // D16: the channel engine's pass, with this pass's trigger (its time-triggered steps run on a time-triggered pass
        // only, as the DM's do), after the DM steps: it needs the same content key, which the check above proved open.
        channels?.runPass(timeTriggered, deadlineMonotonicMillis, sessionStart)
    }

    /**
     * §22.8.1: the held rows of every contact whose key change has been decided.
     *
     * The facade replays them inside the decision that released them; this is the **recovery**
     * half, for a crash between the KEYDEC commit and the replay — the decision is taken, the rows
     * are still there, and nothing else would ever look at them again. The predicate is exactly
     * that state: live held rows on a contact that is no longer `changed`.
     *
     * `hold_until_minute` is compared against **`now_e`** and not the wall clock (R-T7, §10.3): a
     * row past its hold belongs to SWEEP, and a clock stepped backwards must not hand it back to
     * the replay after SWEEP has already decided it is gone.
     */
    private fun replayReleasedHolds() {
        val contactIds = database.transaction { tx ->
            held.contactsWithReleasedHolds(tx.sql, expiry.nowMinute(tx.sql))
        }
        for (contactId in contactIds) heldReplay.replay(contactId)
    }

    // ---------------------------------------------------------------- inbound

    /**
     * §7.7 point 1: peek, order, then claim and consume **one blob at a time**.
     *
     * The claim is `Inbox.claimOne`, which commits the offer counter before the hand-off, so a
     * native crash inside `RECV` is counted against the poison guard even though the transaction
     * rolled back (§7.8).
     */
    private fun consumeInbox(deadlineMonotonicMillis: Long?) {
        if (!storageLatchOpen()) return
        for (peeked in peekOrder.order()) {
            if (outOfTime(deadlineMonotonicMillis)) return
            val blob = sync.inbox.claimOne(Consumer.DM, peeked.namespace, peeked.hash) ?: continue
            val result = try {
                receiveStep.receive(blob)
            } catch (e: StorageFullException) {
                // §21.12 point 1 and §7.8's "disk full" row. The claim committed its offer counter
                // and the RECV transaction rolled back: without this the blob is poison at its
                // fourth offer, and the message is lost although nothing died (phase review ENG-2).
                deferAfterStorageFull(blob.namespace, blob.hash)
                return
            }
            if (result == ReceiveStep.Result.CRYPTO_UNAVAILABLE) return
        }
    }

    /**
     * §21.12 point 1: "a RECV or BUNDLE transaction that rolls back with `StorageFullException` is
     * followed by `Inbox.defer(ns, hash, 60 s)` in its own transaction, which resets the counter
     * … and if that also fails an in-memory storage-full latch stops DM claims until a write
     * transaction succeeds". A re-offer time is local: nothing reaches a relay (T28).
     */
    private fun deferAfterStorageFull(namespace: NamespaceId, hash: BlobHash) {
        try {
            database.transaction { tx ->
                sync.inbox.defer(tx, namespace, hash, STORAGE_FULL_DEFER_SECONDS)
            }
        } catch (e: StorageFullException) {
            owedDefers += namespace to hash
        }
    }

    /**
     * Whether blobs may be claimed: true once every deferral [owedDefers] holds has been written.
     * Each is retried here, before any claim, so the latch stays shut exactly as long as a write
     * fails.
     */
    private fun storageLatchOpen(): Boolean {
        while (owedDefers.isNotEmpty()) {
            val (namespace, hash) = owedDefers.first()
            try {
                database.transaction { tx ->
                    sync.inbox.defer(tx, namespace, hash, STORAGE_FULL_DEFER_SECONDS)
                }
            } catch (e: StorageFullException) {
                return false
            }
            owedDefers.removeAt(0)
        }
        return true
    }

    /**
     * `BUNDLE` (§21.7 point 3): the fetched bundles of the contacts currently establishing.
     *
     * A blob whose namespace belongs to no `fetching` contact is consumed and dropped: it is a
     * bundle of a namespace this device stopped listening to, and leaving it would keep the
     * namespace un-removable at `EST-END`.
     */
    private fun claimBundles() {
        if (!storageLatchOpen()) return
        val owners = bundleOwners()
        val claimed = sync.inbox.claim(Consumer.PREKEYS, BUNDLE_CLAIM)
        for ((index, blob) in claimed.withIndex()) {
            try {
                if (owners.isEmpty()) {
                    // Nothing is establishing, so nothing may arrive; a stale row is consumed all
                    // the same, because `Namespaces.remove` answers false while one is left
                    // (§21.7 point 5).
                    database.transaction { tx -> sync.inbox.markConsumed(tx, blob.namespace, blob.hash) }
                    continue
                }
                val contactId = owners[blob.namespace.toByteArray().toList()]
                database.transaction { tx ->
                    if (!sync.inbox.markConsumed(tx, blob.namespace, blob.hash)) return@transaction
                    if (contactId == null) return@transaction
                    if (bundleStep.bundle(tx, contactId, blob.ciphertext)) {
                        candidateSince.putIfAbsent(contactId.toList(), clock.nowEpochSeconds())
                    }
                }
            } catch (e: StorageFullException) {
                // §21.12 point 1, for BUNDLE (phase review ENG-2): this blob and every later one of
                // the claim had its offer counted, and none of them will fit either.
                for (rest in claimed.subList(index, claimed.size)) {
                    deferAfterStorageFull(rest.namespace, rest.hash)
                }
                return
            }
        }
    }

    /** `P_c -> contact`, for the contacts whose attempt window is open. */
    private fun bundleOwners(): Map<List<Byte>, ByteArray> {
        val out = HashMap<List<Byte>, ByteArray>()
        val fetching = database.transaction { tx -> contacts.fetching(tx.sql) }
        for (contact in fetching) {
            val card = material.card(contact) ?: continue
            val namespaces = material.namespaces(card) ?: continue
            out[namespaces.bundle.toList()] = contact.contactId
        }
        return out
    }

    // ------------------------------------------------------------ time-triggered

    /**
     * The three time-triggered establishment steps (§21.9 rule 1).
     *
     * `EST-READY` runs two minutes after the first candidate — a delay that lives in memory, so
     * after a restart an existing candidate is processed at the next time-triggered pass, which
     * is what §21.7 point 4 says. `EST-START` and `EST-END` are decided by
     * [EstablishmentSteps.dueStep] from the stored decision minute and `P_c`'s listening flag.
     */
    private fun runEstablishment(sessionStart: Boolean) {
        val now = clock.nowEpochSeconds()
        val fetching = database.transaction { tx -> contacts.fetching(tx.sql) }
        for (contact in fetching) {
            val ready = database.transaction { tx ->
                contacts.bundleCandidate(tx.sql, contact.contactId) != null
            }
            if (ready) {
                val since = candidateSince[contact.contactId.toList()]
                if (since == null || now - since >= EstablishmentSteps.READY_DELAY_SECONDS) {
                    if (establishment.estReady(contact.contactId) == EstablishmentSteps.Result.DONE) {
                        candidateSince.remove(contact.contactId.toList())
                        sendStep.flushPending(contact.contactId)
                        continue
                    }
                }
            }
            val due = database.transaction { tx -> establishment.dueStep(tx, contact, now) }
            when (due) {
                EstablishmentSteps.Due.END -> {
                    // The window ended. A usable session may have arrived from the contact's own
                    // side meanwhile (R-SS1), which `EST-READY` turns into a `ready` contact
                    // without a candidate (§21.7 point 4).
                    if (establishment.estReady(contact.contactId) == EstablishmentSteps.Result.DONE) {
                        sendStep.flushPending(contact.contactId)
                    } else {
                        establishment.estEnd(contact.contactId)
                    }
                }
                // §21.7 point 5: the next attempt opens at a relay session start only (MD-2).
                EstablishmentSteps.Due.START -> if (sessionStart) establishment.estStart(contact.contactId)
                EstablishmentSteps.Due.NONE -> Unit
            }
        }
        flushStranded(now)
        failExpiredPending(now)
    }

    /**
     * §21.7 point 4's "retried at the next time-triggered pass", for the pending items of contacts
     * that are **not** fetching.
     *
     * `EST-READY` commits `establishment = ready` and the flush that follows it is a separate
     * transaction per item, and `flushOne` answers false on a full disk, on a week whose slot table
     * cannot give a quorum, and on a session that turned out to be unusable. Every one of those
     * leaves a live `dm_pending_send` row on a contact the establishment loop above no longer
     * visits — as does a process death between the `EST-READY` commit and the flush. The user's
     * send reported `QUEUED`; without this step the item would sit until `fail_after_hour` and
     * fail, days after later messages to the same contact were delivered.
     *
     * **It is not a time-triggered re-establishment** (§8.7, T28, T31). The cause is the user's own
     * send — the pending item exists because of it, and §21.9 rule 1 already makes `EST-START` a
     * step a time-triggered pass may run to *continue* one. What is forbidden is a re-establishment
     * caused by something that **arrived**, and nothing here reads the inbox: the set of contacts
     * it visits is a function of local rows that are identical in the two worlds `NoReflexTest`
     * compares. `fetch_attempts` bounds it at three windows, after which `EST-END` fails the items.
     *
     * **The continuation is started as the user's retry** (slice S10c; §21.7 point 5, §13.5's
     * `unreachable → fetching`). Every path that leaves a pending item — a send, a retry, a reset
     * and a scheduled control — commits it and then asks `EST-START` for an establishment **with**
     * `userRetry`, in a transaction of its own; a process death between the two is how an item
     * gets here. For a contact whose three windows were already spent that flag is the whole
     * difference: without it `EST-START` answered `UNCHANGED` against the spent budget, the
     * contact stayed `unreachable`, and the item waited for R-T5 to fail it at `fail_after_hour`
     * — up to seven days — unless the user happened to write to the contact again. The crash
     * enumeration of SCN-C found it (34 consecutive crash points of one send, §22.23). It lifts no
     * bound: `EST-END` fails every pending item in the transaction that makes a contact
     * `unreachable`, so a pending item on one can only have been queued **after** the budget ran
     * out, by one of the four actions above, each of which would have started a fresh count
     * itself; and this step visits no `fetching` contact, so it never restarts an establishment
     * that is still in progress. Each start it makes is followed by at most three windows, after
     * which `EST-END` fails the item it was for.
     */
    private fun flushStranded(now: Long) {
        val stranded = database.transaction { tx ->
            contacts.contacts(tx.sql)
                .filter { it.establishment != ContactStore.Establishment.FETCHING }
                .filter {
                    it.trust == ContactStore.Trust.UNVERIFIED ||
                        it.trust == ContactStore.Trust.VERIFIED
                }
                .filter { messages.pendingSends(tx.sql, it.contactId).isNotEmpty() }
                .map { it.contactId }
        }
        for (contactId in stranded) {
            sendStep.flushPending(contactId)
            // A fetch only when the contact has **no usable session to seal onto**, never merely
            // because the flush did not succeed. A full disk or a week whose slot table gives no
            // quorum leaves the item pending on a perfectly good session, and re-establishing for
            // that would spend a `P_c` window — relay-visible, and bounded by L7-D6 — on a problem
            // no bundle can solve. When there is no usable session, the send that queued the item
            // already asked for an establishment, and this is that establishment continuing.
            val needsSession = database.transaction { tx ->
                if (messages.pendingSends(tx.sql, contactId).isEmpty()) {
                    false
                } else {
                    val current = sessions.current(tx.sql, contactId)
                    current == null || SessionSlots.isStale(current, now)
                }
            }
            if (needsSession) establishment.estStart(contactId, userRetry = true)
        }
    }

    /**
     * R-T5 (§10.1): a message waiting for a bundle fails at its deadline. It never reaches the
     * session layer after its store deadline, because no copy could be stored then anyway.
     */
    private fun failExpiredPending(now: Long) {
        database.transaction { tx ->
            for (contact in contacts.contacts(tx.sql)) {
                for (pending in messages.pendingSends(tx.sql, contact.contactId)) {
                    if (pending.failAfterHour > now) continue
                    messages.deletePendingSend(tx, pending.itemId)
                    messages.setItemState(
                        tx,
                        pending.itemId,
                        MessageStore.ITEM_PENDING,
                        EstablishmentSteps.STATE_FAILED,
                    )
                    messages.setMessageState(
                        tx,
                        pending.itemId,
                        MessageStore.STATE_QUEUED,
                        EstablishmentSteps.STATE_FAILED,
                    )
                }
            }
        }
    }

    private fun outOfTime(deadlineMonotonicMillis: Long?): Boolean {
        val deadline = deadlineMonotonicMillis ?: return false
        // §21.12 point 1: the tail claims one blob at a time and stops claiming when fewer than
        // two seconds of its deadline remain, so a claimed blob is never abandoned unconsumed.
        return clock.monotonicMillis() + TAIL_RESERVE_MILLIS >= deadline
    }

    /** [retire] with nothing more to do on the thread. */
    override fun close() {
        retire { }
    }

    companion object {
        /** §13.7: the actor's thread name. */
        const val THREAD_NAME: String = "ghost-dm"

        /** The `INTERNAL` answer of a facade call that reached a stopped actor. */
        private const val STOPPED: String = "the DM actor is stopped"

        /** How many bundle blobs one pass claims. */
        const val BUNDLE_CLAIM: Int = 16

        /** §21.12 point 1: the tail stops claiming with fewer than two seconds left. */
        const val TAIL_RESERVE_MILLIS: Long = 2_000

        /** §21.12 point 1: a blob whose `RECV` or `BUNDLE` hit a full disk is re-offered after 60 s. */
        const val STORAGE_FULL_DEFER_SECONDS: Int = 60
    }
}
