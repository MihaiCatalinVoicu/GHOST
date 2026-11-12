package org.ghost.messaging.engine

import org.ghost.messaging.port.DmClock
import org.ghost.messaging.port.ExpiryWake
import org.ghost.sync.api.ConsumerTail
import org.ghost.sync.api.SyncChange
import org.ghost.sync.api.SyncListener

/**
 * **The DM actor's triggers, bound in one place** (Phase 9 design §13.7, §21.9 rule 1, §10.7
 * triggers 1 and 5; the review of §22.36, item 12): what each production entry point hands the actor
 * — the listener's hints, the consumer tail, a relay session start, the alarm and a database open,
 * the in-process timer's wake — and the schedule that arms the timer and the alarm, with the next
 * `EST-READY` among the timer's terms.
 *
 * **Why one class.** `MessagingRuntime` bound each of these in a lambda of its own, and the test
 * harness's `DmDevice` bound copies of them beside it: a world that "ran the production triggers" ran
 * the harness's copies, so a runtime whose timer wake counted as a relay session start, whose consumer
 * tail did, whose listener dropped a hint or whose schedule lost the `EST-READY` term passed every
 * world (the review of §22.36, finding 2). `MessagingRuntime` and the harness's `DmDevice` now both
 * build their triggers here: a world runs the runtime's bindings, and a change to one is a change to
 * the other.
 *
 * **It decides the kind of the two triggers it owns and no other.** Which call is a relay session
 * start is `MessagingWiring`'s decision — `onRelaySessionStart` passes `sessionStart = true`, the
 * alarm and a database open do not (`MessagingWiringTest` pins it) — and [onTimeTrigger] carries the
 * flag it is given. The two triggers bound here, the timer's wake and the consumer tail, are time
 * triggers that start **no** relay session (§21.7 point 5, phase review MD-2): a later fetch attempt
 * opened by either could open and close with no relay session to list `P_c` in its window.
 */
internal class DmTriggers(
    /**
     * The in-process timer's scheduler (`ExpiryTimer`'s seam): null for the production daemon
     * thread; a world of the test harness passes its virtual-time scheduler.
     */
    private val timerScheduler: ((Long, () -> Unit) -> ExpiryTimer.Cancellable)? = null,
) : AutoCloseable {

    /** Set once the actor exists ([bind]); a trigger that comes before it does nothing. */
    @Volatile
    private var actor: DmActor? = null

    private val timerHolder = lazy {
        if (timerScheduler == null) ExpiryTimer(wake = ::timerFired) else ExpiryTimer(::timerFired, timerScheduler)
    }

    /**
     * §10.7 trigger 1, the actor's in-process timer: its wake is a time trigger that starts no relay
     * session. Built on first use, so a harness device that only records its timer ([schedule]'s
     * `timer`) starts no scheduler thread.
     */
    val timer: ExpiryTimer by timerHolder

    private fun timerFired() {
        actor?.onTimeTrigger()
    }

    /** Binds the triggers to [actor], once. */
    fun bind(actor: DmActor) {
        check(this.actor == null) { "the DM triggers are bound already" }
        this.actor = actor
    }

    /**
     * The inbox listener of §13.7 (`Inbox.setListener`): every hint posts a coalesced pass and
     * returns, touching nothing — the committing thread can be a lane thread.
     */
    val listener: SyncListener = SyncListener { changes ->
        val a = actor ?: return@SyncListener
        for (change in changes) a.onChange(change)
    }

    /**
     * The `ConsumerTail` body (§13.3 item 6, `SyncController.setConsumerTail`): a time-triggered
     * pass that returns by the deadline, and no relay session start (`DmActor.consumerTail`).
     */
    val consumerTail: ConsumerTail = ConsumerTail { kind, deadline -> actor?.consumerTail(kind, deadline) }

    /**
     * A relay session start ([sessionStart] true, `MessagingWiring.onRelaySessionStart`), the alarm
     * or a database open (false): a time trigger (§21.9 rule 1). Posts.
     */
    fun onTimeTrigger(sessionStart: Boolean = false, onDone: () -> Unit = {}) {
        actor?.onTimeTrigger(sessionStart, onDone) ?: onDone()
    }

    /** MD-6/MD-4: the runtime's brackets around a relay session or quiet run (MessagingWiring). */
    fun sessionBegin() {
        actor?.sessionBegin()
    }

    fun sessionEnd() {
        actor?.sessionEnd()
    }

    /** One hint, as [listener] would deliver it. Posts. */
    fun onChange(change: SyncChange) {
        actor?.onChange(change)
    }

    /**
     * Seconds until the next `EST-READY` a bundle candidate waits for (phase review MD-3,
     * `DmActor.nextReadySeconds`): a term of the timer's minimum. Actor thread only, like the schedule
     * that reads it.
     */
    fun readyDelay(): Long? = actor?.nextReadySeconds()

    /**
     * The two wakes of §10.7 as the runtime wires them (§21.9 rule 1): the row deadlines go to the one
     * inexact [alarm] and to the actor [timer]; the owner's `t_pub` and week boundary (§22.14 item 10)
     * and the next `EST-READY` ([readyDelay]) go to the timer alone. The runtime passes this class's
     * [DmTriggers.timer]; a harness device passes a recording beside it, or in place of it. [owner] null
     * leaves the owner's terms out: the S10 crash harness drives its passes itself, and every database
     * read is an event of its enumeration.
     */
    fun schedule(
        sweeper: Sweeper,
        alarm: ExpiryWake,
        notices: UnreadNotices,
        timer: ExpiryWake,
        owner: OwnerSteps?,
        clock: DmClock,
    ): ExpirySchedule = ExpirySchedule(
        sweeper = sweeper,
        wakes = alarm,
        notices = notices,
        timer = timer,
        ownerDelay = { owner?.nextOwnerWakeSeconds()?.let { maxOf(0L, it - clock.nowEpochSeconds()) } },
        establishmentDelay = ::readyDelay,
    )

    /** Stops the timer's scheduler, if one was started. */
    override fun close() {
        if (timerHolder.isInitialized()) timer.close()
    }

    override fun toString(): String = "DmTriggers"
}
