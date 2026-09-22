package org.ghost.messaging.engine

import org.ghost.messaging.api.NotificationPort
import org.ghost.messaging.port.ExpiryWake

/**
 * The "After commit: notification count" of Phase 9 design §7.2 (the `RECV`, `HELD`, `DISPLAY` and
 * `SWEEP` rows), §10.6 and §10.7 (Q19).
 *
 * > `NotificationPort.onUnreadChanged(count)`; cancelled at 0.
 *
 * **A count and nothing else.** The port's signature is the guarantee (see
 * [org.ghost.messaging.api.NotificationPort]); this class is what decides *when* it is called and
 * makes sure the number it carries is the one the expiry filter of §10.7 point 4 produces — a
 * message whose timer passed is not counted even before SWEEP has deleted it, so the badge never
 * tells the user about something the conversation no longer shows.
 *
 * **Only on a change.** A pass that consumed nothing and swept nothing publishes nothing, so the
 * port is not a heartbeat: an implementation that reposts a notification on every call would
 * otherwise re-raise it on every actor wake, and Android's notification history keeps what was
 * posted for 24 hours (§10.7, RE §8.4). The last published value lives in memory and starts at
 * [NEVER], so the first publish after a process start always goes through — including a `0`, which
 * is the cancel §10.6 asks for when the last unread message expired while the process was dead.
 *
 * **Actor-thread only.** Every caller is inside a DM actor pass or a facade call that posts to it
 * (§13.7), which is what makes [last] a plain field rather than an atomic.
 */
internal class UnreadNotices(private val liveUnreadCount: () -> Int) {

    @Volatile
    private var port: NotificationPort? = null

    private var last: Int = NEVER

    /** Wires or clears the port (§13.2 `setNotificationPort`). Clearing forgets the last count. */
    fun setPort(port: NotificationPort?) {
        this.port = port
        if (port == null) last = NEVER
    }

    /**
     * Publishes the live unread count if it changed since the last publish.
     *
     * Reading the count costs one transaction, so it is read **only** when a port is wired: a
     * device with no UI attached does no work for a notification nobody receives.
     */
    fun publish() {
        val sink = port ?: return
        val count = liveUnreadCount()
        if (count == last) return
        last = count
        sink.onUnreadChanged(count)
    }

    private companion object {
        /** No count has been published by this process yet, so any first value is a change. */
        const val NEVER: Int = -1
    }
}

/**
 * What every DM transaction owes **after** it commits (Phase 9 design §7.2's last column, §10.7
 * triggers 1 and 5): the unread count, and the timer and the alarm moved to the next due minute.
 *
 * It exists as one object because the two callers are two — [DmActor] after every pass, and
 * [MessagingEngine] after a `markDisplayed`, which is the one facade call that *moves* a deletion
 * time (§7.2's DISPLAY row: "timer and alarm rescheduled"). A facade call that did not reschedule
 * would leave a display-started countdown with no wake behind it until something else happened to
 * wake the actor.
 *
 * **Actor-thread only**, like [UnreadNotices]: every caller is inside a pass or inside the
 * facade's `onActor` block, so this never posts to itself and never blocks.
 */
internal class ExpirySchedule(
    private val sweeper: Sweeper,
    private val wakes: ExpiryWake,
    private val notices: UnreadNotices,
) {
    /**
     * The count and the two wakes. Null from [Sweeper.nextWake] cancels them (§10.7).
     *
     * The wakes are given a **delay** and not a minute, because the subtraction has to happen
     * against `now_e` (R-T7) and this side is the one that knows it — see
     * [org.ghost.messaging.port.ExpiryWake] for what a wall-clock subtraction cost.
     */
    fun afterCommit() {
        notices.publish()
        wakes.wakeIn(sweeper.nextWake()?.delaySeconds)
    }

    /**
     * §13.2 `setNotificationPort`. A port wired after the process started has never been told
     * anything, so it is given the current count at once rather than left blank until the next
     * pass; a null port is cleared and the last published count forgotten.
     */
    fun setNotificationPort(port: NotificationPort?) {
        notices.setPort(port)
        notices.publish()
    }
}
