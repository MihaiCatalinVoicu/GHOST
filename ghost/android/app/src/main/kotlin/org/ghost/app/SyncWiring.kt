package org.ghost.app

import org.ghost.sync.api.SessionParticipant
import org.ghost.sync.api.SyncController
import org.ghost.sync.api.UpdateParticipant

/**
 * The app's sync decisions (design §5.4, §5.6, §11.2 #17, #18; Phase 8 design §11.6, §19.11;
 * Phase 13 design §3.5 D33, X-U14), free of Android types:
 *  - at every process start the entitlement engine is installed as the sync runtime's one session
 *    participant, before anything can start a session (quiet runs happen only while one is installed,
 *    so it never follows entitlement state);
 *  - when the database key envelope exists, the payment-screen hold of the previous process is
 *    restored from the moment the engine remembered ([paymentShownAt]), which [restorePaymentHold]
 *    reads on the sync runtime thread (reading it opens the database: never on the main thread),
 *    then the periodic job is ensured; ensuring reschedules only when the pending job is missing or
 *    differs, so the period timer is not reset;
 *  - right after the key is first created, the job is ensured and the database announced;
 *  - **sessions follow INTERACTIVE (D33, X-U14)**: ON_START runs only the local step ([visible] —
 *    the DM stack's build if a database is open); [onInteractive] starts the foreground session
 *    (`SyncController.onAppForeground`) and the entitlement engine's foreground hook (the pending
 *    trial's retry), only after the unlock and the resume — nothing syncs while only the lock
 *    screen shows. ON_STOP (and a lock while visible) ends the session ([onHidden]: the controller's
 *    background hook and the engine's hidden hook, which keeps an open payment screen's moment,
 *    §19.11); it never schedules anything: no request and no wake-up is caused by user activity.
 */
internal class SyncWiring(
    private val keyExists: () -> Boolean,
    private val controller: SyncController,
    private val ensurePeriodic: () -> Unit,
    private val databaseAvailable: () -> Unit,
    private val participant: SessionParticipant,
    /** The update engine, installed as the runtime's one updater (Phase 14 design §9.4 item 2). */
    private val updater: UpdateParticipant,
    private val paymentShownAt: () -> Long?,
    private val restorePaymentHold: (() -> Long?) -> Unit,
    private val visible: () -> Unit,
    private val foregroundHook: () -> Unit,
    private val hidden: () -> Unit,
) {
    fun onProcessStart() {
        controller.setParticipant(participant)
        controller.setUpdater(updater)
        if (!keyExists()) return
        // Read by the runtime thread (it opens the database), before any job or foreground command.
        restorePaymentHold(paymentShownAt)
        ensurePeriodic()
    }

    fun onKeyCreated() {
        ensurePeriodic()
        databaseAvailable()
    }

    /** ON_START: the local step only (D33) — never the foreground session. */
    fun onWindowVisible() {
        visible()
    }

    /** The app became INTERACTIVE (unlocked and resumed): the foreground session starts. */
    fun onInteractive() {
        controller.onAppForeground()
        foregroundHook()
    }

    /** ON_STOP or a lock while visible: the foreground session ends. */
    fun onHidden() {
        controller.onAppBackground()
        hidden()
    }

    override fun toString(): String = "SyncWiring"
}
