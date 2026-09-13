package org.ghost.app

import org.ghost.sync.api.SessionParticipant
import org.ghost.sync.api.SyncController

/**
 * The app's sync decisions (design §5.4, §5.6, §11.2 #17, #18; Phase 8 design §11.6, §19.11), free of
 * Android types:
 *  - at every process start the entitlement engine is installed as the sync runtime's one session
 *    participant, before anything can start a session (quiet runs happen only while one is installed,
 *    so it never follows entitlement state);
 *  - when the database key envelope exists, the payment-screen hold of the previous process is
 *    restored from the moment the engine remembered ([paymentShownAt]), then the periodic job is
 *    ensured; ensuring reschedules only when the pending job is missing or differs, so the period
 *    timer is not reset;
 *  - right after the key is first created, the job is ensured and the database announced;
 *  - visibility starts and stops the foreground session and lets a pending onboarding trial retry
 *    ([visible]); hiding the app, which hides an open payment screen, lets the engine keep that
 *    moment for the next process ([hidden]); it never schedules anything: no request and no wake-up
 *    is caused by user activity.
 */
internal class SyncWiring(
    private val keyExists: () -> Boolean,
    private val controller: SyncController,
    private val ensurePeriodic: () -> Unit,
    private val databaseAvailable: () -> Unit,
    private val participant: SessionParticipant,
    private val paymentShownAt: () -> Long?,
    private val visible: () -> Unit,
    private val hidden: () -> Unit,
) {
    fun onProcessStart() {
        controller.setParticipant(participant)
        if (!keyExists()) return
        paymentShownAt()?.let(controller::restorePaymentHold)
        ensurePeriodic()
    }

    fun onKeyCreated() {
        ensurePeriodic()
        databaseAvailable()
    }

    fun onVisible() {
        controller.onAppForeground()
        visible()
    }

    fun onHidden() {
        controller.onAppBackground()
        hidden()
    }

    override fun toString(): String = "SyncWiring"
}
