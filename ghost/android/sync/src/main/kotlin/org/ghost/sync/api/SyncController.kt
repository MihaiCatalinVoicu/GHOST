package org.ghost.sync.api

/** Process-level control of sync; the Android implementation is wired by the app (design §5.4). */
interface SyncController {
    fun onAppForeground()

    fun onAppBackground()

    /** STANDARD mode only: wakes the work lane for due stores; never creates read events. */
    fun requestExpedite()

    fun setPrivacyMode(mode: PrivacyMode)

    /** Counts and enums only. */
    fun status(): SyncStatus

    /** The local data was wiped: cancel the periodic job and stop every session (design §11.2 #17). */
    fun onWipe()

    /**
     * Installs the one session participant (Phase 8 design §11.6: the entitlement engine), or
     * removes it with null. Set it once, at wiring: quiet runs happen only while a participant is
     * installed, so it must not follow entitlement state. It takes effect from the next session.
     */
    fun setParticipant(p: SessionParticipant?)

    /**
     * Runs [block] exactly once, on its own thread, with a USER_ISSUER_CALL session (onboarding's
     * `RedeemInvite` and the optional STANDARD-mode buttons, declared L3 samples). For user actions
     * only, while the app is visible: READY on the one transport, the foreground session's if it
     * runs, otherwise made READY for the call. The session allows one issuer call. While the app is
     * hidden, and when sync cannot run (wiped, stopped), the session is already closed and the call
     * fails `closed`, so no issuer call happens during a background session or a quiet run (P-7,
     * T23). A call that made the transport READY for itself is closed when the app is hidden or when
     * the foreground session starts (the payment hold ended): nothing relay-visible waits for it.
     */
    fun runUserIssuerCall(block: (ParticipantSession) -> Unit)

    /**
     * The payment screen is shown (Phase 8 design §19.11): any running relay session is closed at
     * once, and none starts while it is shown.
     */
    fun onPaymentScreenShown()

    /**
     * The payment screen was hidden (hiding the app hides it too): relay sessions stay held off
     * for U[20 min, 60 min] more.
     */
    fun onPaymentScreenHidden()

    /**
     * Gives a new process the payment-screen hold of an earlier one (Phase 8 design §19.11, E15).
     * The hold lives in memory and dies with its process, so the entitlement engine persists the
     * moment the payment screen was last visible ([lastShownEpochSeconds], device wall clock,
     * rounded up to its minute) and calls this at wiring, before a job or the foreground can start a
     * relay session (commands run in the order they are posted). Relay sessions are then held as if
     * the screen had been hidden at that moment, for a fresh U[20 min, 60 min], never more than
     * 60 min from now; a running relay session is closed at once; a moment older than the hold
     * holds nothing.
     */
    fun restorePaymentHold(lastShownEpochSeconds: Long)
}
