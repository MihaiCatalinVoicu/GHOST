package org.ghost.entitlement.port

import org.ghost.sync.api.SessionKind

/**
 * The engine's view of one participant session (Phase 8 design §11.6): a relay session (foreground or
 * background) grants [redeem] only, a quiet run or a user issuer call grants [issuer] only. Production:
 * `android.EntitlementParticipant` over the `ParticipantSession` of the sync runtime.
 */
interface SessionPort {
    val kind: SessionKind

    /** The session's lease closed: every call fails `closed`. */
    val closed: Boolean

    /** The sync engine trusts the device wall clock (READY in this process, no step since). */
    fun clockTrusted(): Boolean

    /** QUIET and USER_ISSUER_CALL only; at most one call. */
    val issuer: IssuerPort?

    /** FOREGROUND and BACKGROUND only. */
    val redeem: RedeemPort?
}

/**
 * The user-driven parts of the sync controller (design §8.3, §11.2, §19.11). Production:
 * `android.EntitlementWiring` over `SyncController`.
 */
interface UserCallPort {
    /** Runs [block] once on its own thread with a USER_ISSUER_CALL session (closed while the app is hidden). */
    fun runUserIssuerCall(block: (SessionPort) -> Unit)

    /** The payment screen is shown: relay sessions are closed and held off. */
    fun paymentScreenShown()

    /** The payment screen was hidden: relay sessions stay held for U[20 min, 60 min]. */
    fun paymentScreenHidden()
}
