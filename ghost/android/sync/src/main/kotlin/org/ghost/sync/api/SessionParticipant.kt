package org.ghost.sync.api

import org.ghost.network.OnionAddress
import org.ghost.network.RelayTransport
import org.ghost.network.TorIssuerTransport
import org.ghost.network.TorRelayTransport

/**
 * The one participant of the sync runtime (Phase 8 design §11.6; ADR-23 amends ADR-20 point 1). One
 * slot, like the consumer listener: [SyncController.setParticipant]. The entitlement engine is the
 * only implementer in Phase 8. It shares the process's one Tor transport through leases instead of
 * owning a second one (two Arti clients must not share a state directory, and a second bootstrap
 * would be a timing fingerprint).
 *
 * Contract:
 *  - every callback runs on its own thread, never a lane thread, and may block; nothing it does can
 *    delay or suppress a read-lane event (T19): its calls never feed the session's breakers,
 *    budgets or transport faults, and it never holds the session's lock;
 *  - its database work goes through [SyncStores.database][org.ghost.sync.store.SyncStores.database],
 *    in short transactions; a call made inside a sync transaction is refused with
 *    [IllegalStateException] (no network call inside a transaction, design §11.5);
 *  - its calls fail with `NetworkException(category)` like any relay call, or with
 *    [IllegalArgumentException] for arguments refused before any I/O; `closed` (retryable) once the
 *    session's lease has closed.
 */
interface SessionParticipant {
    /**
     * A relay session (the foreground, or a normal background run) is READY. Own thread, until the
     * session ends ([ParticipantSession.closed]); the session's end never waits for it.
     */
    fun onRelaySession(session: ParticipantSession)

    /**
     * A quiet run started (1/8 of the periodic runs, drawn from client randomness only): the
     * transport is READY and no relay session runs. Must return before the deadline; at the
     * deadline the lease closes and the job ends whether or not it has returned.
     */
    fun onQuietRun(session: ParticipantSession)
}

/** What a [ParticipantSession] stands for; it decides which access it grants. */
enum class SessionKind { FOREGROUND, BACKGROUND, QUIET, USER_ISSUER_CALL }

/**
 * A participant's lease on the one transport for one session, quiet run or user issuer call.
 *
 *  - [relayRedeem] exists in FOREGROUND and BACKGROUND sessions only, [issuer] in QUIET and
 *    USER_ISSUER_CALL sessions only: no automatic issuer call can happen during a relay session,
 *    and no relay is touched in a quiet run (P-7). A USER_ISSUER_CALL session is open only while
 *    the app is visible, so it may overlap the foreground session (a declared L3 sample) and never
 *    a background session or a quiet run (T23; see [SyncController.runUserIssuerCall]).
 *  - [issuer] makes at most one call per session: the first call attempt uses it up and every later
 *    one fails `closed` (J9). The call runs on a fresh issuer flow, ended after the call.
 *  - Once [closed], every call fails `closed` (retryable); a call never outlives
 *    [deadlineMonotonicMillis] (its deadline is cut to what is left).
 */
interface ParticipantSession {
    val kind: SessionKind

    /** FOREGROUND and BACKGROUND only. */
    val relayRedeem: RelayRedeemAccess?

    /** QUIET and USER_ISSUER_CALL only. */
    val issuer: IssuerAccess?

    /** The engine trusts the device wall clock (a READY in this process, no step since), and the lease is open. */
    fun clockTrusted(): Boolean

    /** Monotonic time (the sync clock) at which the lease closes; `Long.MAX_VALUE` in the foreground. */
    val deadlineMonotonicMillis: Long

    /** The lease is closed (the session ended, or its deadline passed): every call fails `closed`. */
    val closed: Boolean
}

/** Redemption at a relay (Phase 8 design §10.9), on the namespace's own circuits. */
interface RelayRedeemAccess {
    /** See [TorRelayTransport.redeem]; [requestId] is identical on every retry. */
    fun redeem(
        relay: OnionAddress,
        namespace: NamespaceId,
        token: ByteArray,
        requestId: ByteArray,
        deadlineMillis: Int = RelayTransport.MAX_DEADLINE_MILLIS,
    ): TorRelayTransport.RedeemAnswer
}

/**
 * Issuer calls (Phase 8 design §5.3, §8.3, §9.4, §19.8), each on a fresh issuer flow that no other
 * call shares; see [TorIssuerTransport] for the arguments and the answers.
 */
interface IssuerAccess {
    fun requestInvoice(
        claimHash: ByteArray,
        credits: List<ByteArray>,
        baseWeek: Long,
        deadlineMillis: Int = TorIssuerTransport.MAX_DEADLINE_MILLIS,
    ): TorIssuerTransport.InvoiceAnswer

    fun blindSign(
        invoiceId: ByteArray,
        claimKey: ByteArray,
        seed: ByteArray,
        product: Int,
        baseWeek: Long,
        layoutDigest: ByteArray,
        positions: Int,
        deadlineMillis: Int = TorIssuerTransport.MAX_SIGNING_DEADLINE_MILLIS,
    ): TorIssuerTransport.SignAnswer

    fun invoiceStatus(
        invoiceId: ByteArray,
        claimKey: ByteArray,
        deadlineMillis: Int = TorIssuerTransport.MAX_DEADLINE_MILLIS,
    ): TorIssuerTransport.StatusAnswer

    fun redeemInvite(
        inviteToken: ByteArray,
        seed: ByteArray,
        baseWeek: Long,
        layoutDigest: ByteArray,
        positions: Int,
        deadlineMillis: Int = TorIssuerTransport.MAX_SIGNING_DEADLINE_MILLIS,
    ): TorIssuerTransport.TrialAnswer

    fun claimPayout(
        claimId: ByteArray,
        credits: List<ByteArray>,
        payoutAddress: String,
        deadlineMillis: Int = TorIssuerTransport.MAX_DEADLINE_MILLIS,
    ): TorIssuerTransport.ClaimAnswer

    fun refreshCredit(
        receivedCredit: ByteArray,
        seed: ByteArray,
        layoutDigest: ByteArray,
        deadlineMillis: Int = TorIssuerTransport.MAX_DEADLINE_MILLIS,
    ): TorIssuerTransport.RefreshAnswer
}
