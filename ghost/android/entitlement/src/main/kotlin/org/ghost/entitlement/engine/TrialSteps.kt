package org.ghost.entitlement.engine

import org.ghost.entitlement.api.ActivationResult
import org.ghost.entitlement.api.ActivationState
import org.ghost.entitlement.port.InviteTokenCheck
import org.ghost.entitlement.port.IssuerPort
import org.ghost.entitlement.store.InviteStore
import org.ghost.entitlement.store.PurchaseRow
import org.ghost.entitlement.store.PurchaseStore
import org.ghost.entitlement.store.StateStore
import org.ghost.entitlement.store.TransactionNonceStore
import org.ghost.identity.Invite
import org.ghost.network.EntitlementCrypto
import org.ghost.network.NetworkException
import org.ghost.network.TorIssuerTransport
import org.ghost.sync.api.NamespaceId
import org.ghost.sync.api.SyncTransaction
import org.ghost.sync.store.Time

/**
 * The invite trial (design §8.3) and invite revocation (§8.6, §19.14), both `RedeemInvite` with a trial
 * layout. An onboarding trial is a trial row without a due time: it runs only as a user issuer call
 * in the foreground, before the identity has any relay traffic. A revocation is a trial row with a due
 * time: quiet-run work, never a foreground call. The activation sequence ends either with an active
 * identity holding its trial tokens or with no identity: a refused trial wipes the identity first and
 * then records the failure, so a crash between the two resumes into the same end.
 */
internal class TrialSteps(private val c: EngineContext) {

    private class TrialCall(
        val onboarding: Boolean,
        val attempt: Int,
        val token: ByteArray,
        val seed: ByteArray,
        val base: Long,
        val digest: ByteArray,
        val positions: Int,
    )

    private sealed class Outcome {
        class Ok(val tokens: List<TorIssuerTransport.IssuedToken>) : Outcome()
        object Refused : Outcome()
        object WrongPeriod : Outcome()
        object Transient : Outcome()
        object Malformed : Outcome()
    }

    /**
     * `Entitlement.activate` (§8.3 steps 1–4): the invite is parsed and verified (with the offline
     * token check); one transaction records the trial, the drop target (with `t_drop` drawn in
     * `[start(base + 3), start(base + 8))`, §19.12) and the invite nonce; the identity is created; the
     * `RedeemInvite` runs as a user issuer call.
     */
    fun activate(text: String, now: Long): ActivationResult {
        val pending = c.tx { tx -> pendingOnboarding(tx) }
        if (pending != null) {
            resume(now)
            return ActivationResult.PENDING
        }
        if (c.identity.hasIdentity()) return ActivationResult.ALREADY_ACTIVE
        val base = Grid.week(now)
        if (!c.covers(base, Layouts.TRIAL_WEEKS)) return ActivationResult.UNAVAILABLE
        val layout = try {
            c.crypto.layout(EntitlementCrypto.PRODUCT_TRIAL, base)
        } catch (e: NetworkException) {
            return ActivationResult.UNAVAILABLE
        }
        val id = c.random.bytes(EngineContext.ID_BYTES)
        val seed = c.random.bytes(EngineContext.SECRET_BYTES)
        val dropMinute = Time.floorMinute(Grid.start(base + DROP_FIRST_WEEK) + minOf(DROP_SPAN - 1, (c.random.uniform() * DROP_SPAN).toLong()))
        val invite = try {
            c.tx { tx -> record(tx, text, now, id, seed, base, layout.digest(), dropMinute) }
        } catch (e: Invite.Rejection) {
            return refusal(e)
        } catch (e: NetworkException) {
            return ActivationResult.UNAVAILABLE
        }
        c.identity.create(invite)
        startCall(id)
        return ActivationResult.PENDING
    }

    private fun record(tx: SyncTransaction, text: String, now: Long, id: ByteArray, seed: ByteArray, base: Long, digest: ByteArray, dropMinute: Long): Invite {
        // The nonce is recorded inside this transaction (§19.20 point 6): a rolled-back activation keeps it unused.
        val invite = Invite.parseAndVerify(text, now, InviteTokenCheck(c.crypto), TransactionNonceStore(tx, Grid.day(now) * Grid.DAY))
        // A target left by an earlier activation that failed has no identity behind it any more.
        c.invites.deleteDropTarget(tx)
        c.purchases.insert(
            tx, id, PurchaseStore.TRIAL, PurchaseStore.INVITE, seed, null, invite.inviteToken, base, c.summary.seq, digest, Time.floorHour(now), null,
        )
        c.invites.insertDropTarget(tx, invite.dropNamespace, invite.dropKey, invite.dropSlots, dropMinute, invite.expiryDay + INVITER_LISTEN_DAYS)
        return invite
    }

    private fun refusal(e: Invite.Rejection): ActivationResult = when (e) {
        is Invite.Rejection.Malformed -> ActivationResult.REFUSED_MALFORMED
        is Invite.Rejection.UnsupportedVersion -> ActivationResult.REFUSED_VERSION
        is Invite.Rejection.BadSignature -> ActivationResult.REFUSED_SIGNATURE
        is Invite.Rejection.TokenRefused -> ActivationResult.REFUSED_TOKEN
        is Invite.Rejection.Expired -> ActivationResult.REFUSED_EXPIRED
        is Invite.Rejection.Replayed -> ActivationResult.REFUSED_REPLAYED
    }

    /**
     * Crash recovery and the next foreground attempt (§8.3 steps 4–5): a pending onboarding trial with
     * no identity resumes at the identity's creation, with one at the `RedeemInvite`.
     */
    fun resume(now: Long) {
        val pending = c.tx { tx -> pendingOnboarding(tx) } ?: return
        if (!c.identity.hasIdentity()) c.identity.create(null)
        startCall(pending.id())
    }

    private fun startCall(id: ByteArray) {
        if (!c.memory.trialCall.compareAndSet(false, true)) return
        c.deps.userCalls.runUserIssuerCall { session ->
            try {
                val issuer = session.issuer
                if (issuer != null && !session.closed) redeem(issuer, id, c.now(), session.clockTrusted())
            } finally {
                c.memory.trialCall.set(false)
            }
        }
    }

    /** One `RedeemInvite` of trial [id]; [trusted] is the session's clock trust (the base week is issuer-facing, §19.4). */
    fun redeem(issuer: IssuerPort, id: ByteArray, now: Long, trusted: Boolean) = c.memory.flight(id) {
        if (!trusted) return@flight
        val row = c.tx { tx -> c.purchases.get(tx, id) } ?: return@flight
        if (row.kind != PurchaseStore.TRIAL || row.state != PurchaseStore.PREPARED) return@flight
        if (row.attempt >= cap(row.nextDueMinute == null)) {
            fail(id, row.nextDueMinute == null, now)
            return@flight
        }
        val call = c.tx { tx -> prepare(tx, id, now) } ?: return@flight
        val outcome = try {
            val answer = issuer.redeemInvite(call.token, call.seed, call.base, call.digest, call.positions)
            when (answer.result) {
                TorIssuerTransport.TRIAL_OK -> Outcome.Ok(answer.tokens)
                TorIssuerTransport.TRIAL_REPLAYED -> Outcome.Refused
                TorIssuerTransport.TRIAL_WRONG_PERIOD -> Outcome.WrongPeriod
                else -> Outcome.Malformed
            }
        } catch (e: NetworkException) {
            when (RetryPolicy.classify(e.category)) {
                Failure.TRANSIENT -> Outcome.Transient
                Failure.UNAUTHORIZED, Failure.REJECTED -> Outcome.Refused
                Failure.MALFORMED -> Outcome.Malformed
            }
        } catch (e: IllegalArgumentException) {
            Outcome.Refused
        }
        apply(id, call, outcome, now)
    }

    private fun prepare(tx: SyncTransaction, id: ByteArray, now: Long): TrialCall? {
        val p = c.purchases.get(tx, id) ?: return null
        if (p.kind != PurchaseStore.TRIAL || p.state != PurchaseStore.PREPARED) return null
        var base = checkNotNull(p.baseWeek)
        var digest = p.layoutDigest()
        if (!p.sent) {
            val week = Grid.week(now)
            if (base != week) {
                if (!c.covers(week, Layouts.TRIAL_WEEKS)) return null
                val layout = c.crypto.layout(EntitlementCrypto.PRODUCT_TRIAL, week)
                c.purchases.refreshUnsent(tx, id, week, c.summary.seq, layout.digest())
                base = week
                digest = layout.digest()
            }
        }
        // An onboarding trial keeps no due time (that is how it is told apart); a revocation's retry
        // time is drawn with its first send.
        val onboarding = p.nextDueMinute == null
        val nextDue = if (onboarding) null else RetryPolicy.nextDueAfterSend(p.attempt, p.nextDueMinute, now, c.random::uniform)
        c.purchases.countAttempt(tx, id, PurchaseStore.PREPARED, p.attempt, nextDue)
        val positions = c.crypto.layout(EntitlementCrypto.PRODUCT_TRIAL, base).positions
        return TrialCall(onboarding, p.attempt + 1, p.inputToken(), p.seed(), base, digest, positions)
    }

    /** An onboarding trial retries at each foreground, the user present (§8.3); a revocation retries once (§19.11, §19.14). */
    private fun cap(onboarding: Boolean): Int = if (onboarding) RetryPolicy.ONBOARDING_ATTEMPTS else RetryPolicy.CALL_ATTEMPTS

    private fun apply(id: ByteArray, call: TrialCall, outcome: Outcome, now: Long) {
        when (outcome) {
            is Outcome.Ok -> {
                val order = Layouts.trial(c.summary, call.base)
                if (order.size != outcome.tokens.size) {
                    malformed(id, call.onboarding, now)
                    return
                }
                c.tx { tx ->
                    val p = c.purchases.get(tx, id)
                    if (p != null && p.state == PurchaseStore.PREPARED) {
                        // Onboarding: eligible at once in STANDARD, at an activation slot in HIGH whose extra
                        // days stop at the trial's last week (§12.3, Q30); a revocation's spares follow the
                        // pack rule (§19.24 point 13, §19.26).
                        val eligible = if (call.onboarding) {
                            Slots.trialEligibleMinute(now, call.base, c.random, c.mode())
                        } else {
                            Slots.revocationEligibleMinute(now, c.random, c.mode())
                        }
                        c.purchaseSteps.storeTokens(tx, order, outcome.tokens, eligible)
                        c.purchases.terminal(tx, id, PurchaseStore.PREPARED, PurchaseStore.FINALIZED, Grid.day(now))
                        c.memory.clearMalformed(id)
                    }
                }
            }
            Outcome.Refused -> fail(id, call.onboarding, now)
            Outcome.WrongPeriod -> c.tx { tx ->
                val p = c.purchases.get(tx, id)
                if (p != null && p.state == PurchaseStore.PREPARED) c.purchaseSteps.rePrepare(tx, p, now)
            }
            Outcome.Transient -> if (call.attempt >= cap(call.onboarding)) fail(id, call.onboarding, now)
            Outcome.Malformed -> malformed(id, call.onboarding, now)
        }
    }

    private fun malformed(id: ByteArray, onboarding: Boolean, now: Long) {
        if (c.memory.firstMalformed(id)) return
        c.tx { tx -> c.alarm(tx, StateStore.ALARM_ISSUER_MISMATCH) }
        fail(id, onboarding, now)
    }

    /** "Revoked invite fails closed" (§8.3): the identity is wiped before the failure is recorded. */
    private fun fail(id: ByteArray, onboarding: Boolean, now: Long) {
        if (onboarding) c.identity.wipe()
        c.tx { tx ->
            val p = c.purchases.get(tx, id)
            if (p != null && p.state == PurchaseStore.PREPARED) {
                c.purchases.terminal(tx, id, PurchaseStore.PREPARED, PurchaseStore.FAILED, Grid.day(now))
                if (onboarding) c.invites.deleteDropTarget(tx)
            }
        }
    }

    /**
     * `revokeInvite` (§8.6, §19.14): the invite closes (its drop stops being listened) and a revocation
     * trial with its token becomes quiet-run work; its tokens are kept as spares.
     */
    fun revoke(index: Int, now: Long): Boolean {
        val week = Grid.week(now)
        if (!c.covers(week, Layouts.TRIAL_WEEKS)) return false
        val layout = c.crypto.layout(EntitlementCrypto.PRODUCT_TRIAL, week)
        return c.tx { tx ->
            val invite = c.invites.get(tx, index)
            val payload = invite?.payload()
            if (invite == null || invite.state != InviteStore.CREATED || payload == null) {
                false
            } else {
                val token = payload.copyOfRange(1, 1 + Invite.TOKEN_BYTES)
                c.invites.close(tx, index)
                c.retireNamespace(tx, NamespaceId(invite.dropNamespace()))
                c.purchases.insert(
                    tx, c.random.bytes(EngineContext.ID_BYTES), PurchaseStore.TRIAL, PurchaseStore.INVITE, c.random.bytes(EngineContext.SECRET_BYTES),
                    null, token, week, c.summary.seq, layout.digest(), Time.floorHour(now), Time.floorMinute(now),
                )
                true
            }
        }
    }

    fun activationState(): ActivationState {
        val identity = c.identity.hasIdentity()
        return c.tx { tx ->
            val trials = c.purchases.all(tx).filter { it.kind == PurchaseStore.TRIAL }
            when {
                trials.any { it.state == PurchaseStore.PREPARED && it.nextDueMinute == null } -> ActivationState.PENDING
                identity -> ActivationState.ACTIVE
                trials.any { it.state == PurchaseStore.FAILED } -> ActivationState.FAILED
                else -> ActivationState.NONE
            }
        }
    }

    private fun pendingOnboarding(tx: SyncTransaction): PurchaseRow? =
        c.purchases.live(tx).firstOrNull { it.kind == PurchaseStore.TRIAL && it.state == PurchaseStore.PREPARED && it.nextDueMinute == null }

    override fun toString(): String = "TrialSteps"

    internal companion object {
        private const val DROP_FIRST_WEEK = 3L
        private const val DROP_SPAN: Long = 5 * Grid.WEEK

        /** `t_drop` < start(base + [DROP_END_WEEK]): the end of the drop window (§19.12; [RefreshPlan]). */
        const val DROP_END_WEEK: Long = DROP_FIRST_WEEK + DROP_SPAN / Grid.WEEK

        /** The inviter listens until `expiry_day + 56` (§8.5). */
        private const val INVITER_LISTEN_DAYS = 56L
    }
}
