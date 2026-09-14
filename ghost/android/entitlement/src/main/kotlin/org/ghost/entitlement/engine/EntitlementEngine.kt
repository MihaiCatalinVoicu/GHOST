package org.ghost.entitlement.engine

import org.ghost.entitlement.api.ActivationResult
import org.ghost.entitlement.api.ActivationState
import org.ghost.entitlement.api.ClaimId
import org.ghost.entitlement.api.Disclosure
import org.ghost.entitlement.api.Entitlement
import org.ghost.entitlement.api.EntitlementFlag
import org.ghost.entitlement.api.EntitlementStatus
import org.ghost.entitlement.api.PayWith
import org.ghost.entitlement.api.PaymentInstructions
import org.ghost.entitlement.api.PurchaseId
import org.ghost.entitlement.api.RestoreResult
import org.ghost.entitlement.port.EntitlementRandom
import org.ghost.entitlement.port.SessionPort
import org.ghost.entitlement.store.Kinds
import org.ghost.entitlement.store.PurchaseRow
import org.ghost.entitlement.store.PurchaseStore
import org.ghost.entitlement.store.StateStore
import org.ghost.entitlement.store.TokenStore
import org.ghost.network.EntitlementCrypto.ScheduleSummary
import org.ghost.network.NetworkException
import org.ghost.sync.api.PrivacyMode
import org.ghost.sync.api.SyncTransaction
import org.ghost.sync.store.SyncStores
import org.ghost.sync.store.Time
import java.nio.ByteBuffer
import java.util.EnumSet

/**
 * The entitlement engine (Phase 8 design §11): pure JVM behind ports, the facade of §11.2 and the
 * three entry points the sync runtime drives through its one participant slot:
 *  - [onRelaySession]: the redeem lane (§11.6, §12.4), drop sending and receiving, GC; no issuer call;
 *  - [onQuietRun]: at most one issuer call (§12.2, J9), only under a trusted clock (§19.4);
 *  - [onForeground]: a pending onboarding trial resumes as a user issuer call (§8.3).
 * [stores] gives the sync stores of the open database (null while none is open). The built-in
 * schedule is accepted against the remembered one once per database (ES rule 5); on a conflict the
 * engine stays inert and `SCHEDULE_CONFLICT` is raised.
 */
class EntitlementEngine(private val deps: EngineDeps, private val stores: () -> SyncStores?) : Entitlement {
    private val memory = EngineMemory()

    @Volatile
    private var summary: ScheduleSummary? = null

    private var context: EngineContext? = null

    /** The context of the open database, accepting the schedule on its first use; null without a database or schedule. */
    @Synchronized
    internal fun context(): EngineContext? {
        val s = stores() ?: return null
        context?.let { if (it.sync === s) return it }
        val sum = summary ?: try {
            deps.crypto.scheduleSummary()
        } catch (e: NetworkException) {
            return null
        }
        summary = sum
        val ctx = EngineContext(s, sum, deps, memory)
        val result = ctx.tx { tx -> ScheduleAcceptance(ctx.keys, ctx.state).accept(tx, sum) { deps.random.bytes(EngineContext.SECRET_BYTES) } }
        ctx.accepted = result == ScheduleAcceptance.Result.ACCEPTED
        context = ctx
        return ctx
    }

    private fun ready(): EngineContext? = context()?.takeIf { it.accepted }

    // ------------------------------------------------------------------ participant entry points

    /**
     * A relay session: the redeem lane until the session closes. An inert engine runs no lane, so it
     * reports its one (empty) step at once: a background session held open for a lane step (Q29,
     * §19.23 point 5) is not kept until its deadline for nothing.
     */
    fun onRelaySession(session: SessionPort) {
        val c = ready()
        if (c == null) {
            session.redeem?.stepDone()
            return
        }
        c.redeemLane.run(session) { tick(c, session) }
    }

    /**
     * One pass of a relay session's loop (GC and drops, then one redeem-lane step, reported), for a
     * driver that keeps the lane's pace itself with [redeemLane]'s waits in virtual time (the JVM
     * harness, design §11.9); [onRelaySession] runs the same passes on its own thread, and an inert
     * engine reports its empty step as it does.
     */
    internal fun relayPass(session: SessionPort) {
        val redeem = session.redeem ?: return
        val c = ready()
        if (c == null) {
            redeem.stepDone()
            return
        }
        if (session.closed) return
        tick(c, session)
        c.redeemLane.step(session, redeem)
        redeem.stepDone()
    }

    /** The redeem lane of the open database, or null while the engine is inert. */
    internal fun redeemLane(): RedeemLane? = ready()?.redeemLane

    fun onQuietRun(session: SessionPort) {
        val issuer = session.issuer ?: return
        val c = ready() ?: return
        if (session.closed || !session.clockTrusted()) return
        val now = c.now()
        c.gc.runIfDue(now)
        c.purchaseSteps.settle(now)
        c.quietRunWork.run(issuer, now)
    }

    /** The app became visible: a pending onboarding trial retries (the user is present, §8.3 step 4). */
    fun onForeground() {
        val c = ready() ?: return
        c.trialSteps.resume(c.now())
    }

    /**
     * Relay-session work besides the lane: GC, the install of a restore's owed drop scan (its end is
     * fixed on this clock, §19.26 point 7), drop sending and receiving. GC windows, the scan's end and
     * the drop time are read on the device wall clock, so this runs only while the session trusts it.
     */
    private fun tick(c: EngineContext, session: SessionPort) {
        if (!session.clockTrusted()) return
        val now = c.now()
        c.gc.runIfDue(now)
        c.restoreScan.resume(now)
        c.dropSteps.sendDue(now)
        c.dropSteps.settleSent()
        c.dropSteps.receive(now)
    }

    internal fun counter(name: String): Long = memory.counter(name)

    // ------------------------------------------------------------------ facade

    override fun status(): EntitlementStatus {
        val c = context() ?: return EntitlementStatus.EMPTY
        val now = c.now()
        return c.tx { tx -> statusOf(c, tx, now) }
    }

    private fun statusOf(c: EngineContext, tx: SyncTransaction, now: Long): EntitlementStatus {
        val flags = EnumSet.noneOf(EntitlementFlag::class.java)
        val alarms = c.state.read(tx)?.alarmFlags ?: 0
        if (alarms and StateStore.ALARM_SCHEDULE_CONFLICT != 0) flags += EntitlementFlag.SCHEDULE_CONFLICT
        if (alarms and StateStore.ALARM_ISSUER_MISMATCH != 0) flags += EntitlementFlag.ISSUER_MISMATCH
        if (alarms and StateStore.ALARM_REFUSED_BY_RELAY != 0) flags += EntitlementFlag.REFUSED_BY_RELAY
        if (c.summary.lastWeek - Grid.week(now) < EngineContext.HORIZON_WEEKS) flags += EntitlementFlag.UPDATE_REQUIRED
        memory.neededSince()?.let { since ->
            val delay = (deps.random.prf(EntitlementRandom.DOMAIN_NEED_SURFACE, ByteBuffer.allocate(8).putLong(since).array()) * NEED_SURFACE_SPAN).toLong()
            if (now >= since + delay) flags += EntitlementFlag.ENTITLEMENT_NEEDED
        }
        for (p in c.purchases.all(tx)) {
            when (p.state) {
                PurchaseStore.EXPIRED -> flags += EntitlementFlag.PAYMENT_EXPIRED
                PurchaseStore.LOST -> flags += EntitlementFlag.PAYMENT_LOST
            }
            if (paymentReady(p, now)) flags += EntitlementFlag.PAYMENT_READY
        }
        return EntitlementStatus(
            c.tokens.lastAccessWeek(tx),
            c.tokens.freshAccessPerWeek(tx),
            c.tokens.count(tx, Kinds.CREDIT, TokenStore.FRESH),
            c.tokens.count(tx, Kinds.INVITE, TokenStore.FRESH),
            flags,
        )
    }

    /** `PAYMENT_READY` appears at least U[1 h, 6 h] after the invoice arrived, never as an immediate notification (§19.11). */
    private fun paymentReady(p: PurchaseRow, now: Long): Boolean {
        if (p.kind != PurchaseStore.PACK || p.state != PurchaseStore.INVOICED || p.payWith != PurchaseStore.XMR || p.shown) return false
        val receipt = p.receiptMinute ?: return false
        if ((p.amountAtomic ?: 0L) <= 0L || now >= receipt + PAYMENT_WINDOW) return false
        val delay = PAYMENT_READY_MIN + (deps.random.prf(EntitlementRandom.DOMAIN_PAYMENT_READY, p.id()) * PAYMENT_READY_SPAN).toLong()
        return now >= receipt + delay
    }

    override fun startPurchase(payWith: PayWith): PurchaseId? {
        val c = ready() ?: return null
        return try {
            c.purchaseSteps.start(payWith, c.now(), delayed = memory.neededSince() != null)
        } catch (e: NetworkException) {
            null
        }
    }

    override fun requiredDisclosures(id: PurchaseId): Set<Disclosure> {
        val c = ready() ?: return emptySet()
        val p = c.tx { tx -> c.purchases.get(tx, id.toByteArray()) } ?: return emptySet()
        return if (p.kind == PurchaseStore.PACK && p.payWith == PurchaseStore.XMR && p.live) Disclosure.entries.toSet() else emptySet()
    }

    override fun acknowledge(id: PurchaseId, disclosures: Set<Disclosure>) {
        val c = ready() ?: return
        val required = requiredDisclosures(id)
        if (required.isEmpty() || !disclosures.containsAll(required)) return
        c.tx { tx -> c.purchases.setDisclosed(tx, id.toByteArray()) }
    }

    override fun paymentInstructions(id: PurchaseId): PaymentInstructions? {
        val c = ready() ?: return null
        val now = c.now()
        val p = c.tx { tx -> c.purchases.get(tx, id.toByteArray()) } ?: return null
        if (p.kind != PurchaseStore.PACK || p.state != PurchaseStore.INVOICED || p.payWith != PurchaseStore.XMR || !p.disclosed) return null
        val subaddress = p.subaddress ?: return null
        val amount = p.amountAtomic ?: return null
        val deadline = (p.receiptMinute ?: return null) + PAYMENT_WINDOW
        if (now >= deadline) return null
        val outstanding = p.outstandingAtomic ?: amount
        val uri = if (outstanding > 0) {
            try {
                c.crypto.paymentUri(subaddress, outstanding)
            } catch (e: NetworkException) {
                return null
            }
        } else {
            null
        }
        c.tx { tx -> c.purchases.setShown(tx, id.toByteArray()) }
        return PaymentInstructions(subaddress, amount, outstanding, deadline, uri)
    }

    override fun requestInvoiceNow(id: PurchaseId) {
        val c = ready() ?: return
        if (c.mode() != PrivacyMode.STANDARD) return
        val raw = id.toByteArray()
        deps.userCalls.runUserIssuerCall { session ->
            val issuer = session.issuer
            if (issuer != null && !session.closed && session.clockTrusted()) c.purchaseSteps.requestInvoice(issuer, raw, c.now())
        }
    }

    override fun checkNow(id: PurchaseId) {
        val c = ready() ?: return
        if (c.mode() != PrivacyMode.STANDARD) return
        val raw = id.toByteArray()
        deps.userCalls.runUserIssuerCall { session ->
            val issuer = session.issuer
            if (issuer != null && !session.closed) c.purchaseSteps.invoiceStatus(issuer, raw)
        }
    }

    override fun cancel(id: PurchaseId): Boolean {
        val c = ready() ?: return false
        return c.purchaseSteps.cancel(id.toByteArray(), c.now())
    }

    override fun activate(inviteText: String): ActivationResult {
        val c = ready() ?: return ActivationResult.UNAVAILABLE
        return c.trialSteps.activate(inviteText, c.now())
    }

    override fun activationState(): ActivationState {
        val c = context() ?: return if (deps.identity.hasIdentity()) ActivationState.ACTIVE else ActivationState.NONE
        return c.trialSteps.activationState()
    }

    override fun restore(mnemonic: List<String>): RestoreResult {
        val c = ready() ?: return RestoreResult.UNAVAILABLE
        return c.restoreScan.restore(mnemonic)
    }

    override fun createInvite(expiryDay: Int): String? {
        val c = ready() ?: return null
        return try {
            c.dropSteps.createInvite(expiryDay.toLong(), c.now())
        } catch (e: NetworkException) {
            null
        }
    }

    override fun revokeInvite(index: Int): Boolean {
        val c = ready() ?: return false
        return try {
            c.trialSteps.revoke(index, c.now())
        } catch (e: NetworkException) {
            false
        }
    }

    override fun claimPayout(address: String): ClaimId? {
        val c = ready() ?: return null
        return c.claimSteps.create(address, c.now())
    }

    override fun setAutoRenewWithCredits(enabled: Boolean) {
        val c = ready() ?: return
        c.tx { tx -> c.state.setAutoRenew(tx, enabled) }
    }

    override fun paymentScreenShown(id: PurchaseId) {
        deps.userCalls.paymentScreenShown()
        memory.paymentScreenOpen.set(true)
        rememberPaymentScreen()
    }

    override fun paymentScreenHidden(id: PurchaseId) {
        deps.userCalls.paymentScreenHidden()
        memory.paymentScreenOpen.set(false)
        rememberPaymentScreen()
    }

    /**
     * The app went to the background. The sync runtime hides an open payment screen with it (the hold
     * starts then), so the moment kept for the next process moves to now: a process killed in the
     * background, while the user pays from a wallet app, restores the hold from when the screen was
     * last visible, not from when it was opened (§19.11, E15).
     */
    fun onBackground() {
        if (memory.paymentScreenOpen.getAndSet(false)) rememberPaymentScreen()
    }

    /** The minute the payment screen was last visible, rounded up, survives the process (§19.11, E15). */
    private fun rememberPaymentScreen() {
        val c = context() ?: return
        val minute = Time.ceilMinute(c.now())
        c.tx { tx -> c.state.setPaymentShown(tx, minute) }
    }

    override fun toString(): String = "EntitlementEngine"

    private companion object {
        const val PAYMENT_WINDOW: Long = 24 * Grid.HOUR
        const val PAYMENT_READY_MIN: Long = Grid.HOUR
        const val PAYMENT_READY_SPAN: Long = 5 * Grid.HOUR
        const val NEED_SURFACE_SPAN: Long = 12 * Grid.HOUR
    }
}
