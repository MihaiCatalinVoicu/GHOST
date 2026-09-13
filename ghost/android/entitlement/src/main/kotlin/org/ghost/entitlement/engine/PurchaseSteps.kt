package org.ghost.entitlement.engine

import org.ghost.entitlement.api.PayWith
import org.ghost.entitlement.api.PurchaseId
import org.ghost.entitlement.port.IssuerPort
import org.ghost.entitlement.store.Kinds
import org.ghost.entitlement.store.PurchaseRow
import org.ghost.entitlement.store.PurchaseStore
import org.ghost.entitlement.store.StateStore
import org.ghost.entitlement.store.TokenStore
import org.ghost.entitlement.store.sha256
import org.ghost.network.EntitlementCrypto
import org.ghost.network.NetworkException
import org.ghost.network.TorIssuerTransport
import org.ghost.sync.api.SyncTransaction
import org.ghost.sync.store.Time

/**
 * Pack purchases and refreshes of received credits (design §5.3, §11.4, §11.5, §19.8, §19.11,
 * §19.13). Every call is a short transaction, the call, a short transaction; the first transaction
 * writes ahead (`sent = 1`, the attempt counted, credits reserved) so a crash is an ambiguous timeout
 * whose retry sends identical bytes (the native side recomputes the request from the stored seed and
 * layout digest). No issuer answer ever changes a due time, a base week or a count (R1, J9).
 */
internal class PurchaseSteps(private val c: EngineContext) {

    private class RequestCall(val claimHash: ByteArray, val credits: List<ByteArray>, val baseWeek: Long, val xmr: Boolean)

    private class SignCall(
        val invoiceId: ByteArray,
        val claimKey: ByteArray,
        val seed: ByteArray,
        val product: Int,
        val baseWeek: Long,
        val layoutDigest: ByteArray,
        val positions: Int,
    )

    private class RefreshCall(val credit: ByteArray, val seed: ByteArray, val layoutDigest: ByteArray)

    /**
     * `startPurchase` (local only, §5.3 step 1): claim key, seed and base week are written before
     * anything is sent. While `ENTITLEMENT_NEEDED` is set ([delayed]) the `RequestInvoice` waits
     * U[0, 24 h] (§19.13).
     */
    fun start(payWith: PayWith, now: Long, delayed: Boolean): PurchaseId? {
        if (!c.purchasable(now)) return null
        val week = Grid.week(now)
        val xmr = payWith == PayWith.XMR
        val layout = c.crypto.layout(Layouts.packProduct(xmr), week)
        val id = c.random.bytes(EngineContext.ID_BYTES)
        val seed = c.random.bytes(EngineContext.SECRET_BYTES)
        val claimKey = c.random.bytes(EngineContext.SECRET_BYTES)
        val nextDue = if (delayed) Time.ceilMinute(now + (c.random.uniform() * NEEDED_REQUEST_DELAY).toLong()) else null
        val created = c.tx { tx ->
            if (!xmr && Pricing.coveringSet(c.summary, c.tokens.freshCredits(tx), week, week) == null) {
                false
            } else {
                c.purchases.insert(
                    tx, id, PurchaseStore.PACK, if (xmr) PurchaseStore.XMR else PurchaseStore.CREDITS, seed, claimKey, null, week,
                    c.summary.seq, layout.digest(), Time.floorHour(now), nextDue,
                )
                true
            }
        }
        return if (created) PurchaseId(id) else null
    }

    // ------------------------------------------------------------------ RequestInvoice

    /** `RequestInvoice` of pack [id]; the caller holds an issuer access and a trusted clock (§19.4). */
    fun requestInvoice(issuer: IssuerPort, id: ByteArray, now: Long) = c.memory.flight(id) {
        val call = c.tx { tx -> prepareRequest(tx, id, now) } ?: return@flight
        val answer = try {
            issuer.requestInvoice(call.claimHash, call.credits, call.baseWeek)
        } catch (e: NetworkException) {
            c.tx { tx -> requestFailed(tx, id, RetryPolicy.classify(e.category), now) }
            return@flight
        } catch (e: IllegalArgumentException) {
            c.tx { tx -> requestFailed(tx, id, Failure.REJECTED, now) }
            return@flight
        }
        c.tx { tx -> applyInvoice(tx, id, call, answer, now) }
    }

    private fun prepareRequest(tx: SyncTransaction, id: ByteArray, now: Long): RequestCall? {
        val p = c.purchases.get(tx, id) ?: return null
        if (p.kind != PurchaseStore.PACK || p.state != PurchaseStore.PREPARED) return null
        val xmr = p.payWith == PurchaseStore.XMR
        var base = checkNotNull(p.baseWeek)
        if (!p.sent) {
            // Base week refreshed while nothing was sent (§11.4), from the device clock under clockTrusted().
            val week = Grid.week(now)
            if (!c.covers(week, Layouts.PACK_WEEKS)) {
                failPrepared(tx, p, now)
                return null
            }
            if (base != week) {
                val layout = c.crypto.layout(Layouts.packProduct(xmr), week)
                c.purchases.refreshUnsent(tx, id, week, c.summary.seq, layout.digest())
                base = week
            }
            if (!xmr) {
                // The smallest covering set of own fresh credits, reserved with the first send (§11.4).
                val set = Pricing.coveringSet(c.summary, c.tokens.freshCredits(tx), base, week)
                if (set == null) {
                    failPrepared(tx, p, now)
                    return null
                }
                set.forEach { c.tokens.reserveCredit(tx, it.nullifier(), TokenStore.FOR_PURCHASE, id) }
            }
        }
        if (p.attempt >= RetryPolicy.CALL_ATTEMPTS) {
            failPrepared(tx, p, now)
            return null
        }
        c.purchases.countAttempt(tx, id, PurchaseStore.PREPARED, p.attempt, RetryPolicy.nextDueAfterSend(p.attempt, p.nextDueMinute, now, c.random::uniform))
        val credits = if (xmr) emptyList() else c.tokens.reservedCredits(tx, TokenStore.FOR_PURCHASE, id).map { it.token() }
        return RequestCall(sha256(CLAIM_LABEL, p.claimKey()), credits, base, xmr)
    }

    private fun applyInvoice(tx: SyncTransaction, id: ByteArray, call: RequestCall, answer: TorIssuerTransport.InvoiceAnswer, now: Long) {
        val p = c.purchases.get(tx, id) ?: return
        if (p.state != PurchaseStore.PREPARED) return
        when (answer.result) {
            TorIssuerTransport.INVOICE_OK -> {
                // The native side checked amount and subaddress against the ES; checked again here (§7.8, EM8).
                val expected = if (call.xmr) Pricing.price(c.summary, Grid.priceEpoch(call.baseWeek)) else 0L
                if (expected == null || answer.amountAtomic != expected || (answer.subaddress != null) != call.xmr) {
                    malformed(tx, p, now)
                    return
                }
                val receipt = Time.floorMinute(now)
                // An invoice that came on the RequestInvoice retry spent the first BlindSign window (E5).
                val first = (p.attempt - 1).coerceIn(0, RetryPolicy.BLIND_SIGN_ATTEMPTS - 1)
                c.purchases.invoiced(
                    tx, id, answer.invoiceId(), answer.subaddress, answer.amountAtomic, receipt,
                    if (call.xmr) TorIssuerTransport.STATE_AWAITING_PAYMENT else 0,
                    first, RetryPolicy.blindSignDueMinute(p.seed(), receipt, first),
                )
                c.memory.clearMalformed(id)
            }
            TorIssuerTransport.INVOICE_WRONG_PERIOD -> rePrepare(tx, p, now)
            TorIssuerTransport.INVOICE_CREDITS_SPENT -> {
                // Nothing consumed: the masked credits are spent elsewhere and deleted, the others released.
                val sent = c.tokens.reservedCredits(tx, TokenStore.FOR_PURCHASE, id)
                c.purchases.terminal(tx, id, PurchaseStore.PREPARED, PurchaseStore.FAILED, Grid.day(now))
                sent.forEachIndexed { i, t -> if (i < MASK_BITS && (answer.spentMask ushr i) and 1L == 1L) c.tokens.delete(tx, t.nullifier()) }
                c.tokens.releaseCredits(tx, TokenStore.FOR_PURCHASE, id)
            }
            TorIssuerTransport.INVOICE_CLAIM_CONFLICT -> {
                c.alarm(tx, StateStore.ALARM_ISSUER_MISMATCH)
                failPrepared(tx, p, now)
            }
            else -> malformed(tx, p, now)
        }
    }

    private fun requestFailed(tx: SyncTransaction, id: ByteArray, failure: Failure, now: Long) {
        val p = c.purchases.get(tx, id) ?: return
        if (p.state != PurchaseStore.PREPARED) return
        when (failure) {
            Failure.TRANSIENT -> if (p.attempt >= RetryPolicy.CALL_ATTEMPTS) failPrepared(tx, p, now)
            Failure.UNAUTHORIZED, Failure.REJECTED -> failPrepared(tx, p, now)
            Failure.MALFORMED -> malformed(tx, p, now)
        }
    }

    // ------------------------------------------------------------------ BlindSign

    /** One `BlindSign` attempt of the fixed plan (§19.11); the caller picked it at its due time. */
    fun blindSign(issuer: IssuerPort, id: ByteArray, now: Long) = c.memory.flight(id) {
        val call = c.tx { tx -> prepareSign(tx, id, now) } ?: return@flight
        val answer = try {
            issuer.blindSign(call.invoiceId, call.claimKey, call.seed, call.product, call.baseWeek, call.layoutDigest, call.positions)
        } catch (e: NetworkException) {
            c.tx { tx -> signFailed(tx, id, RetryPolicy.classify(e.category), now) }
            return@flight
        } catch (e: IllegalArgumentException) {
            c.tx { tx -> signFailed(tx, id, Failure.REJECTED, now) }
            return@flight
        }
        c.tx { tx -> applySign(tx, id, answer, now) }
    }

    private fun prepareSign(tx: SyncTransaction, id: ByteArray, now: Long): SignCall? {
        val p = c.purchases.get(tx, id) ?: return null
        if (p.kind != PurchaseStore.PACK || p.state != PurchaseStore.INVOICED) return null
        if (p.attempt >= RetryPolicy.BLIND_SIGN_ATTEMPTS) {
            endInvoiced(tx, p, lostOrExpired(p), now)
            return null
        }
        val base = checkNotNull(p.baseWeek)
        val product = Layouts.packProduct(p.payWith == PurchaseStore.XMR)
        val positions = c.crypto.layout(product, base).positions
        val next = p.attempt + 1
        val nextDue = if (next < RetryPolicy.BLIND_SIGN_ATTEMPTS) RetryPolicy.blindSignDueMinute(p.seed(), checkNotNull(p.receiptMinute), next) else null
        c.purchases.countAttempt(tx, id, PurchaseStore.INVOICED, p.attempt, nextDue)
        return SignCall(p.invoiceId(), p.claimKey(), p.seed(), product, base, p.layoutDigest(), positions)
    }

    private fun applySign(tx: SyncTransaction, id: ByteArray, answer: TorIssuerTransport.SignAnswer, now: Long) {
        val p = c.purchases.get(tx, id) ?: return
        if (p.state != PurchaseStore.INVOICED) return
        when (answer.state) {
            TorIssuerTransport.STATE_SIGNED -> finalizePack(tx, p, answer.tokens, now)
            TorIssuerTransport.STATE_AWAITING_PAYMENT, TorIssuerTransport.STATE_AWAITING_CONFIRMATIONS, TorIssuerTransport.STATE_UNDERPAID -> {
                c.purchases.progress(tx, id, answer.state, outstanding(p, answer.creditedAtomic, answer.seenAtomic))
                afterNonFinal(tx, p, now)
            }
            TorIssuerTransport.STATE_EXPIRED -> endInvoiced(tx, p, PurchaseStore.EXPIRED, now)
            TorIssuerTransport.STATE_OTHER_REQUEST_ISSUED -> {
                c.alarm(tx, StateStore.ALARM_ISSUER_MISMATCH)
                endInvoiced(tx, p, PurchaseStore.FAILED, now)
            }
            else -> malformed(tx, p, now)
        }
    }

    /** One transaction: every token with its (kind, epoch, slot) from the layout order, `finalized`, secrets wiped (§11.5). */
    private fun finalizePack(tx: SyncTransaction, p: PurchaseRow, tokens: List<TorIssuerTransport.IssuedToken>, now: Long) {
        val xmr = p.payWith == PurchaseStore.XMR
        val order = Layouts.pack(c.summary, checkNotNull(p.baseWeek), xmr)
        if (order.size != tokens.size) {
            malformed(tx, p, now)
            return
        }
        storeTokens(tx, order, tokens, Slots.packEligibleMinute(now, c.random, c.mode()))
        if (!xmr) c.tokens.deleteReservedCredits(tx, TokenStore.FOR_PURCHASE, p.id())
        c.purchases.terminal(tx, p.id(), PurchaseStore.INVOICED, PurchaseStore.FINALIZED, Grid.day(now))
        c.memory.clearMalformed(p.id())
    }

    private fun signFailed(tx: SyncTransaction, id: ByteArray, failure: Failure, now: Long) {
        val p = c.purchases.get(tx, id) ?: return
        if (p.state != PurchaseStore.INVOICED) return
        when (failure) {
            Failure.TRANSIENT -> afterNonFinal(tx, p, now)
            Failure.UNAUTHORIZED -> endInvoiced(tx, p, lostOrExpired(p), now)
            Failure.REJECTED -> endInvoiced(tx, p, PurchaseStore.FAILED, now)
            Failure.MALFORMED -> malformed(tx, p, now)
        }
    }

    /** After a non-final answer: the fifth one ends the plan (`lost`, §19.11). */
    private fun afterNonFinal(tx: SyncTransaction, p: PurchaseRow, now: Long) {
        if (p.attempt >= RetryPolicy.BLIND_SIGN_ATTEMPTS) endInvoiced(tx, p, PurchaseStore.LOST, now)
    }

    private fun lostOrExpired(p: PurchaseRow): String =
        if (p.prevState == TorIssuerTransport.STATE_EXPIRED) PurchaseStore.EXPIRED else PurchaseStore.LOST

    private fun outstanding(p: PurchaseRow, credited: Long, seen: Long): Long {
        val amount = checkNotNull(p.amountAtomic)
        return maxOf(0L, amount - minOf(amount, credited) - minOf(amount, seen))
    }

    // ------------------------------------------------------------------ InvoiceStatus

    /** The optional "check now" (§5.3 step 5): a status read; it never triggers `BlindSign`. */
    fun invoiceStatus(issuer: IssuerPort, id: ByteArray) {
        val keys = c.tx { tx ->
            c.purchases.get(tx, id)?.takeIf { it.kind == PurchaseStore.PACK && it.state == PurchaseStore.INVOICED }?.let { it.invoiceId() to it.claimKey() }
        } ?: return
        val answer = try {
            issuer.invoiceStatus(keys.first, keys.second)
        } catch (e: NetworkException) {
            return
        } catch (e: IllegalArgumentException) {
            return
        }
        if (answer.state !in TorIssuerTransport.STATE_AWAITING_PAYMENT..TorIssuerTransport.STATE_EXPIRED) return
        c.tx { tx ->
            val p = c.purchases.get(tx, id)
            if (p != null && p.state == PurchaseStore.INVOICED) c.purchases.progress(tx, id, answer.state, outstanding(p, answer.creditedAtomic, answer.seenAtomic))
        }
    }

    // ------------------------------------------------------------------ RefreshCredit

    /** `RefreshCredit` of a received credit, alone in its quiet run (§19.8). */
    fun refresh(issuer: IssuerPort, id: ByteArray, now: Long) = c.memory.flight(id) {
        val call = c.tx { tx -> prepareRefresh(tx, id, now) } ?: return@flight
        val answer = try {
            issuer.refreshCredit(call.credit, call.seed, call.layoutDigest)
        } catch (e: NetworkException) {
            c.tx { tx -> refreshFailed(tx, id, RetryPolicy.classify(e.category), now) }
            return@flight
        } catch (e: IllegalArgumentException) {
            c.tx { tx -> refreshFailed(tx, id, Failure.REJECTED, now) }
            return@flight
        }
        // The fresh credit's epoch comes from the schedule; a check that cannot run leaves the flow for
        // an identical retry (the issuer re-serves the same signature).
        val issued = answer.token
        val verified = if (answer.result == TorIssuerTransport.REFRESH_OK && issued != null) {
            try {
                c.crypto.verifyToken(issued.token(), EntitlementCrypto.KIND_CREDIT)
            } catch (e: NetworkException) {
                return@flight
            }
        } else {
            null
        }
        c.tx { tx -> applyRefresh(tx, id, answer, verified, now) }
    }

    private fun prepareRefresh(tx: SyncTransaction, id: ByteArray, now: Long): RefreshCall? {
        val p = c.purchases.get(tx, id) ?: return null
        if (p.kind != PurchaseStore.REFRESH || p.state != PurchaseStore.PREPARED) return null
        if (p.attempt >= RetryPolicy.CALL_ATTEMPTS) {
            failPrepared(tx, p, now)
            return null
        }
        c.purchases.countAttempt(tx, id, PurchaseStore.PREPARED, p.attempt, RetryPolicy.nextDueAfterSend(p.attempt, p.nextDueMinute, now, c.random::uniform))
        return RefreshCall(p.inputToken(), p.seed(), p.layoutDigest())
    }

    private fun applyRefresh(
        tx: SyncTransaction,
        id: ByteArray,
        answer: TorIssuerTransport.RefreshAnswer,
        verified: EntitlementCrypto.VerifiedToken?,
        now: Long,
    ) {
        val p = c.purchases.get(tx, id) ?: return
        if (p.kind != PurchaseStore.REFRESH || p.state != PurchaseStore.PREPARED) return
        when (answer.result) {
            TorIssuerTransport.REFRESH_OK -> {
                val issued = answer.token
                if (issued == null || verified == null || verified.kind != EntitlementCrypto.KIND_CREDIT) {
                    malformed(tx, p, now)
                    return
                }
                c.tokens.insertFresh(tx, issued.nullifier(), Kinds.CREDIT, verified.epoch, null, issued.token(), Time.floorMinute(now))
                c.purchases.terminal(tx, id, PurchaseStore.PREPARED, PurchaseStore.FINALIZED, Grid.day(now))
                c.memory.clearMalformed(id)
            }
            TorIssuerTransport.REFRESH_REPLAYED -> {
                // Used elsewhere or refreshed with another value (possibly a malicious invitee): dropped.
                c.memory.count(Counters.REFRESH_REPLAYED)
                failPrepared(tx, p, now)
            }
            else -> malformed(tx, p, now)
        }
    }

    private fun refreshFailed(tx: SyncTransaction, id: ByteArray, failure: Failure, now: Long) {
        val p = c.purchases.get(tx, id) ?: return
        if (p.state != PurchaseStore.PREPARED) return
        when (failure) {
            Failure.TRANSIENT -> if (p.attempt >= RetryPolicy.CALL_ATTEMPTS) failPrepared(tx, p, now)
            Failure.UNAUTHORIZED, Failure.REJECTED -> failPrepared(tx, p, now)
            Failure.MALFORMED -> malformed(tx, p, now)
        }
    }

    // ------------------------------------------------------------------ shared transitions

    /** Stores issued tokens with their (kind, epoch, slot) from the layout order (§11.7). */
    fun storeTokens(tx: SyncTransaction, order: List<Position>, tokens: List<TorIssuerTransport.IssuedToken>, eligibleMinute: Long) {
        order.forEachIndexed { i, pos ->
            val t = tokens[i]
            c.tokens.insertFresh(tx, t.nullifier(), Kinds.code(pos.kind), pos.epoch, pos.slot, t.token(), eligibleMinute)
        }
    }

    /**
     * A prepared flow closes as failed; credits reserved for it return to fresh (the one release path,
     * §11.3). A credits flow whose sends were all ambiguous also ends here once its retry is spent: a
     * release loses those credits only if the issuer did record the invoice (they come back
     * `CREDITS_SPENT` when next presented), a deletion would lose them in every case.
     */
    fun failPrepared(tx: SyncTransaction, p: PurchaseRow, now: Long) {
        c.purchases.terminal(tx, p.id(), PurchaseStore.PREPARED, PurchaseStore.FAILED, Grid.day(now))
        if (p.payWith == PurchaseStore.CREDITS) c.tokens.releaseCredits(tx, TokenStore.FOR_PURCHASE, p.id())
    }

    /** An invoiced pack ends; a credits-paid invoice spent its credits at the issuer, so they are deleted. */
    private fun endInvoiced(tx: SyncTransaction, p: PurchaseRow, to: String, now: Long) {
        c.purchases.terminal(tx, p.id(), PurchaseStore.INVOICED, to, Grid.day(now))
        if (p.payWith == PurchaseStore.CREDITS) c.tokens.deleteReservedCredits(tx, TokenStore.FOR_PURCHASE, p.id())
    }

    /** A malformed answer (§5.7): one identical retry, then `failed` and `ISSUER_MISMATCH`; never re-blinding. */
    fun malformed(tx: SyncTransaction, p: PurchaseRow, now: Long) {
        if (c.memory.firstMalformed(p.id())) {
            if (p.state == PurchaseStore.INVOICED) afterNonFinal(tx, p, now)
            return
        }
        c.alarm(tx, StateStore.ALARM_ISSUER_MISMATCH)
        when (p.state) {
            PurchaseStore.PREPARED -> failPrepared(tx, p, now)
            PurchaseStore.INVOICED -> endInvoiced(tx, p, PurchaseStore.FAILED, now)
        }
    }

    /**
     * `WRONG_PERIOD` (§5.3): the issuer recorded nothing, so the flow closes as `failed` and, in the same
     * transaction, a new prepared flow starts with a new seed (and claim key) and the current week;
     * reserved credits return to fresh. A trial keeps its invite token and its scheduling (§8.3).
     */
    fun rePrepare(tx: SyncTransaction, p: PurchaseRow, now: Long) {
        failPrepared(tx, p, now)
        val week = Grid.week(now)
        val pack = p.kind == PurchaseStore.PACK
        val product = if (pack) Layouts.packProduct(p.payWith == PurchaseStore.XMR) else EntitlementCrypto.PRODUCT_TRIAL
        val layout = c.crypto.layout(product, week)
        val nextDue = if (!pack && p.nextDueMinute != null) Time.floorMinute(now) else null
        c.purchases.insert(
            tx, c.random.bytes(EngineContext.ID_BYTES), p.kind, p.payWith, c.random.bytes(EngineContext.SECRET_BYTES),
            if (pack) c.random.bytes(EngineContext.SECRET_BYTES) else null, if (pack) null else p.inputToken(), week, c.summary.seq,
            layout.digest(), Time.floorHour(now), nextDue,
        )
    }

    /**
     * Local transitions that need no call, at the start of a quiet run: an invoice whose five attempts
     * are used up is `lost` (or `expired`), a prepared flow over its cap `failed`. Flows with a call
     * in flight are left alone.
     */
    fun settle(now: Long) = c.tx { tx ->
        for (p in c.purchases.live(tx)) {
            if (c.memory.inFlight(p.id())) continue
            when {
                p.kind == PurchaseStore.PACK && p.state == PurchaseStore.INVOICED && p.attempt >= RetryPolicy.BLIND_SIGN_ATTEMPTS ->
                    endInvoiced(tx, p, lostOrExpired(p), now)
                p.kind == PurchaseStore.PACK && p.state == PurchaseStore.PREPARED && p.attempt >= RetryPolicy.CALL_ATTEMPTS ->
                    failPrepared(tx, p, now)
                p.kind == PurchaseStore.REFRESH && p.state == PurchaseStore.PREPARED && p.attempt >= RetryPolicy.CALL_ATTEMPTS ->
                    failPrepared(tx, p, now)
            }
        }
    }

    /**
     * `cancel` (§11.2, §11.4): an XMR pack whose payment instructions were never shown; a credits pack
     * only before its first send. A credits pack's `RequestInvoice` is its payment: once it left the
     * device the issuer may hold a confirmed invoice for those credits, which only the identical retry
     * recovers, and an invoiced credits pack is paid (it never gets payment instructions).
     */
    fun cancel(id: ByteArray, now: Long): Boolean = c.tx { tx ->
        val p = c.purchases.get(tx, id)
        when {
            p == null || p.kind != PurchaseStore.PACK || !p.live || p.shown || c.memory.inFlight(id) -> false
            p.payWith == PurchaseStore.CREDITS && p.sent -> false
            p.state == PurchaseStore.PREPARED -> {
                failPrepared(tx, p, now)
                true
            }
            else -> {
                endInvoiced(tx, p, PurchaseStore.FAILED, now)
                true
            }
        }
    }

    override fun toString(): String = "PurchaseSteps"

    private companion object {
        val CLAIM_LABEL = "ghost/v1/issuer-claim".toByteArray(Charsets.US_ASCII)
        const val NEEDED_REQUEST_DELAY: Long = 24 * Grid.HOUR
        const val MASK_BITS = 64
    }
}
