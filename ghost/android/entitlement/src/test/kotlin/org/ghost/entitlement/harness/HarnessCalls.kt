package org.ghost.entitlement.harness

import org.ghost.entitlement.engine.Grid
import org.ghost.entitlement.engine.Position
import org.ghost.entitlement.engine.RedeemPlanner
import org.ghost.network.EntitlementCrypto
import org.ghost.network.NetworkException
import org.ghost.network.OnionAddress
import org.ghost.network.TorIssuerTransport
import org.ghost.network.TorRelayTransport
import org.ghost.sync.api.NamespaceId
import org.ghost.sync.harness.CallInfo
import org.ghost.sync.harness.CallKind
import org.ghost.sync.harness.EventKind
import org.ghost.sync.harness.Fault
import org.ghost.sync.port.EntitlementCalls

/**
 * The native layer of the harness (design §10.9, §11.7): what `TorRelayTransport.redeem` and
 * `TorIssuerTransport` do in Rust around a call, over the [ModelRedeemRelay]s and the [ModelIssuer]:
 * the checks before any I/O (a token bound by the schedule to this relay's slot in its week, a
 * layout digest that matches the recomputed layout: `invalid_argument`), seed-derived blinding
 * (`TestTokenCrypto`), and the validation of every answer (capability v2 fields, `relay_period_id`
 * within ±1 week, the ES price and subaddress, `s'^e ≡ B` and PSS for every signature:
 * `malformed_response`). Each call has the three events of the harness bus (design §13.2
 * "FaultyIssuerPort and FaultyRedeemPort": fail before, succeed but lose the response, succeed), so a
 * fault plan can crash the process or fail the call at each, and the scenario's relay hook runs there.
 */
internal class HarnessCalls(private val owner: EntClient) : EntitlementCalls {
    private val ent: EntWorld get() = owner.ent
    private val schedule: TestSchedule get() = owner.ent.schedule
    private var issuerCalls = 0

    /** Runs at every issuer call that reaches this layer (the quiet run counts them, J9). */
    var onIssuerCall: (() -> Unit)? = null

    private fun fail(category: String): Nothing = throw NetworkException(category)

    private fun event(kind: EventKind, info: CallInfo): String? {
        val planned = when (val f = owner.c.bus.event(kind, info)) {
            null -> null
            is Fault.Network -> f.category
            is Fault.Interleave -> {
                f.action()
                null
            }
            is Fault.Crash -> error("crash faults are thrown by the bus")
        }
        return planned ?: owner.w.relayHook?.invoke(owner.c, kind, info)
    }

    // ------------------------------------------------------------------ redemption

    /** The week of an ACCESS token whose challenge names a slot the schedule assigns to [relay] then, or null. */
    private fun boundWeek(token: ByteArray, relay: OnionAddress): Long? {
        if (token.size != TestSchedule.TOKEN_BYTES || token[0] != 0.toByte() || token[1] != 2.toByte()) return null
        val key = schedule.keyById(token.copyOfRange(66, 98)) ?: return null
        if (key.kind != EntitlementCrypto.KIND_ACCESS) return null
        val digest = token.copyOfRange(34, 66)
        val slots = RedeemPlanner.slotsFor(schedule.summary, relay, key.epoch)
        return key.epoch.takeIf { slots.any { s -> schedule.challengeDigest(EntitlementCrypto.KIND_ACCESS, key.epoch, s).contentEquals(digest) } }
    }

    override fun redeem(relay: OnionAddress, namespace: ByteArray, token: ByteArray, requestId: ByteArray, deadlineMillis: Int): TorRelayTransport.RedeemAnswer {
        require(namespace.size == 32 && requestId.size == 16) { "redeem arguments out of range" }
        val w = owner.w
        val c = owner.c
        val nullifier = Bytes.hex(if (token.size >= TestSchedule.TOKEN_INPUT_BYTES) TestSchedule.nullifier(token) else Bytes.sha256(token))
        val nsHex = Bytes.hex(namespace)
        ent.records.present(nullifier, "$relay|$nsHex")
        ent.records.secrets += Bytes.hex(token)
        // Before any I/O: a token bound elsewhere never leaves the device (0 requests).
        val week = boundWeek(token, relay)
        if (week == null) {
            ent.records.refused += nullifier
            fail("invalid_argument")
        }
        val node = w.node(relay)
        val model = ent.redeemRelay(node) ?: fail("invalid_argument")
        val info = CallInfo(CallKind.REDEEM, node.name, nsHex, listOf(nullifier))
        event(EventKind.RELAY_BEFORE_SEND, info)?.let { fail(it) }
        if (c.offline()) fail("transport")
        if (!node.reachable) fail(node.unreachableCategory)
        // Every byte of the RedeemToken request a relay observes: token, namespace and request id (NI-1, P-3).
        ent.records.relayLog += "t=${w.clock.millis}|redeem|${node.name}|$nsHex|${Bytes.hex(token)}|${Bytes.hex(requestId)}"
        val first = c.transport.circuits.add("work|${node.name}|$nsHex")
        val latency = w.latency.of(c.name, node.name, NamespaceId(namespace), CallKind.REDEEM, w.clock.millis, first)
        val arrives = latency <= deadlineMillis || latency / 2 <= deadlineMillis
        w.clock.advance(minOf(latency, deadlineMillis.toLong()))
        val answer = if (arrives) model.redeem(token, namespace, requestId, w.relayNow(node)) else null
        (answer?.result as? ModelRedeemRelay.Result.Ok)?.let { ent.records.minted[Bytes.hex(it.capability)] = nullifier }
        ent.records.bump()
        event(EventKind.RELAY_AFTER_APPLY, info)?.let { fail(it) }
        if (answer == null || latency > deadlineMillis) fail("timeout")
        if (Math.abs(answer.relayPeriod - Grid.week(w.clock.epochSeconds())) > 1) fail("malformed_response")
        val out = when (val r = answer.result) {
            is ModelRedeemRelay.Result.Ok -> {
                val cap = r.capability
                val expiry = Grid.start(week + 1) + 3_600
                val ok = cap.size == TorRelayTransport.CAPABILITY_V2_BYTES && cap[0] == 2.toByte() && cap[1] == 2.toByte() &&
                    cap.copyOfRange(2, 34).contentEquals(namespace) &&
                    java.nio.ByteBuffer.wrap(cap, 34, 8).long == schedule.constants.capabilityQuotaBytes &&
                    java.nio.ByteBuffer.wrap(cap, 42, 8).long == expiry
                if (!ok) fail("malformed_response")
                TorRelayTransport.RedeemAnswer(TorRelayTransport.REDEEM_OK, answer.relayPeriod, answer.relayMinute, expiry, cap)
            }
            ModelRedeemRelay.Result.Replayed -> TorRelayTransport.RedeemAnswer(TorRelayTransport.REDEEM_REPLAYED, answer.relayPeriod, answer.relayMinute, 0, null)
            ModelRedeemRelay.Result.WrongPeriod -> TorRelayTransport.RedeemAnswer(TorRelayTransport.REDEEM_WRONG_PERIOD, answer.relayPeriod, answer.relayMinute, 0, null)
            is ModelRedeemRelay.Result.Denied -> {
                if (r.status == ModelRedeemRelay.REJECTED_TOKEN) ent.records.refused += nullifier
                fail(r.category)
            }
        }
        event(EventKind.RELAY_AFTER_RESPONSE, info)?.let { fail(it) }
        return out
    }

    // ------------------------------------------------------------------ issuer calls

    /** One issuer call with its three events; [call] reaches the model at the issuer's clock, [map] validates. */
    private fun <T, R> issuer(name: String, flow: ByteArray, requestBytes: Int, call: (Long) -> ModelIssuer.Reply<T>, map: (T) -> R): R {
        val w = owner.w
        val index = issuerCalls++
        onIssuerCall?.invoke()
        ent.records.issuerLog += "t=${w.clock.millis}|$name|flow=${owner.flowIndex(flow)}|req=$requestBytes"
        val info = CallInfo(CallKind.ISSUER, ISSUER, "", emptyList())
        event(EventKind.RELAY_BEFORE_SEND, info)?.let { fail(it) }
        if (owner.c.offline()) fail("transport")
        w.clock.advance(ent.config.issuerLatencyMillis(index))
        if (ent.config.issuerUnavailable(index)) fail("relay_unavailable")
        ent.issuer.tickIfStale(ent.issuerNow())
        val reply = call(ent.issuerNow())
        ent.records.bump()
        event(EventKind.RELAY_AFTER_APPLY, info)?.let { fail(it) }
        val value = when (reply) {
            is ModelIssuer.Reply.Err -> fail(reply.category)
            is ModelIssuer.Reply.Ok -> reply.value
        }
        val out = map(value)
        event(EventKind.RELAY_AFTER_RESPONSE, info)?.let { fail(it) }
        return out
    }

    /** The positions of [product] at [index] if they match [layoutDigest] and [positions] (checked before any I/O). */
    private fun layout(product: Int, index: Long, layoutDigest: ByteArray, positions: Int): List<Position> {
        val list = schedule.positions(product, index) ?: fail("invalid_argument")
        if (list.size != positions || !Batch.layoutDigest(list).contentEquals(layoutDigest)) fail("invalid_argument")
        return list
    }

    /** Records every token finalized from an answer; an invoice's own ([invoice]) also on its model invoice (MS-6). */
    private fun issued(list: List<Position>, tokens: List<ByteArray>, invoice: ByteArray?): List<TorIssuerTransport.IssuedToken> {
        val finalized = invoice?.let { ent.issuer.invoice(it)?.finalized }
        return tokens.mapIndexed { i, t ->
            val n = TestSchedule.nullifier(t)
            val hex = Bytes.hex(n)
            // Part of the crash digest: a crash after this answer was validated leaves other records.
            if (ent.records.issued.putIfAbsent(hex, EntRecords.Issued(list[i].kind, list[i].epoch, invoice?.let(Bytes::hex))) == null) ent.records.bump()
            finalized?.add(hex)
            ent.records.secrets += Bytes.hex(t)
            TorIssuerTransport.IssuedToken(n, t)
        }
    }

    override fun requestInvoice(flow: ByteArray, claimHash: ByteArray, credits: List<ByteArray>, baseWeek: Long, deadlineMillis: Int): TorIssuerTransport.InvoiceAnswer =
        issuer("requestInvoice", flow, 32 + 8 + credits.size * TestSchedule.TOKEN_BYTES, { now -> ent.issuer.requestInvoice(claimHash, credits, baseWeek, now) }) { a ->
            val xmr = credits.isEmpty()
            val amount = if (a.result == TorIssuerTransport.INVOICE_OK && xmr) a.amount + ent.config.issuerAmountOffset else a.amount
            when (a.result) {
                TorIssuerTransport.INVOICE_OK -> {
                    val id = a.invoiceId()
                    if (id.all { it == 0.toByte() }) fail("malformed_response")
                    val price = schedule.price(Grid.priceEpoch(baseWeek))
                    val subaddressOk = if (xmr) a.subaddress != null && HarnessAddresses.type(a.subaddress) == '7' else a.subaddress == null
                    val amountOk = if (xmr) !ent.config.nativeChecksAmounts || amount == price else amount == 0L
                    if (!subaddressOk || !amountOk) fail("malformed_response")
                    ent.records.secrets += Bytes.hex(id)
                    TorIssuerTransport.InvoiceAnswer(a.result, id, amount, a.subaddress, 0)
                }
                TorIssuerTransport.INVOICE_CREDITS_SPENT -> {
                    if (a.spentMask == 0L || (credits.size < 64 && a.spentMask ushr credits.size != 0L)) fail("malformed_response")
                    TorIssuerTransport.InvoiceAnswer(a.result, ByteArray(16), 0, null, a.spentMask)
                }
                else -> TorIssuerTransport.InvoiceAnswer(a.result, ByteArray(16), 0, null, 0)
            }
        }

    override fun blindSign(
        flow: ByteArray,
        invoiceId: ByteArray,
        claimKey: ByteArray,
        seed: ByteArray,
        product: Int,
        baseWeek: Long,
        layoutDigest: ByteArray,
        positions: Int,
        deadlineMillis: Int,
    ): TorIssuerTransport.SignAnswer {
        val list = layout(product, baseWeek, layoutDigest, positions)
        ent.records.secrets += Bytes.hex(seed)
        ent.records.secrets += Bytes.hex(claimKey)
        val blinded = Batch.blind(schedule, seed, list)
        return issuer("blindSign", flow, 16 + 32 + blinded.size, { now -> ent.issuer.blindSign(invoiceId, claimKey, blinded, now) }) { a ->
            if (a.state == TorIssuerTransport.STATE_SIGNED) {
                val tokens = Batch.finalize(schedule, seed, list, a.signatures) ?: fail("malformed_response")
                ent.records.finalizedAt += owner.w.clock.epochSeconds()
                TorIssuerTransport.SignAnswer(a.state, a.credited, a.seen, issued(list, tokens, invoiceId))
            } else {
                TorIssuerTransport.SignAnswer(a.state, a.credited, a.seen, emptyList())
            }
        }
    }

    override fun invoiceStatus(flow: ByteArray, invoiceId: ByteArray, claimKey: ByteArray, deadlineMillis: Int): TorIssuerTransport.StatusAnswer =
        issuer("invoiceStatus", flow, 48, { _ -> ent.issuer.invoiceStatus(invoiceId, claimKey) }) { a -> TorIssuerTransport.StatusAnswer(a.state, a.credited, a.seen) }

    override fun redeemInvite(
        flow: ByteArray,
        inviteToken: ByteArray,
        seed: ByteArray,
        baseWeek: Long,
        layoutDigest: ByteArray,
        positions: Int,
        deadlineMillis: Int,
    ): TorIssuerTransport.TrialAnswer {
        val list = layout(EntitlementCrypto.PRODUCT_TRIAL, baseWeek, layoutDigest, positions)
        ent.records.secrets += Bytes.hex(seed)
        val blinded = Batch.blind(schedule, seed, list)
        return issuer("redeemInvite", flow, TestSchedule.TOKEN_BYTES + 8 + blinded.size, { now -> ent.issuer.redeemInvite(inviteToken, baseWeek, blinded, now) }) { a ->
            if (a.result == TorIssuerTransport.TRIAL_OK) {
                val tokens = Batch.finalize(schedule, seed, list, a.signatures) ?: fail("malformed_response")
                TorIssuerTransport.TrialAnswer(a.result, issued(list, tokens, null))
            } else {
                TorIssuerTransport.TrialAnswer(a.result, emptyList())
            }
        }
    }

    override fun claimPayout(flow: ByteArray, claimId: ByteArray, credits: List<ByteArray>, payoutAddress: String, deadlineMillis: Int): TorIssuerTransport.ClaimAnswer =
        issuer("claimPayout", flow, 16 + credits.size * TestSchedule.TOKEN_BYTES + payoutAddress.length, { now -> ent.issuer.claimPayout(claimId, credits, payoutAddress, now) }) { a ->
            if (a.result == TorIssuerTransport.CLAIM_QUEUED && a.queued <= 0) fail("malformed_response")
            if (a.result == TorIssuerTransport.CLAIM_CREDITS_SPENT && (a.spentMask == 0L || (credits.size < 64 && a.spentMask ushr credits.size != 0L))) {
                fail("malformed_response")
            }
            TorIssuerTransport.ClaimAnswer(a.result, a.queued, a.spentMask)
        }

    override fun refreshCredit(flow: ByteArray, receivedCredit: ByteArray, seed: ByteArray, layoutDigest: ByteArray, deadlineMillis: Int): TorIssuerTransport.RefreshAnswer {
        val epoch = schedule.verify(receivedCredit, EntitlementCrypto.KIND_CREDIT, ignoreRevocation = true)?.epoch ?: fail("invalid_argument")
        val list = layout(EntitlementCrypto.PRODUCT_REFRESH, epoch, layoutDigest, 1)
        ent.records.secrets += Bytes.hex(seed)
        val blinded = Batch.blind(schedule, seed, list)
        return issuer("refreshCredit", flow, TestSchedule.TOKEN_BYTES + blinded.size, { now -> ent.issuer.refreshCredit(receivedCredit, blinded, now) }) { a ->
            if (a.result == TorIssuerTransport.REFRESH_OK) {
                val tokens = Batch.finalize(schedule, seed, list, a.signature) ?: fail("malformed_response")
                TorIssuerTransport.RefreshAnswer(a.result, issued(list, tokens, null).single())
            } else {
                TorIssuerTransport.RefreshAnswer(a.result, null)
            }
        }
    }

    override fun endFlow(flow: ByteArray) = Unit

    override fun toString(): String = "HarnessCalls"

    companion object {
        const val ISSUER = "issuer"
    }
}
