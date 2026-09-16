package org.ghost.entitlement.harness

import org.ghost.entitlement.api.PayWith
import org.ghost.entitlement.port.TokenCryptoPort
import org.ghost.network.EntitlementCrypto
import org.ghost.sync.harness.CallKind
import org.ghost.sync.harness.EventKind
import org.ghost.sync.harness.Mutation
import org.ghost.sync.harness.World
import org.ghost.sync.harness.World.Companion.HOUR
import org.ghost.sync.harness.World.Companion.MINUTE
import org.ghost.sync.harness.foreground
import org.ghost.sync.store.Time

/**
 * A client mutant of Phase 8 design §13.5, implemented in test sources only: rewrites of the armed
 * client's SQL statements (the Phase 7 [Mutation] mechanism) and substitutions of the harness
 * configuration (the quiet-run decision, the token-crypto port, the schedule's counts). The engine
 * itself has no seam for any of them.
 */
internal class EntMutant(
    val name: String,
    val mutation: Mutation? = null,
    /** The configuration a world runs with under this mutant, from its own and the subject's namespace count. */
    val configure: ((EntConfig, Int) -> EntConfig)? = null,
) {
    override fun toString(): String = "EntMutant($name)"
}

/**
 * The client mutants EM1–EM9 of design §13.5, the NI-K-caught privacy mutants M3, M8 and M20, four
 * fixtures of the S9c review that pin what the harness checks beyond them (MS-6 for issued and
 * never-delivered invoices, the accounting of every finalized kind, every redemption byte in NI-1),
 * and one of the restore-scan review (every credit sealed into a listened drop ends refreshed), each
 * detected by `EntitlementMutantDetectionTest` in the world named there.
 */
internal object EntMutants {
    private const val PURCHASE_ATTEMPT = "UPDATE ent_purchase SET sent = 1, attempt = ?1, next_due_minute = ?2 WHERE"
    private const val CLAIM_ATTEMPT = "UPDATE ent_claim SET sent = 1, attempt = ?1, next_due_minute = ?2 WHERE"
    private const val RESERVATION_DELETE = "DELETE FROM ent_token WHERE nullifier = ?1 AND state = 'reserved' AND reserved_for = 'relay' AND request_id = ?2"
    private const val RESERVATION_LOOKUP = "reserved_for = 'relay' AND reserved_relay = ?1 AND reserved_namespace = ?2 AND epoch = ?3"
    private const val TOKEN_INSERT = "INSERT INTO ent_token("
    private const val PURCHASE_COLUMNS = "state, seed, claim_key, invoice_id"
    private const val RESERVE_REQUEST_ID = "request_id = ?3 WHERE nullifier = ?4 AND kind = 'access' AND state = 'fresh'"

    /** What the hostile issuer of EM8 states above the ES price, in atomic units. */
    const val HOSTILE_OFFSET = 1_000_000L

    /** A mutation that rewrites the statements [f] maps (null: unchanged). */
    private fun rewrite(f: (World, String, List<Any?>) -> Pair<String, List<Any?>>?): Mutation =
        Mutation(rewrite = { w -> { sql, args -> f(w, sql, args) ?: Pair(sql, args) } })

    /** EM1 NewSeedOnRetry: a retried call re-blinds with a new seed. */
    val EM1 = EntMutant("EM1 NewSeedOnRetry", rewrite { _, sql, args ->
        if (sql.startsWith(PURCHASE_ATTEMPT)) Pair(sql.replace("SET sent = 1,", "SET sent = 1, seed = CASE WHEN ?5 > 0 THEN zeroblob(32) ELSE seed END,"), args) else null
    })

    /** EM2 ReleaseReservation: a relay reservation ends by returning the token to fresh. */
    val EM2 = EntMutant("EM2 ReleaseReservation", rewrite { _, sql, args ->
        if (sql == RESERVATION_DELETE) {
            Pair(
                "UPDATE ent_token SET state = 'fresh', reserved_for = NULL, reserved_relay = NULL, reserved_namespace = NULL, request_id = NULL " +
                    "WHERE nullifier = ?1 AND state = 'reserved' AND reserved_for = 'relay' AND request_id = ?2",
                args,
            )
        } else {
            null
        }
    })

    /**
     * EM3 PutOutsideTx: the token's deletion leaves the transaction that installs the capability. Here
     * it never runs; the commit check fires at the capability's commit, where a deletion in a later
     * transaction is caught just the same (a crash between the two would leave this world).
     */
    val EM3 = EntMutant("EM3 PutOutsideTx", rewrite { _, sql, args ->
        if (sql == RESERVATION_DELETE) Pair("DELETE FROM ent_token WHERE 0 AND nullifier = ?1 AND request_id = ?2", args) else null
    })

    /** EM4 RedeemOtherRelayOnTimeout: the pending reservation of the week is taken for any relay and namespace. */
    val EM4 = EntMutant("EM4 RedeemOtherRelayOnTimeout", rewrite { _, sql, args ->
        if (sql.contains(RESERVATION_LOOKUP)) Pair(sql.replace(RESERVATION_LOOKUP, "reserved_for = 'relay' AND ?1 IS NOT NULL AND ?2 IS NOT NULL AND epoch = ?3"), args) else null
    })

    /**
     * EM5 SendBeforeWriteAhead: the claim key the first `RequestInvoice` carries is not the one
     * persisted (as when it is written after the send and a crash loses the one sent): every read of
     * an unsent pack sees another key than the stored one.
     */
    val EM5 = EntMutant("EM5 SendBeforeWriteAhead", rewrite { _, sql, args ->
        if (sql.startsWith("SELECT ") && sql.contains("FROM ent_purchase") && sql.contains(PURCHASE_COLUMNS)) {
            Pair(sql.replace(PURCHASE_COLUMNS, "state, seed, CASE WHEN sent = 0 AND kind = 'pack' THEN zeroblob(32) ELSE claim_key END, invoice_id"), args)
        } else {
            null
        }
    })

    /**
     * EM6 WipeBeforeFinalize: the finalizing transaction wipes the secrets while the tokens go to a
     * later write that never happens (a crash between the two): the inserts land in a side table.
     */
    val EM6 = EntMutant("EM6 WipeBeforeFinalize", rewrite { w, sql, args ->
        if (sql.startsWith(TOKEN_INSERT) && (args[5] as Number).toLong() > Time.floorMinute(w.clock.epochSeconds())) {
            Pair(sql.replace(TOKEN_INSERT, "INSERT INTO em6_pending("), args)
        } else {
            null
        }
    })

    /** EM7 LayoutChangedAfterSend: a retried call carries another layout digest. */
    val EM7 = EntMutant("EM7 LayoutChangedAfterSend", rewrite { _, sql, args ->
        if (sql.startsWith(PURCHASE_ATTEMPT)) Pair(sql.replace("SET sent = 1,", "SET sent = 1, layout_digest = CASE WHEN ?5 > 0 THEN zeroblob(32) ELSE layout_digest END,"), args) else null
    })

    /**
     * The hostile-issuer mode of EM8 (not a mutant): the issuer states more than the ES price and the
     * native layer's own check is off, so the Kotlin engine alone decides.
     */
    val HOSTILE_ISSUER = EntMutant("hostile issuer", configure = { c, _ -> c.copy(issuerAmountOffset = HOSTILE_OFFSET, nativeChecksAmounts = false) })

    /** EM8 TrustIssuerAmount: the engine takes the issuer's amount (its price table follows the issuer). */
    val EM8 = EntMutant("EM8 TrustIssuerAmount", configure = { c, _ ->
        c.copy(issuerAmountOffset = HOSTILE_OFFSET, nativeChecksAmounts = false, cryptoFor = { base -> PriceFollowingCrypto(base, HOSTILE_OFFSET) })
    })

    /** EM9 ClaimAddressChangedOnRetry: a retried claim carries another payout address. */
    val EM9 = EntMutant("EM9 ClaimAddressChangedOnRetry", rewrite { _, sql, args ->
        if (sql.startsWith(CLAIM_ATTEMPT)) Pair(sql.replace("SET sent = 1,", "SET sent = 1, payout_address = CASE WHEN ?4 > 0 THEN payout_address || '0' ELSE payout_address END,"), args) else null
    })

    /** M3 ImmediateEligible: pack tokens are usable at finalization. */
    val M3 = EntMutant("M3 ImmediateEligible", rewrite { w, sql, args ->
        val now = Time.floorMinute(w.clock.epochSeconds())
        if (sql.startsWith(TOKEN_INSERT) && args[1] == "access" && (args[5] as Number).toLong() > now) Pair(sql, args.toMutableList().also { it[5] = now }) else null
    })

    /** M8 VariableCounts: the pack's token count grows with the client's namespaces. */
    val M8 = EntMutant("M8 VariableCounts", configure = { c, namespaces -> c.copy(accessPerSlot = c.accessPerSlot + maxOf(0, namespaces - NiWorld.BASE_NAMESPACES)) })

    /** M20 QuietWhenWorkDue: a quiet run is forced whenever a `BlindSign` is due. */
    val M20 = EntMutant("M20 QuietWhenWorkDue", configure = { c, _ -> c.copy(quietOverride = { ec, _, drawn -> drawn || blindSignDue(ec) }) })

    /**
     * GiveUpAfterLostSign (S9c review): the first `BlindSign` write-ahead spends the whole attempt
     * plan, so a signed answer that is lost is never retried: a paid invoice ends issued at the
     * issuer and `lost` at the client, without its tokens (MS-6).
     */
    val GIVE_UP_AFTER_LOST_SIGN = EntMutant("GiveUpAfterLostSign", rewrite { _, sql, args ->
        if (sql.startsWith(PURCHASE_ATTEMPT)) Pair(sql.replace("attempt = ?1,", "attempt = CASE WHEN ?4 = 'invoiced' THEN 5 ELSE ?1 END,"), args) else null
    })

    /**
     * NoRequestInvoiceRetry (S9c review): the first `RequestInvoice` write-ahead spends both capped
     * attempts, so an answer that is lost is never retried identically: a credits invoice the issuer
     * confirmed never reaches the client and its credits are lost while a retry was allowed (MS-6).
     */
    val NO_REQUEST_INVOICE_RETRY = EntMutant("NoRequestInvoiceRetry", rewrite { _, sql, args ->
        if (sql.startsWith(PURCHASE_ATTEMPT)) Pair(sql.replace("attempt = ?1,", "attempt = CASE WHEN ?4 = 'prepared' THEN 2 ELSE ?1 END,"), args) else null
    })

    /**
     * LoseCreditAndInviteTokens (S9c review): the CREDIT and INVITE tokens of a finalized batch never
     * reach `ent_token` (their inserts land in EM6's side table): the token accounting of design
     * §13.2 covers every finalized kind, not only ACCESS.
     */
    val LOSE_CREDIT_AND_INVITE_TOKENS = EntMutant("LoseCreditAndInviteTokens", rewrite { _, sql, args ->
        if (sql.startsWith(TOKEN_INSERT) && (args[1] == "credit" || args[1] == "invite")) Pair(sql.replace(TOKEN_INSERT, "INSERT INTO em6_pending("), args) else null
    })

    /**
     * RequestIdFromIssuerState (S9c review): a redemption's `request_id` is the token's nullifier prefix
     * while a purchase is still unanswered, so the relays learn whether the issuer answered the first
     * `RequestInvoice` (NI-1 covers every byte a relay observes, P-3).
     */
    val REQUEST_ID_FROM_ISSUER_STATE = EntMutant("RequestIdFromIssuerState", rewrite { _, sql, args ->
        if (sql.contains(RESERVE_REQUEST_ID)) {
            Pair(sql.replace("request_id = ?3", "request_id = CASE WHEN (SELECT count(*) FROM ent_purchase WHERE state = 'prepared') > 0 THEN substr(?4, 1, 16) ELSE ?3 END"), args)
        } else {
            null
        }
    })

    /**
     * LoseReceivedDropCredit (restore-scan review RS-4): the blob of a listened drop is taken for a blob
     * of a closed one, so the credit an invitee sealed to it is consumed unread. The harness accounts
     * every credit a scenario seals into a drop of its subject, in each crash run as well, not only
     * in a scenario's fault-free outcome check.
     */
    val LOSE_RECEIVED_DROP_CREDIT = EntMutant("LoseReceivedDropCredit", rewrite { _, sql, args ->
        if (sql == INVITE_BY_NAMESPACE) Pair("$sql AND 0", args) else null
    })

    private const val INVITE_BY_NAMESPACE =
        "SELECT invite_index, state, payload, drop_namespace, listen_until_day, refresh_minute FROM ent_invite WHERE drop_namespace = ?1"

    private fun blindSignDue(ec: EntClient): Boolean {
        var n = 0L
        ec.c.jdbc.query(
            "SELECT count(*) FROM ent_purchase WHERE kind = 'pack' AND state = 'invoiced' AND attempt < 5 AND next_due_minute <= ?1",
            listOf(Time.floorMinute(ec.w.clock.epochSeconds())),
        ) { n = it.long(0) }
        return n > 0
    }

    /** EM6's side table: temporary, on the client's one connection, outside the schema. */
    fun em6Setup(e: EntClient) = e.c.jdbc.exec(
        "CREATE TEMP TABLE IF NOT EXISTS em6_pending(nullifier BLOB, kind TEXT, epoch INTEGER, slot INTEGER, token BLOB, state TEXT, eligible_minute INTEGER)",
        emptyList(),
    )
}

/**
 * EM8's token-crypto port: the schedule summary's prices follow what the hostile issuer states, so a
 * mutant engine that believes an issuer amount finds it equal to "the ES price"; everything else is
 * the [TestTokenCrypto] of the world.
 */
internal class PriceFollowingCrypto(base: TestTokenCrypto, offset: Long) : TokenCryptoPort by base {
    private val shifted = base.schedule.let { s -> TestSchedule(s.accessPerSlot, s.trialPerSlot, s.slots, s.revoked, s.prices.mapValues { it.value + offset }, s.seq) }

    override fun scheduleSummary(): EntitlementCrypto.ScheduleSummary = shifted.summary

    override fun toString(): String = "PriceFollowingCrypto"
}

/**
 * EM4's world: E-A, where relay A's redemptions time out after the relay applied them until a second
 * namespace, on B and C, needs capabilities: the real engine retries A identically and redeems fresh
 * tokens for the new namespace; the mutant presents A's reserved token there (RED-2).
 */
internal class ScenarioEM4 : ScenarioEA() {
    override fun build(w: World) {
        super.build(w)
        val (a, b, c) = Triple(w.relays[0], w.relays[1], w.relays[2])
        val dm2 = alice.c.namespace("dm2", listOf(b, c), listen = false)
        val dm2Hex = Bytes.hex(dm2.toByteArray())
        var dm2Seen = false
        w.relayHook = { client, kind, info ->
            if (client === alice.c && info.kind == CallKind.REDEEM && info.namespace == dm2Hex && !dm2Seen) {
                dm2Seen = true
                w.scriptState++
            }
            if (client === alice.c && kind == EventKind.RELAY_AFTER_APPLY && info.kind == CallKind.REDEEM && info.relay == a.name && !dm2Seen) "timeout" else null
        }
        w.at(22 * HOUR + 36 * MINUTE, "enqueue op2") { alice.c.enqueue("op2", dm2) }
        w.foreground(alice.c, 22 * HOUR + 50 * MINUTE, 23 * HOUR + 20 * MINUTE)
        w.endMillis = 23 * HOUR + 30 * MINUTE
    }
}

/** EM6's world (and LoseCreditAndInviteTokens'): E-A without writes, with EM6's side table. */
internal class ScenarioEM6 : ScenarioEA(writes = false) {
    override fun build(w: World) {
        super.build(w)
        EntMutants.em6Setup(alice)
    }
}

/**
 * GiveUpAfterLostSign's world: E-A, where the answer of the first `BlindSign` that signs is lost after
 * the issuer applied it (the invoice is ISSUED). The real engine retries at the next planned attempt and
 * gets the identical signatures again; the mutant ends the purchase `lost`.
 */
internal class ScenarioLostSign : ScenarioEA() {
    override fun build(w: World) {
        super.build(w)
        var lost = false
        w.relayHook = { client, kind, info ->
            val signed = ent.issuer.history.values.any { it.state == ModelIssuer.State.ISSUED }
            if (!lost && signed && client === alice.c && kind == EventKind.RELAY_AFTER_APPLY && info.kind == CallKind.ISSUER) {
                lost = true
                w.scriptState++
                "timeout"
            } else {
                null
            }
        }
    }
}

/**
 * NoRequestInvoiceRetry's world: E-D, where the answer of the first `RequestInvoice` is lost after the
 * issuer confirmed the credits invoice. The real engine retries identically a day later and gets the
 * same invoice; the mutant fails the flow at once.
 */
internal class ScenarioLostRequest : ScenarioED() {
    override fun build(w: World) {
        super.build(w)
        var lost = false
        w.relayHook = { client, kind, info ->
            if (!lost && client === alice.c && kind == EventKind.RELAY_AFTER_APPLY && info.kind == CallKind.ISSUER) {
                lost = true
                w.scriptState++
                "timeout"
            } else {
                null
            }
        }
    }
}

/**
 * EM8's world: a pack in XMR against an issuer that states more than the ES price. The real engine
 * refuses the invoice (`malformed_response`, one identical retry, then `failed` and
 * `ISSUER_MISMATCH`); nothing is paid or written.
 */
internal class ScenarioEM8 : EntScenario("EM8/hostile-issuer") {
    override fun build(w: World) {
        standard(w)
        w.purchase(0, PayWith.XMR, listOf(10 * MINUTE))
        for (t in listOf(MINUTE, 45 * MINUTE, 30 * HOUR, 55 * HOUR)) w.quietRunAt(t)
        w.endMillis = 56 * HOUR
    }
}

/**
 * EM9's world: E-H, where the first `ClaimPayout` times out after the issuer queued it, so the claim
 * is retried (identically by the real engine) in a later quiet run.
 */
internal class ScenarioEM9 : ScenarioEH() {
    override fun build(w: World) {
        super.build(w)
        var lost = false
        w.relayHook = { client, kind, info ->
            if (client === alice.c && kind == EventKind.RELAY_AFTER_APPLY && info.kind == CallKind.ISSUER && !lost) {
                lost = true
                w.scriptState++
                "timeout"
            } else {
                null
            }
        }
        for (t in listOf(54 * HOUR, 78 * HOUR)) w.quietRunAt(t)
        w.endMillis = 80 * HOUR
    }
}
