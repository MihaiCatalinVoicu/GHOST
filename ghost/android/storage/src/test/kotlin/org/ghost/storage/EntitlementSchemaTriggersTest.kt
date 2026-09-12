package org.ghost.storage

import org.junit.Assert.assertEquals
import org.junit.Test

/**
 * The 13 state-machine and write-once triggers of migration v3 (Phase 8 design §11.3, §11.4; G-12):
 * each legal transition is accepted, each illegal one is refused with the trigger's message, and the
 * client flows of §11.4 run through them without a refusal.
 */
class EntitlementSchemaTriggersTest {
    private val terminal = listOf("finalized", "expired", "failed", "lost")
    private val purchaseStates = listOf("prepared", "invoiced") + terminal
    private val legalPurchase = mapOf(
        "prepared" to setOf("invoiced", "finalized", "failed"),
        "invoiced" to setOf("finalized", "expired", "failed", "lost"),
    )
    private val frozen = "issuance secrets and layout are frozen once sent"
    private val reservationEnds = "a reservation ends only by deletion"

    @Test
    fun esMemoryIsAppendOnly() = EntitlementFixture().use { f ->
        val db = f.db
        db.exec("INSERT INTO ent_key(kind, epoch, key_id) VALUES ('access', ?, ?)", listOf(WEEK0, hash(1)))
        db.exec("INSERT INTO ent_schedule_fact(fact, epoch, digest) VALUES ('slots', ?, ?)", listOf(WEEK0, hash(2)))
        db.rejects("ent_key is append-only", "UPDATE ent_key SET key_id = ? WHERE kind = 'access'", hash(9))
        db.rejects("ent_key is append-only", "UPDATE ent_key SET key_id = key_id")
        db.rejects("ent_key is append-only", "DELETE FROM ent_key")
        db.rejects("ent_schedule_fact is append-only", "UPDATE ent_schedule_fact SET digest = ?", hash(9))
        db.rejects("ent_schedule_fact is append-only", "DELETE FROM ent_schedule_fact WHERE fact = 'slots'")
        // A remembered (kind, epoch) or fact is never written a second time.
        db.rejects(UNIQUE_FAILED, "INSERT INTO ent_key(kind, epoch, key_id) VALUES ('access', ?, ?)", WEEK0, hash(3))
        db.rejects(UNIQUE_FAILED, "INSERT INTO ent_schedule_fact(fact, epoch, digest) VALUES ('slots', ?, ?)", WEEK0, hash(3))
        // Appending is allowed.
        db.exec("INSERT INTO ent_key(kind, epoch, key_id) VALUES ('access', ?, ?)", listOf(WEEK0 + 1, hash(4)))
        db.exec("INSERT INTO ent_schedule_fact(fact, epoch, digest) VALUES ('price', 223, ?)", listOf(hash(5)))
        assertEquals(2L, db.queryLong("SELECT count(*) FROM ent_key"))
        assertEquals(2L, db.queryLong("SELECT count(*) FROM ent_schedule_fact"))
    }

    /** Puts pack [i] into [state] through legal steps. */
    private fun EntitlementFixture.packIn(i: Int, state: String) {
        purchase(i)
        if (state == "prepared") return
        assertEquals(1, invoice(i))
        if (state == "invoiced") return
        assertEquals(1, terminal(i, state))
    }

    /** The statement moving purchase [i] from [from] to [to], with the columns the target's CHECKs need. */
    private fun moveTo(i: Int, from: String, to: String): Pair<String, List<Any?>> = when {
        from == "prepared" && to == "invoiced" ->
            "UPDATE ent_purchase SET state = 'invoiced', sent = 1, invoice_id = ?, subaddress = ?, amount_atomic = 5, receipt_minute = ? WHERE purchase_id = ?" to
                listOf(bytes(16, 0x70 + i), subaddress(i), T0, purchaseId(i))
        to == "prepared" || to == "invoiced" -> "UPDATE ent_purchase SET state = ? WHERE purchase_id = ?" to listOf(to, purchaseId(i))
        else -> "UPDATE ent_purchase SET state = ?, $TERMINAL_WIPE WHERE purchase_id = ?" to listOf(to, DAY0, purchaseId(i))
    }

    @Test
    fun purchaseTransitionsFollowTheStateMachine() = EntitlementFixture().use { f ->
        var i = 0
        var legalCount = 0
        for (from in purchaseStates) for (to in purchaseStates) {
            i++
            f.packIn(i, from)
            val (sql, args) = moveTo(i, from, to)
            if (from == to || to in legalPurchase[from].orEmpty()) {
                assertEquals("$from -> $to", 1, f.db.execUpdate(sql, args))
                assertEquals(to, f.purchaseState(i))
                legalCount++
            } else {
                f.db.rejects("illegal purchase transition", sql, *args.toTypedArray())
                assertEquals("$from -> $to", from, f.purchaseState(i))
            }
        }
        assertEquals(6 + 3 + 4, legalCount)
    }

    @Test
    fun onlyPacksAreEverInvoiced() = EntitlementFixture().use { f ->
        f.purchase(1, kind = "trial")
        f.purchase(2, kind = "refresh")
        for (i in 1..2) {
            f.rejectsPurchaseUpdate(CHECK_FAILED, i, "state = 'invoiced', sent = 1, invoice_id = ?, amount_atomic = 0, receipt_minute = ?", bytes(16, 9), T0)
        }
        // A trial or a refresh ends directly: prepared -> finalized or failed.
        assertEquals(1, f.terminal(1, "finalized"))
        assertEquals(1, f.terminal(2, "failed"))
    }

    @Test
    fun issuanceSecretsAndLayoutAreFrozenOnceSent() = EntitlementFixture().use { f ->
        f.purchase(1)
        // Before the first send the base week and the layout may be refreshed (a week change, §11.5).
        assertEquals(
            1,
            f.updatePurchase(1, "seed = ?, claim_key = ?, base_week = ?, schedule_seq = 2, layout_digest = ?", bytes(32, 1), bytes(32, 2), WEEK0 + 1, bytes(32, 3)),
        )
        assertEquals(1, f.updatePurchase(1, "sent = 1"))
        val changes = listOf<Pair<String, Any?>>(
            "seed = ?" to bytes(32, 9),
            "seed = ?" to null,
            "claim_key = ?" to bytes(32, 9),
            "base_week = ?" to WEEK0 + 2,
            "schedule_seq = ?" to 3,
            "layout_digest = ?" to bytes(32, 9),
        )
        for ((set, value) in changes) f.rejectsPurchaseUpdate(frozen, 1, set, value)
        f.rejectsPurchaseUpdate(frozen, 1, "sent = 0")
        // Everything else of a live row stays writable, and an unchanged value is no change.
        assertEquals(1, f.updatePurchase(1, "seed = seed, attempt = 1, next_due_minute = ?, prev_state = 2, disclosed = 1, shown = 1", T0 + 3600))
        // Invoiced: still frozen; the finalizing transaction wipes everything at once.
        assertEquals(1, f.invoice(1))
        f.rejectsPurchaseUpdate(frozen, 1, "layout_digest = ?", bytes(32, 8))
        assertEquals(1, f.terminal(1, "finalized"))

        // Every state but prepared freezes them, even with sent still 0.
        f.purchase(2)
        assertEquals(1, f.updatePurchase(2, "state = 'invoiced', invoice_id = ?, amount_atomic = 0, receipt_minute = ?", bytes(16, 2), T0))
        f.rejectsPurchaseUpdate(frozen, 2, "seed = ?", bytes(32, 7))

        // The input token of a trial or a refresh is frozen the same way.
        for ((i, kind) in listOf(3 to "trial", 4 to "refresh")) {
            f.purchase(i, kind = kind)
            assertEquals(1, f.updatePurchase(i, "sent = 1"))
            f.rejectsPurchaseUpdate(frozen, i, "input_token = ?", bytes(354, 2))
            f.rejectsPurchaseUpdate(frozen, i, "seed = ?", bytes(32, 2))
        }
    }

    @Test
    fun kindAndPaymentNeverChange() = EntitlementFixture().use { f ->
        f.purchase(1)
        f.rejectsPurchaseUpdate(frozen, 1, "pay_with = 'credits'")
        f.rejectsPurchaseUpdate(frozen, 1, "kind = 'trial', pay_with = 'invite', claim_key = NULL, input_token = ?", bytes(354, 1))
        assertEquals(1, f.terminal(1, "failed"))
        f.rejectsPurchaseUpdate(frozen, 1, "pay_with = 'credits'")
        f.rejectsPurchaseUpdate(frozen, 1, "kind = 'refresh', pay_with = 'credit'")
    }

    @Test
    fun anInvoiceIsRecordedOnce() = EntitlementFixture().use { f ->
        val msg = "an invoice is recorded once"
        f.purchase(1)
        assertEquals(1, f.invoice(1))
        f.rejectsPurchaseUpdate(msg, 1, "invoice_id = ?", bytes(16, 0x99))
        f.rejectsPurchaseUpdate(msg, 1, "invoice_id = NULL")
        f.rejectsPurchaseUpdate(msg, 1, "subaddress = ?", subaddress(9))
        f.rejectsPurchaseUpdate(msg, 1, "amount_atomic = ?", 5L)
        // Re-writing the same values is no change; the outstanding amount follows each answer.
        assertEquals(1, f.updatePurchase(1, "invoice_id = invoice_id, subaddress = subaddress, amount_atomic = amount_atomic, outstanding_atomic = 0"))
        // The terminal transaction wipes the invoice.
        assertEquals(1, f.terminal(1, "expired"))
        // A zero-amount invoice (paid by credits) has no subaddress; a payable one needs one.
        f.purchase(2, payWith = "credits")
        assertEquals(1, f.invoice(2, amount = 0))
        f.purchase(3)
        f.rejectsPurchaseUpdate(CHECK_FAILED, 3, "state = 'invoiced', invoice_id = ?, amount_atomic = 5, receipt_minute = ?", bytes(16, 3), T0)
        f.rejectsPurchaseUpdate(
            CHECK_FAILED, 3, "state = 'invoiced', invoice_id = ?, subaddress = ?, amount_atomic = 0, receipt_minute = ?", bytes(16, 3), subaddress(3), T0,
        )
    }

    @Test
    fun aLivePurchaseIsNeverDeleted() = EntitlementFixture().use { f ->
        val msg = "a live purchase is never deleted"
        val delete = "DELETE FROM ent_purchase WHERE purchase_id = ?"
        f.purchase(1)
        f.db.rejects(msg, delete, purchaseId(1))
        assertEquals(1, f.invoice(1))
        f.db.rejects(msg, delete, purchaseId(1))
        for ((k, state) in terminal.withIndex()) {
            val i = 10 + k
            f.packIn(i, state)
            assertEquals(state, 1, f.db.changes(delete, purchaseId(i)))
        }
    }

    @Test
    fun aRelayReservationEndsOnlyByDeletion() = EntitlementFixture().use { f ->
        f.accessToken(1)
        assertEquals(1, f.reserveForRelay(1))
        assertEquals(0, f.reserveForRelay(1))
        f.db.rejects(
            reservationEnds,
            "UPDATE ent_token SET state = 'fresh', reserved_for = NULL, reserved_relay = NULL, reserved_namespace = NULL, request_id = NULL WHERE nullifier = ?",
            hash(1),
        )
        assertEquals("reserved", f.tokenState(1))
        // tx2 of the redeem lane deletes the token, guarded by the reservation's request id.
        val delete = "DELETE FROM ent_token WHERE nullifier = ? AND state = 'reserved' AND request_id = ?"
        assertEquals(0, f.db.changes(delete, hash(1), bytes(16, 9)))
        assertEquals(1, f.db.changes(delete, hash(1), bytes(16, 1)))
        // A token not yet eligible cannot be reserved (guard eligible_minute <= now).
        f.db.exec(
            "INSERT INTO ent_token(nullifier, kind, epoch, slot, token, state, eligible_minute) VALUES (?, 'access', ?, 3, ?, 'fresh', ?)",
            listOf(hash(2), WEEK0, bytes(354, 2), T0 + 3600),
        )
        assertEquals(0, f.reserveForRelay(2))
        // An invite token is never reserved: it is deleted when an invite is created.
        f.token(3, "invite", epoch = 726)
        f.db.rejects(CHECK_FAILED, "UPDATE ent_token SET state = 'reserved', reserved_for = 'purchase', reserved_ref = ? WHERE nullifier = ?", purchaseId(1), hash(3))
    }

    @Test
    fun oneRelayReservationPerRelayNamespaceAndWeek() = EntitlementFixture().use { f ->
        f.accessToken(1)
        f.accessToken(2)
        f.accessToken(3, epoch = WEEK0 + 1)
        f.accessToken(4)
        assertEquals(1, f.reserveForRelay(1))
        f.db.rejects(
            UNIQUE_FAILED,
            "UPDATE ent_token SET state = 'reserved', reserved_for = 'relay', reserved_relay = 1, reserved_namespace = ?, request_id = ? WHERE nullifier = ?",
            f.ns, bytes(16, 2), hash(2),
        )
        assertEquals(1, f.reserveForRelay(2, relay = 2))
        assertEquals(1, f.reserveForRelay(3))
        assertEquals(1, f.reserveForRelay(4, namespace = bytes(32, 2)))
    }

    @Test
    fun creditsReturnToFreshOnlyForAFailedFlow() = EntitlementFixture().use { f ->
        for (n in 10..17) f.token(n, "credit")
        // Purchase: released only once the purchase failed.
        f.purchase(1, payWith = "credits")
        for (n in 10..11) assertEquals(1, f.reserveCredit(n, "purchase", purchaseId(1)))
        f.db.rejects(reservationEnds, f.release, hash(10))
        assertEquals(1, f.terminal(1, "failed"))
        for (n in 10..11) assertEquals(1, f.db.changes(f.release, hash(n)))
        assertEquals("fresh", f.tokenState(10))
        // A finalized purchase spent its credits: they are deleted, never released.
        f.purchase(2, payWith = "credits")
        assertEquals(1, f.reserveCredit(12, "purchase", purchaseId(2)))
        assertEquals(1, f.invoice(2, amount = 0))
        assertEquals(1, f.terminal(2, "finalized"))
        f.db.rejects(reservationEnds, f.release, hash(12))
        assertEquals(1, f.db.changes("DELETE FROM ent_token WHERE nullifier = ?", hash(12)))
        // Claims: never released while prepared or once queued, released when failed.
        f.claim(1)
        assertEquals(1, f.reserveCredit(13, "claim", claimId(1)))
        f.db.rejects(reservationEnds, f.release, hash(13))
        assertEquals(1, f.decideClaim(1, "queued", 50_000L))
        f.db.rejects(reservationEnds, f.release, hash(13))
        f.claim(2)
        assertEquals(1, f.reserveCredit(14, "claim", claimId(2)))
        assertEquals(1, f.decideClaim(2, "failed"))
        assertEquals(1, f.db.changes(f.release, hash(14)))
        // A reference to no row (a flow deleted by GC) never releases: the design's `= 'failed'`
        // was NULL there and skipped the trigger; the schema compares with IS.
        assertEquals(1, f.reserveCredit(15, "purchase", purchaseId(99)))
        f.db.rejects(reservationEnds, f.release, hash(15))
        assertEquals(1, f.reserveCredit(16, "claim", claimId(99)))
        f.db.rejects(reservationEnds, f.release, hash(16))
        // GC of a failed purchase whose credit is still reserved: the credit can no longer come back.
        f.purchase(3, payWith = "credits")
        assertEquals(1, f.reserveCredit(17, "purchase", purchaseId(3)))
        assertEquals(1, f.terminal(3, "failed"))
        assertEquals(1, f.db.changes("DELETE FROM ent_purchase WHERE purchase_id = ?", purchaseId(3)))
        f.db.rejects(reservationEnds, f.release, hash(17))
    }

    @Test
    fun aTokenAndItsReservationKeepTheirBinding() = EntitlementFixture().use { f ->
        val msg = "a token and its reservation keep their binding"
        f.accessToken(1)
        val immutable = listOf(
            "nullifier = zeroblob(32)", "kind = 'invite', slot = NULL", "epoch = epoch + 1", "slot = 4", "token = zeroblob(354)",
            "eligible_minute = eligible_minute + 60",
        )
        for (set in immutable) f.db.rejects(msg, "UPDATE ent_token SET $set WHERE nullifier = ?", hash(1))
        assertEquals(1, f.reserveForRelay(1))
        for (set in listOf("request_id = zeroblob(16)", "reserved_relay = 2", "reserved_namespace = zeroblob(32)", "token = zeroblob(354)")) {
            f.db.rejects(msg, "UPDATE ent_token SET $set WHERE nullifier = ?", hash(1))
        }
        // Unchanged values are no change.
        assertEquals(1, f.db.changes("UPDATE ent_token SET request_id = request_id, token = token WHERE nullifier = ?", hash(1)))
        // A reserved credit keeps its reference and purpose.
        f.token(2, "credit")
        f.purchase(1, payWith = "credits")
        f.purchase(2, payWith = "credits")
        assertEquals(1, f.reserveCredit(2, "purchase", purchaseId(1)))
        f.db.rejects(msg, "UPDATE ent_token SET reserved_ref = ? WHERE nullifier = ?", purchaseId(2), hash(2))
        f.db.rejects(msg, "UPDATE ent_token SET reserved_for = 'claim' WHERE nullifier = ?", hash(2))
    }

    @Test
    fun inviteTransitions() = EntitlementFixture().use { f ->
        val states = listOf("created", "credited", "closed")
        val legal = mapOf("created" to setOf("credited", "closed"), "credited" to setOf("closed"))
        val move = "UPDATE ent_invite SET state = ?, payload = CASE WHEN ? = 'created' THEN payload ELSE NULL END WHERE invite_index = ?"
        var i = 0
        for (from in states) for (to in states) {
            i++
            f.invite(i)
            if (from != "created") assertEquals(1, f.db.changes(move, from, from, i))
            if (from == to || to in legal[from].orEmpty()) {
                assertEquals("$from -> $to", 1, f.db.changes(move, to, to, i))
            } else {
                f.db.rejects("illegal invite transition", move, to, to, i)
            }
        }
        // The payload leaves together with the created state.
        f.invite(50)
        f.db.rejects(CHECK_FAILED, "UPDATE ent_invite SET state = 'credited' WHERE invite_index = 50")
    }

    @Test
    fun theDropTargetIsEnqueuedOnce() = EntitlementFixture().use { f ->
        val msg = "illegal drop target transition"
        f.dropTarget()
        f.db.rejects(msg, "UPDATE ent_drop_target SET operation_id = ? WHERE id = 1", opId(1))
        f.db.rejects(CHECK_FAILED, "UPDATE ent_drop_target SET state = 'enqueued' WHERE id = 1")
        assertEquals(1, f.db.changes("UPDATE ent_drop_target SET state = 'enqueued', operation_id = ? WHERE id = 1 AND state = 'waiting'", opId(1)))
        f.db.rejects(msg, "UPDATE ent_drop_target SET operation_id = ? WHERE id = 1", opId(2))
        f.db.rejects(msg, "UPDATE ent_drop_target SET state = 'waiting', operation_id = NULL WHERE id = 1")
        // The outbox outcome is released: the row is deleted.
        assertEquals(1, f.db.changes("DELETE FROM ent_drop_target WHERE id = 1"))
    }

    @Test
    fun aClaimKeepsItsAddressAndIsDecidedOnce() = EntitlementFixture().use { f ->
        val msg = "a claim keeps its address and is decided once"
        f.claim(1)
        assertEquals(1, f.db.changes("UPDATE ent_claim SET sent = 1, attempt = 1, next_due_minute = ? WHERE claim_id = ?", T0 + 3600, claimId(1)))
        f.db.rejects(msg, "UPDATE ent_claim SET sent = 0 WHERE claim_id = ?", claimId(1))
        f.db.rejects(msg, "UPDATE ent_claim SET payout_address = ? WHERE claim_id = ?", subaddress(9), claimId(1))
        // One open claim at a time.
        f.db.rejects(
            UNIQUE_FAILED,
            "INSERT INTO ent_claim(claim_id, state, payout_address, next_due_minute) VALUES (?, 'prepared', ?, ?)",
            claimId(2), subaddress(2), T0,
        )
        assertEquals(1, f.decideClaim(1, "queued", 50_000L))
        f.db.rejects(msg, "UPDATE ent_claim SET state = 'failed' WHERE claim_id = ?", claimId(1))
        f.db.rejects(
            msg, "UPDATE ent_claim SET state = 'prepared', payout_address = ?, next_due_minute = ?, terminal_day = NULL, queued_atomic = NULL WHERE claim_id = ?",
            subaddress(1), T0, claimId(1),
        )
        // With claim 1 decided, a new claim may open; a failed claim stays failed.
        f.claim(2)
        assertEquals(1, f.decideClaim(2, "failed"))
        f.db.rejects(msg, "UPDATE ent_claim SET state = 'queued', queued_atomic = 5 WHERE claim_id = ?", claimId(2))
    }

    @Test
    fun theClientFlowsOfTheDesignRunWithoutARefusal() = EntitlementFixture().use { f ->
        val db = f.db
        // Pack (XMR): prepared, sent, invoiced, answers, then one finalizing transaction: tokens in,
        // state finalized, every secret wiped (§11.5); GC deletes the row at terminal_day + 7.
        f.purchase(1)
        assertEquals(1, db.changes("UPDATE ent_purchase SET sent = 1 WHERE purchase_id = ? AND state = 'prepared' AND sent = 0", purchaseId(1)))
        assertEquals(1, f.invoice(1))
        assertEquals(1, f.updatePurchase(1, "attempt = attempt + 1, prev_state = 3, outstanding_atomic = 0, next_due_minute = ?", T0 + 4 * 3600))
        db.transaction {
            f.accessToken(20)
            f.token(21, "invite", epoch = 726)
            f.token(22, "credit")
            assertEquals(1, db.changes("UPDATE ent_purchase SET state = 'finalized', $TERMINAL_WIPE WHERE purchase_id = ? AND state = 'invoiced'", DAY0, purchaseId(1)))
        }
        assertEquals(
            1L,
            db.queryLong("SELECT count(*) FROM ent_purchase WHERE state = 'finalized' AND seed IS NULL AND created_hour IS NULL AND base_week IS NOT NULL"),
        )
        assertEquals(1, db.changes("DELETE FROM ent_purchase WHERE purchase_id = ? AND terminal_day + 7 <= ?", purchaseId(1), DAY0 + 7))
        // Trial: finalized, or failed (REPLAYED) and followed by a new prepared trial with the same token.
        f.purchase(2, kind = "trial")
        assertEquals(1, f.updatePurchase(2, "sent = 1"))
        assertEquals(1, f.terminal(2, "finalized"))
        f.purchase(3, kind = "trial")
        assertEquals(1, f.updatePurchase(3, "sent = 1"))
        assertEquals(1, f.terminal(3, "failed"))
        // Refresh of a received credit: one fresh credit inserted by the finalizing transaction.
        f.purchase(4, kind = "refresh")
        assertEquals(1, f.updatePurchase(4, "sent = 1"))
        db.transaction {
            f.token(23, "credit")
            assertEquals(1, f.terminal(4, "finalized"))
        }
        // A pack whose attempt plan ran out is lost.
        f.purchase(5)
        assertEquals(1, f.invoice(5))
        assertEquals(1, f.updatePurchase(5, "attempt = 5"))
        assertEquals(1, f.terminal(5, "lost"))
        // Inviter: an invite is created, credited, closed; the drop target of an invitee is enqueued.
        f.invite(0)
        assertEquals(1, db.changes("UPDATE ent_invite SET state = 'credited', payload = NULL WHERE invite_index = 0 AND state = 'created'"))
        assertEquals(1, db.changes("UPDATE ent_invite SET state = 'closed' WHERE invite_index = 0 AND state = 'credited'"))
        f.dropTarget()
        assertEquals(1, db.changes("UPDATE ent_drop_target SET state = 'enqueued', operation_id = ? WHERE id = 1 AND state = 'waiting'", opId(3)))
    }
}
