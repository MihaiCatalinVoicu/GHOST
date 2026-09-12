package org.ghost.storage

/** 2025-09-10 08:00 UTC: a whole hour; UTC day 20341, ISO week 2905 (design §4.1). */
internal const val T0 = 1_757_491_200L
internal const val DAY0 = T0 / 86_400L
internal const val WEEK0 = 2905L

/** The columns a terminal transaction wipes (design §11.3, R10, §19.15); `terminal_day` is bound. */
internal const val TERMINAL_WIPE =
    "terminal_day = ?, seed = NULL, claim_key = NULL, invoice_id = NULL, subaddress = NULL, amount_atomic = NULL, " +
        "input_token = NULL, next_due_minute = NULL, created_hour = NULL, receipt_minute = NULL, outstanding_atomic = NULL"

internal fun purchaseId(i: Int) = bytes(16, i)
internal fun claimId(i: Int) = bytes(16, 0x80 + i)

/** A 95-character standard-address shape (content is irrelevant to the schema). */
internal fun subaddress(i: Int): String = "5" + ('a' + i % 26).toString().repeat(94)

/** A migrated v3 database with helpers that write valid rows of the entitlement tables. */
internal class EntitlementFixture : AutoCloseable {
    val db = JdbcSqlExecutor().also { MigrationRunner(it).migrate() }
    val ns = bytes(32, 1)

    /** A prepared, unsent flow with every live column set: pack (xmr or credits), trial or refresh. */
    fun purchase(i: Int, kind: String = "pack", payWith: String = defaultPayWith(kind)) {
        val pack = kind == "pack"
        db.exec(
            "INSERT INTO ent_purchase(purchase_id, kind, pay_with, state, seed, claim_key, input_token, base_week, schedule_seq, layout_digest, created_hour) " +
                "VALUES (?, ?, ?, 'prepared', ?, ?, ?, ?, 1, ?, ?)",
            listOf(
                purchaseId(i), kind, payWith, bytes(32, 0x30 + i), if (pack) bytes(32, 0x40 + i) else null,
                if (pack) null else bytes(354, 0x50 + i), WEEK0, bytes(32, 0x60 + i), T0,
            ),
        )
    }

    private fun defaultPayWith(kind: String) = when (kind) {
        "trial" -> "invite"
        "refresh" -> "credit"
        else -> "xmr"
    }

    /** The validated `RequestInvoice` answer of a pack; amount 0 = fully paid by credits (no subaddress). */
    fun invoice(i: Int, amount: Long = 1_000_000_000L): Int = db.execUpdate(
        "UPDATE ent_purchase SET state = 'invoiced', sent = 1, invoice_id = ?, subaddress = ?, amount_atomic = ?, receipt_minute = ?, " +
            "outstanding_atomic = ? WHERE purchase_id = ? AND state = 'prepared'",
        listOf(bytes(16, 0x70 + i), if (amount == 0L) null else subaddress(i), amount, T0, amount, purchaseId(i)),
    )

    /** The terminal transaction: state change plus the wipe of every issuance secret. */
    fun terminal(i: Int, state: String): Int =
        db.execUpdate("UPDATE ent_purchase SET state = ?, $TERMINAL_WIPE WHERE purchase_id = ?", listOf(state, DAY0, purchaseId(i)))

    fun updatePurchase(i: Int, set: String, vararg args: Any?): Int =
        db.execUpdate("UPDATE ent_purchase SET $set WHERE purchase_id = ?", args.toList() + listOf(purchaseId(i)))

    fun rejectsPurchaseUpdate(fragment: String, i: Int, set: String, vararg args: Any?) =
        db.rejects(fragment, "UPDATE ent_purchase SET $set WHERE purchase_id = ?", *(args.toList() + listOf(purchaseId(i))).toTypedArray())

    fun purchaseState(i: Int): String? = db.queryString("SELECT state FROM ent_purchase WHERE purchase_id = ?", listOf(purchaseId(i)))

    /** A fresh ACCESS token of [epoch] for ES slot [slot]; [n] makes nullifier and token distinct. */
    fun accessToken(n: Int, epoch: Long = WEEK0, slot: Int = 3) = db.exec(
        "INSERT INTO ent_token(nullifier, kind, epoch, slot, token, state, eligible_minute) VALUES (?, 'access', ?, ?, ?, 'fresh', ?)",
        listOf(hash(n), epoch, slot, bytes(354, n), T0),
    )

    /** A fresh INVITE or CREDIT token (no slot). */
    fun token(n: Int, kind: String, epoch: Long = 223) = db.exec(
        "INSERT INTO ent_token(nullifier, kind, epoch, slot, token, state, eligible_minute) VALUES (?, ?, ?, NULL, ?, 'fresh', ?)",
        listOf(hash(n), kind, epoch, bytes(354, n), T0),
    )

    /** Redeem-lane tx1: reserve a fresh access token for (relay, namespace) with a new request id. */
    fun reserveForRelay(n: Int, relay: Int = 1, namespace: ByteArray = ns, requestId: ByteArray = bytes(16, n)): Int = db.execUpdate(
        "UPDATE ent_token SET state = 'reserved', reserved_for = 'relay', reserved_relay = ?, reserved_namespace = ?, request_id = ? " +
            "WHERE nullifier = ? AND state = 'fresh' AND eligible_minute <= ?",
        listOf(relay, namespace, requestId, hash(n), T0),
    )

    /** Reserve a fresh credit for a purchase or a claim ([ref] = its id). */
    fun reserveCredit(n: Int, forWhat: String, ref: ByteArray): Int = db.execUpdate(
        "UPDATE ent_token SET state = 'reserved', reserved_for = ?, reserved_ref = ? WHERE nullifier = ? AND state = 'fresh'",
        listOf(forWhat, ref, hash(n)),
    )

    /** Release a reserved credit back to fresh (only for a failed flow). */
    val release = "UPDATE ent_token SET state = 'fresh', reserved_for = NULL, reserved_ref = NULL WHERE nullifier = ?"

    fun tokenState(n: Int): String? = db.queryString("SELECT state FROM ent_token WHERE nullifier = ?", listOf(hash(n)))

    fun invite(i: Int) = db.exec(
        "INSERT INTO ent_invite(invite_index, state, payload, drop_namespace, listen_until_day) VALUES (?, 'created', ?, ?, ?)",
        listOf(i, bytes(538, i), bytes(32, i), DAY0 + 90),
    )

    fun dropTarget() = db.exec(
        "INSERT INTO ent_drop_target(id, drop_namespace, drop_key, drop_slots, state, drop_minute, until_day) VALUES (1, ?, ?, ?, 'waiting', ?, ?)",
        listOf(bytes(32, 9), bytes(32, 10), byteArrayOf(5, 0, 17), T0 + 30 * 86_400L, DAY0 + 60),
    )

    fun claim(i: Int) = db.exec(
        "INSERT INTO ent_claim(claim_id, state, payout_address, next_due_minute) VALUES (?, 'prepared', ?, ?)",
        listOf(claimId(i), subaddress(i), T0),
    )

    fun decideClaim(i: Int, state: String, queuedAtomic: Long? = null): Int = db.execUpdate(
        "UPDATE ent_claim SET state = ?, queued_atomic = ?, terminal_day = ?, next_due_minute = NULL, payout_address = NULL " +
            "WHERE claim_id = ? AND state = 'prepared'",
        listOf(state, queuedAtomic, DAY0, claimId(i)),
    )

    override fun close() = db.close()
}
