package org.ghost.storage

import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The CHECK constraints of the v3 entitlement tables (Phase 8 design §11.3): for each table a valid
 * base row, and each single deviation from it refused with a CHECK failure. The base row itself is
 * inserted last, so no refusal comes from a key conflict.
 */
class EntitlementSchemaConstraintsTest {
    private fun SqlExecutor.insert(table: String, row: Map<String, Any?>) =
        exec("INSERT INTO $table(${row.keys.joinToString(", ")}) VALUES (${row.keys.joinToString(", ") { "?" }})", row.values.toList())

    private fun checks(table: String, base: Map<String, Any?>, deviations: List<Map<String, Any?>>) = EntitlementFixture().use { f ->
        for (d in deviations) {
            val e = assertThrows("$table $d", java.sql.SQLException::class.java) { f.db.insert(table, base + d) }
            assertTrue("$table $d: ${e.message}", e.message.orEmpty().contains(CHECK_FAILED))
        }
        f.db.insert(table, base)
    }

    @Test
    fun esMemoryAndState() {
        checks(
            "ent_key", mapOf("kind" to "access", "epoch" to WEEK0, "key_id" to hash(1)),
            listOf(mapOf("kind" to "pack"), mapOf("epoch" to -1), mapOf("key_id" to bytes(31, 1))),
        )
        checks(
            "ent_schedule_fact", mapOf("fact" to "slots", "epoch" to WEEK0, "digest" to hash(1)),
            listOf(mapOf("fact" to "onion"), mapOf("epoch" to -1), mapOf("digest" to bytes(33, 1))),
        )
        checks(
            "ent_state", mapOf("id" to 1, "schedule_seq" to 1, "schedule_digest" to hash(1), "payout_salt" to hash(2)),
            listOf(
                mapOf("id" to 2), mapOf("schedule_seq" to 0), mapOf("schedule_digest" to bytes(31, 1)), mapOf("next_invite_index" to 65536),
                mapOf("next_invite_index" to -1), mapOf("payout_salt" to bytes(16, 1)), mapOf("restore_scan_until_day" to -1),
                mapOf("auto_renew_credits" to 2), mapOf("alarm_flags" to 8), mapOf("alarm_flags" to -1),
            ),
        )
    }

    private val livePack = mapOf(
        "purchase_id" to purchaseId(1), "kind" to "pack", "pay_with" to "xmr", "state" to "prepared", "seed" to hash(1),
        "claim_key" to hash(2), "base_week" to WEEK0, "schedule_seq" to 1, "layout_digest" to hash(3), "created_hour" to T0,
    )
    private val liveTrial = livePack + mapOf("kind" to "trial", "pay_with" to "invite", "claim_key" to null, "input_token" to bytes(354, 4))

    @Test
    fun aLivePurchaseCarriesItsSecretsInTheirShapes() {
        checks(
            "ent_purchase", livePack,
            listOf(
                mapOf("purchase_id" to bytes(15, 1)), mapOf("kind" to "gift"), mapOf("pay_with" to "card"), mapOf("state" to "paid"),
                // Kind and payment are paired.
                mapOf("pay_with" to "invite"), mapOf("pay_with" to "credit"), mapOf("kind" to "trial"), mapOf("kind" to "refresh"),
                // A pack has no input token; every live flow has seed, layout, base week, schedule and hour.
                mapOf("input_token" to bytes(354, 1)), mapOf("seed" to null), mapOf("base_week" to null), mapOf("schedule_seq" to null),
                mapOf("layout_digest" to null), mapOf("created_hour" to null), mapOf("claim_key" to null), mapOf("terminal_day" to DAY0),
                // Shapes and granularity.
                mapOf("seed" to bytes(31, 1)), mapOf("claim_key" to bytes(33, 1)), mapOf("invoice_id" to bytes(15, 1)),
                mapOf("subaddress" to "5".repeat(94)), mapOf("amount_atomic" to -1), mapOf("base_week" to -1), mapOf("schedule_seq" to 0),
                mapOf("layout_digest" to bytes(31, 1)), mapOf("created_hour" to T0 + 60), mapOf("receipt_minute" to T0 + 1),
                mapOf("next_due_minute" to T0 + 30), mapOf("outstanding_atomic" to -1), mapOf("attempt" to 41), mapOf("attempt" to -1),
                mapOf("prev_state" to 7), mapOf("sent" to 2), mapOf("disclosed" to 2), mapOf("shown" to 2),
                // An invoice needs its fields, and a subaddress exactly when something is to be paid.
                mapOf("state" to "invoiced"),
                mapOf("state" to "invoiced", "invoice_id" to bytes(16, 1), "amount_atomic" to 5, "receipt_minute" to T0),
                mapOf("state" to "invoiced", "invoice_id" to bytes(16, 1), "amount_atomic" to 0, "receipt_minute" to T0, "subaddress" to subaddress(1)),
            ),
        )
        checks(
            "ent_purchase", liveTrial,
            listOf(
                mapOf("input_token" to null), mapOf("input_token" to bytes(353, 1)), mapOf("claim_key" to hash(2)),
                mapOf("invoice_id" to bytes(16, 1)), mapOf("amount_atomic" to 0), mapOf("subaddress" to subaddress(1)),
                mapOf("receipt_minute" to T0), mapOf("outstanding_atomic" to 0),
                mapOf("state" to "invoiced"), mapOf("pay_with" to "xmr"),
            ),
        )
    }

    @Test
    fun aTerminalPurchaseCarriesNoSecretAndNoCreationHour() {
        val terminalPack = mapOf(
            "purchase_id" to purchaseId(1), "kind" to "pack", "pay_with" to "xmr", "state" to "finalized", "terminal_day" to DAY0,
            "base_week" to WEEK0, "schedule_seq" to 1, "layout_digest" to hash(3),
        )
        for (state in listOf("finalized", "expired", "failed", "lost")) {
            checks(
                "ent_purchase", terminalPack + mapOf("state" to state),
                listOf(
                    mapOf("terminal_day" to null), mapOf("seed" to hash(1)), mapOf("claim_key" to hash(2)), mapOf("invoice_id" to bytes(16, 1)),
                    mapOf("subaddress" to subaddress(1)), mapOf("amount_atomic" to 5), mapOf("next_due_minute" to T0),
                    mapOf("created_hour" to T0), mapOf("receipt_minute" to T0), mapOf("outstanding_atomic" to 0),
                ),
            )
        }
        checks(
            "ent_purchase", terminalPack + mapOf("kind" to "trial", "pay_with" to "invite"),
            listOf(mapOf("input_token" to bytes(354, 1))),
        )
    }

    private val freshAccess = mapOf(
        "nullifier" to hash(1), "kind" to "access", "epoch" to WEEK0, "slot" to 3, "token" to bytes(354, 1), "state" to "fresh", "eligible_minute" to T0,
    )
    private val relayReservation = mapOf(
        "state" to "reserved", "reserved_for" to "relay", "reserved_relay" to 1, "reserved_namespace" to bytes(32, 1), "request_id" to bytes(16, 1),
    )

    @Test
    fun tokensAndTheirReservations() {
        checks(
            "ent_token", freshAccess,
            listOf(
                mapOf("nullifier" to bytes(31, 1)), mapOf("kind" to "gift"), mapOf("epoch" to -1), mapOf("slot" to null), mapOf("slot" to 32),
                mapOf("slot" to -1), mapOf("token" to bytes(353, 1)), mapOf("state" to "spent"), mapOf("eligible_minute" to T0 + 1),
                // A reservation is complete, and a fresh token has none.
                mapOf("state" to "reserved"), mapOf("reserved_for" to "relay"), relayReservation - "request_id",
                relayReservation - "reserved_namespace", relayReservation - "reserved_relay", relayReservation + mapOf("reserved_ref" to bytes(16, 1)),
                relayReservation + mapOf("reserved_for" to "gift"), relayReservation + mapOf("request_id" to bytes(15, 1)),
                relayReservation + mapOf("reserved_namespace" to bytes(31, 1)),
                // Only credits are reserved for a purchase or a claim.
                mapOf("state" to "reserved", "reserved_for" to "purchase", "reserved_ref" to purchaseId(1)),
            ),
        )
        checks("ent_token", freshAccess + relayReservation, emptyList())
        val freshCredit = freshAccess + mapOf("nullifier" to hash(2), "kind" to "credit", "slot" to null)
        val purchaseReservation = mapOf("state" to "reserved", "reserved_for" to "purchase", "reserved_ref" to purchaseId(1))
        checks(
            "ent_token", freshCredit,
            listOf(
                mapOf("slot" to 3), purchaseReservation - "reserved_ref", purchaseReservation + mapOf("request_id" to bytes(16, 1)),
                purchaseReservation + mapOf("reserved_relay" to 1), purchaseReservation + mapOf("reserved_namespace" to bytes(32, 1)),
                purchaseReservation + mapOf("reserved_ref" to bytes(15, 1)), relayReservation,
            ),
        )
        checks("ent_token", freshCredit + purchaseReservation, emptyList())
    }

    @Test
    fun invitesDropTargetsClaimsAndUsedAddresses() {
        checks(
            "ent_invite", mapOf("invite_index" to 0, "state" to "created", "payload" to bytes(538, 1), "drop_namespace" to hash(1), "listen_until_day" to DAY0),
            listOf(
                mapOf("invite_index" to -1), mapOf("invite_index" to 65536), mapOf("state" to "sent"), mapOf("payload" to bytes(537, 1)),
                mapOf("state" to "credited"), mapOf("state" to "closed"), mapOf("drop_namespace" to bytes(31, 1)), mapOf("listen_until_day" to -1),
            ),
        )
        checks(
            "ent_drop_target",
            mapOf(
                "id" to 1, "drop_namespace" to hash(1), "drop_key" to hash(2), "drop_slots" to byteArrayOf(5, 0, 17), "state" to "waiting",
                "drop_minute" to T0, "until_day" to DAY0,
            ),
            listOf(
                mapOf("id" to 2), mapOf("drop_namespace" to bytes(31, 1)), mapOf("drop_key" to bytes(33, 1)), mapOf("drop_slots" to byteArrayOf(5, 0)),
                mapOf("drop_slots" to byteArrayOf(5, 0, 17, 1)), mapOf("state" to "sent"), mapOf("state" to "enqueued"),
                mapOf("operation_id" to opId(1)), mapOf("state" to "enqueued", "operation_id" to bytes(15, 1)), mapOf("drop_minute" to T0 + 30),
                mapOf("until_day" to -1),
            ),
        )
        val prepared = mapOf("claim_id" to claimId(1), "state" to "prepared", "payout_address" to subaddress(1), "next_due_minute" to T0)
        checks(
            "ent_claim", prepared,
            listOf(
                mapOf("claim_id" to bytes(15, 1)), mapOf("state" to "paid"), mapOf("payout_address" to null), mapOf("next_due_minute" to null),
                mapOf("terminal_day" to DAY0), mapOf("payout_address" to "5".repeat(94)), mapOf("queued_atomic" to 5), mapOf("sent" to 2),
                mapOf("attempt" to 21), mapOf("next_due_minute" to T0 + 1),
                mapOf("state" to "queued", "terminal_day" to DAY0), mapOf("state" to "queued", "queued_atomic" to 0, "terminal_day" to DAY0),
                mapOf("state" to "failed", "payout_address" to null, "next_due_minute" to null),
            ),
        )
        checks(
            "ent_payout_used", mapOf("address_hash" to hash(1), "until_day" to DAY0 + 365),
            listOf(mapOf("address_hash" to bytes(31, 1)), mapOf("until_day" to -1)),
        )
    }
}
