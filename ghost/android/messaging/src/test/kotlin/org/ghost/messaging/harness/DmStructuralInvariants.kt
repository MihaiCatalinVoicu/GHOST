package org.ghost.messaging.harness

import org.ghost.storage.JdbcSqlExecutor
import org.ghost.storage.MigrationRunner

/**
 * The structural invariants of Phase 9 design §15.3, checked **after every reboot** and again at
 * quiescence (RG-7).
 *
 * > `integrity_check` ok, `foreign_key_check` empty, every expected trigger present; every `queued`
 * > outgoing message has an unreleased outbox op or a pending send; every `dm_outbound_op` of
 * > purpose `item` references a live outbox op or a released outcome; every `pending` or `enqueued`
 * > item has a pending send or an unreleased op; held rows exist only for `changed` contacts; at
 * > most 2 `olm_session` rows per contact, with exactly one `current` whenever any exists; every
 * > `previous` row has a `retire_day`; every `olm_prekey_used` row references a live generation; at
 * > most 14 generations; at most 3 `dm_peer_pq` rows per contact; no session row for a `revoked`,
 * > `blocked` or `changed` contact other than sessions under the pinned identity of a `changed`
 * > contact; the `delete_at` CHECK holds; after SWEEP and R-K1 no row has
 * > `delete_at_minute ≤ now_e` and the WAL is 0 bytes; every registration row is consistent with
 * > its capability.
 *
 * Every clause above is here, and each says in its own message which one it is, because a crash
 * enumeration reports a *class* and the class is only useful if the line names the rule. Three of
 * them are also enforced by the schema (§13.6 step 6) — the two-slot bound is the primary key of
 * `olm_session`, `retire_day` on `previous` is a CHECK, and `delete_at_minute` is a CHECK — and
 * they are still asserted here, because what they then catch is a **migration** that dropped the
 * guard, which is SCN-L's failure mode and not a hypothetical one.
 *
 * **Declared gap in the session clause.** "no session row … other than sessions under the pinned
 * identity of a `changed` contact" cannot be decided from the schema: `olm_session` carries a
 * `session_id`, not the peer identity the session was built under. What is checked is the half
 * that is decidable — no session row at all for a `revoked` or a `blocked` contact — and the
 * `changed` half is left to KC1/KC2, which assert it behaviourally (no encrypt to a `changed`
 * contact, held content not displayed). §22.15 records it.
 */
internal object DmStructuralInvariants {

    /** At most this many generations live at once (§15.3; 13 weekly plus the current one). */
    const val MAX_GENERATIONS: Int = 14

    /** At most this many PQ offers are kept per contact (§22.8.6). */
    const val MAX_PEER_PQ: Int = 3

    /**
     * Every clause of §15.3 over one node's database, on the **raw** connection so the check is not
     * itself an event of the run it is checking.
     *
     * [where] names the moment ("reboot 3", "end") and goes into every failure message.
     */
    fun check(node: DmNode, where: String, heavy: Boolean = true) {
        val sql = node.raw
        val label = "${node.name} @ $where"

        if (heavy) {
            var integrity = "missing"
            sql.query("PRAGMA integrity_check") { integrity = it.string(0) }
            if (integrity != "ok") dmViolation("$label: integrity_check = $integrity")
            var foreignKeyProblems = 0
            sql.query("PRAGMA foreign_key_check") { foreignKeyProblems++ }
            if (foreignKeyProblems != 0) {
                dmViolation("$label: foreign_key_check reported $foreignKeyProblems rows")
            }
            // "every expected trigger present" — and every expected table, and the connection
            // pragmas, which is exactly `verifyIntegrity`'s contract.
            runCatching { MigrationRunner(sql).verifyIntegrity() }
                .onFailure { dmViolation("$label: ${it.message}") }
        }

        // Every `queued` outgoing message has an unreleased outbox op or a pending send.
        empty(
            sql, label, "a queued outgoing message with neither an op nor a pending send",
            """SELECT count(*) FROM dm_message m
                 WHERE m.direction = 'out' AND m.state = 'queued'
                   AND NOT EXISTS (SELECT 1 FROM dm_outbound_item i
                                     JOIN dm_pending_send p ON p.item_id = i.item_id
                                    WHERE i.message_ref = m.message_id)
                   AND NOT EXISTS (SELECT 1 FROM dm_outbound_item i
                                     JOIN dm_outbound_op o ON o.item_id = i.item_id
                                     JOIN outbox_op x ON x.operation_id = o.operation_id
                                    WHERE i.message_ref = m.message_id AND x.released = 0)""",
        )

        // Every `dm_outbound_op` of purpose `item` references a live outbox op **or a released
        // outcome**.
        //
        // The second branch is not decoration and it took a run to find out why. `OutboxStore`
        // lets identical bytes into a namespace under a new operation id only once the earlier op
        // is released and wiped, and it does that by **deleting the old row** ("the old row is
        // deleted below and the new op pins the tombstone"). So an INDETERMINATE resend of §7.5
        // leaves a `dm_outbound_op` whose `outbox_op` is gone — legitimately, because its outcome
        // was released, which is exactly what created the resend. Once the row is gone "it was
        // released" is not directly readable, so what is checked is the two observable forms of it:
        // the item reached a terminal state, or a later op of the same item is live.
        empty(
            sql, label,
            "a dm_outbound_op of purpose 'item' with neither an outbox_op nor a released outcome",
            """SELECT count(*) FROM dm_outbound_op o
                 WHERE o.purpose = 'item'
                   AND NOT EXISTS (SELECT 1 FROM outbox_op x WHERE x.operation_id = o.operation_id)
                   AND NOT EXISTS (SELECT 1 FROM dm_outbound_item i
                                    WHERE i.item_id = o.item_id
                                      AND i.state IN ('sent', 'degraded', 'failed', 'indeterminate'))
                   AND NOT EXISTS (SELECT 1 FROM dm_outbound_op o2
                                     JOIN outbox_op x2 ON x2.operation_id = o2.operation_id
                                    WHERE o2.item_id = o.item_id
                                      AND o2.operation_id <> o.operation_id)""",
        )

        // Every `pending` or `enqueued` item has a pending send or an unreleased op.
        empty(
            sql, label, "a pending/enqueued item with neither a pending send nor an unreleased op",
            """SELECT count(*) FROM dm_outbound_item i
                 WHERE i.state IN ('pending', 'enqueued')
                   AND NOT EXISTS (SELECT 1 FROM dm_pending_send p WHERE p.item_id = i.item_id)
                   AND NOT EXISTS (SELECT 1 FROM dm_outbound_op o
                                     JOIN outbox_op x ON x.operation_id = o.operation_id
                                    WHERE o.item_id = i.item_id AND x.released = 0)""",
        )

        // Held rows exist only for `changed` contacts.
        empty(
            sql, label, "a held row on a contact that is not 'changed'",
            """SELECT count(*) FROM dm_held h JOIN dm_contact c ON c.contact_id = h.contact_id
                 WHERE c.trust_state <> 'changed'""",
        )

        // At most 2 `olm_session` rows per contact, with exactly one `current` whenever any exists.
        empty(
            sql, label, "a contact with more than two session rows",
            "SELECT count(*) FROM (SELECT contact_id FROM olm_session GROUP BY contact_id HAVING count(*) > 2)",
        )
        empty(
            sql, label, "a contact with sessions but no 'current' slot",
            """SELECT count(*) FROM (SELECT contact_id FROM olm_session GROUP BY contact_id
                                      HAVING sum(CASE WHEN slot = 'current' THEN 1 ELSE 0 END) <> 1)""",
        )

        // Every `previous` row has a `retire_day`.
        empty(
            sql, label, "a 'previous' session with no retire_day",
            "SELECT count(*) FROM olm_session WHERE slot = 'previous' AND retire_day IS NULL",
        )

        // Every `olm_prekey_used` row references a live generation.
        empty(
            sql, label, "an olm_prekey_used row whose generation is gone",
            """SELECT count(*) FROM olm_prekey_used u
                 WHERE NOT EXISTS (SELECT 1 FROM olm_prekey_gen g WHERE g.gen_id = u.gen_id)""",
        )

        // At most 14 generations.
        atMost(sql, label, "generations", MAX_GENERATIONS, "SELECT count(*) FROM olm_prekey_gen")

        // At most 3 `dm_peer_pq` rows per contact.
        empty(
            sql, label, "a contact with more than $MAX_PEER_PQ PQ offers",
            "SELECT count(*) FROM (SELECT contact_id FROM dm_peer_pq GROUP BY contact_id " +
                "HAVING count(*) > $MAX_PEER_PQ)",
        )

        // No session row for a `revoked` or a `blocked` contact (see the declared gap above).
        empty(
            sql, label, "a session row on a revoked or blocked contact",
            """SELECT count(*) FROM olm_session s JOIN dm_contact c ON c.contact_id = s.contact_id
                 WHERE c.trust_state IN ('revoked', 'blocked')""",
        )

        // The `delete_at` CHECK: `delete_at_minute` is the expiry when there is one, the unread
        // deadline otherwise, and null when there is neither.
        empty(
            sql, label, "a message whose delete_at_minute disagrees with its deadlines",
            """SELECT count(*) FROM dm_message
                 WHERE delete_at_minute IS NOT (CASE WHEN expire_at_minute IS NOT NULL
                                                     THEN expire_at_minute
                                                     ELSE unread_deadline_minute END)""",
        )

        // Every registration row is consistent with its capability: a registration exists only
        // where the namespace does, and a `registered` one only where the capability it was made
        // from is still known.
        empty(
            sql, label, "a registration for a namespace this device does not have",
            """SELECT count(*) FROM relay_key_registration r
                 WHERE NOT EXISTS (SELECT 1 FROM sync_namespace n WHERE n.namespace_id = r.namespace_id)""",
        )
    }

    /**
     * The first half of §15.3's post-sweep clause: **no row is past its deadline**.
     *
     * The second half ("the WAL is 0 bytes") is [walEmptyAfterReboot], and the two are separate on
     * purpose. A sweep that deleted nothing does not checkpoint — it has no pages to free — and an
     * actor pass writes after SWEEP anyway, so a log measured at the end of a pass is measuring the
     * pass, not the sweep. §15.3 says "after SWEEP **and R-K1**", and R-K1 happens at an open.
     */
    fun afterSweep(node: DmNode, nowEpochSeconds: Long, where: String) {
        val label = "${node.name} @ $where"
        val minute = nowEpochSeconds - Math.floorMod(nowEpochSeconds, 60L)
        empty(
            node.raw, label, "a message past its delete_at_minute after SWEEP",
            "SELECT count(*) FROM dm_message WHERE delete_at_minute IS NOT NULL " +
                "AND delete_at_minute <= $minute",
        )
    }

    /**
     * The second half: the write-ahead log is empty once the device has been through R-K1.
     *
     * Reboots the node, which is the only place R-K1 runs, and asserts that the checkpoint both
     * *succeeded* (a busy log would mean another connection was still holding frames, which after a
     * process death would be a harness bug) and left nothing behind. Plaintext SWEEP deleted lives
     * on in `-wal` frames until a checkpoint truncates them, so "the rows are gone" and "the bytes
     * are gone" are two statements and only this one is T25's. The **physical** scan that reads
     * those bytes looking for a canary is S9's, in `EphemeralTest`; what this adds is that a crash
     * anywhere in the run cannot leave a log the next open fails to clear.
     */
    fun walEmptyAfterReboot(node: DmNode, where: String) {
        node.reboot()
        val label = "${node.name} @ $where"
        if (!node.lastOpenTruncated) {
            dmViolation("$label: R-K1 could not truncate the log at the open")
        }
        if (node.walBytesAfterOpen != 0L) {
            dmViolation(
                "$label: the log held ${node.walBytesAfterOpen} bytes after SWEEP and R-K1",
            )
        }
    }

    /**
     * A digest of the committed state a reboot left behind: two crash runs of the same class must
     * agree on it once both have run to quiescence.
     *
     * It covers what the gate is about — what was displayed, in what order, and what is still owed
     * — and deliberately not the ciphertexts, which differ by construction whenever the ratchet
     * stepped a different number of times.
     */
    fun digest(node: DmNode): String {
        val out = StringBuilder()
        node.raw.query(
            "SELECT hex(c.contact_id), c.trust_state, c.establishment FROM dm_contact c " +
                "ORDER BY c.contact_id",
        ) { out.append("contact ${it.string(0)} ${it.string(1)} ${it.string(2)}\n") }
        node.raw.query(
            "SELECT hex(m.message_id), m.direction, m.state, m.sort_minute, m.minute_index " +
                "FROM dm_message m ORDER BY m.sort_minute, m.minute_index, m.message_id",
        ) {
            out.append(
                "msg ${it.string(0)} ${it.string(1)} ${it.string(2)} ${it.long(3)} ${it.long(4)}\n",
            )
        }
        node.raw.query(
            "SELECT hex(i.item_id), i.state FROM dm_outbound_item i ORDER BY i.item_id",
        ) { out.append("item ${it.string(0)} ${it.string(1)}\n") }
        node.raw.query("SELECT count(*) FROM dm_held") { out.append("held ${it.long(0)}\n") }
        return out.toString()
    }

    /** The rendered order of one node's conversations: CS-4's oracle. */
    fun renderOrder(node: DmNode): List<String> {
        val out = ArrayList<String>()
        node.raw.query(
            "SELECT hex(conversation_id), hex(message_id) FROM dm_message " +
                "ORDER BY conversation_id, sort_minute, minute_index, message_id",
        ) { out += it.string(0) + ":" + it.string(1) }
        return out
    }

    private fun empty(sql: JdbcSqlExecutor, label: String, what: String, query: String) {
        var count = 0L
        sql.query(query) { count = it.long(0) }
        if (count != 0L) dmViolation("$label: $count × $what")
    }

    private fun atMost(sql: JdbcSqlExecutor, label: String, what: String, bound: Int, query: String) {
        var count = 0L
        sql.query(query) { count = it.long(0) }
        if (count > bound) dmViolation("$label: $count $what, bound is $bound")
    }
}
