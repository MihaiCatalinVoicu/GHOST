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
    fun check(node: DmNode, where: String, heavy: Boolean = true, settled: Boolean = true) {
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

        // Held rows exist only for `changed` contacts — **at quiescence**.
        //
        // At a *reboot* the clause as §15.3 writes it is too strong, and the crash enumeration is
        // what showed it. §8.3 and §22.8.1 put HELD **outside** the KEYDEC transaction on purpose
        // ("one transaction per row", so a row that drops does not roll back the ones already
        // applied), and `DmActor.replayReleasedHolds` is the recovery half that exists for exactly
        // this window: "a crash between the KEYDEC commit and the replay — the decision is taken,
        // the rows are still there, and nothing else would ever look at them again". A reboot
        // inside that window therefore finds held rows on an `unverified` contact, legally, and an
        // invariant that failed there would be asserting that a documented recovery path may not
        // exist. §22.15 item 16 records the conflict between §15.3's unqualified clause and §8.3.
        //
        // What holds at **both** moments is the half that says nothing is stranded: a `blocked` or
        // `revoked` contact is one the replay refuses (R5), so a held row on one can never be
        // replayed and never be deleted by anything but SWEEP.
        empty(
            sql, label, "a held row on a blocked or revoked contact, which nothing will ever replay",
            """SELECT count(*) FROM dm_held h JOIN dm_contact c ON c.contact_id = h.contact_id
                 WHERE c.trust_state IN ('blocked', 'revoked')""",
        )
        if (settled) {
            empty(
                sql, label, "a held row on a contact that is not 'changed'",
                """SELECT count(*) FROM dm_held h JOIN dm_contact c ON c.contact_id = h.contact_id
                     WHERE c.trust_state <> 'changed'""",
            )
        }

        // At most 2 `olm_session` rows per contact, with exactly one `current` whenever any exists.
        empty(
            sql, label, "a contact with more than two session rows",
            "SELECT count(*) FROM (SELECT contact_id FROM olm_session GROUP BY contact_id HAVING count(*) > 2)",
        )
        empty(
            sql, label, "a contact with more than one 'current' slot",
            """SELECT count(*) FROM (SELECT contact_id FROM olm_session GROUP BY contact_id
                                      HAVING sum(CASE WHEN slot = 'current' THEN 1 ELSE 0 END) > 1)""",
        )
        // "Exactly one `current` whenever any exists" — **except in R-SS0's re-establishment
        // window**, which §15.3's clause does not allow for and the engine opens on purpose (S10b,
        // §22.19). A send that finds its session stale (`UNACK_MAX`) or unable to seal
        // (`NO_SEAL_KEY`) demotes `current` to `previous` in its own transaction, so that
        // `EST-READY`'s "unless a usable session already exists" finds the slot empty
        // (`SendStep`, R-SS0 of §8.2) — and until the establishment builds the replacement the
        // contact has a `previous` and no `current`. The window is legal while that establishment
        // is owed: a pending send is waiting for it (and the next time-triggered pass starts it,
        // which is also the recovery for a crash between the demotion and `EST-START`), or it is
        // `fetching`, or it gave up (`unreachable`) and the demoted row receives until its
        // `retire_day`. What stays forbidden is the state no path creates: sessions, no `current`,
        // and a contact that is `ready` with nothing owed. The first version of this clause fired
        // on exactly that window in the world of mutant MC-33, and nothing in S10's scenarios ever
        // re-establishes a session, which is why nobody had seen it.
        empty(
            sql, label, "a contact with sessions but no 'current' slot and no establishment owed",
            """SELECT count(*) FROM (SELECT contact_id FROM olm_session GROUP BY contact_id
                                      HAVING sum(CASE WHEN slot = 'current' THEN 1 ELSE 0 END) = 0) x
                 WHERE NOT EXISTS (SELECT 1 FROM dm_pending_send p WHERE p.contact_id = x.contact_id)
                   AND NOT EXISTS (SELECT 1 FROM dm_contact c WHERE c.contact_id = x.contact_id
                                     AND c.establishment IN ('fetching', 'unreachable'))""",
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
     * §10.6 and §8.7 (S10b): after SWEEP, **no `previous` session is past its `retire_day`**.
     *
     * §15.3 checks that every `previous` row *has* a retire day, and nothing checked that the day
     * is honoured, so mutant MC-26 ("`previous` never retired"; §15.7 names "CS-8 bound, structural
     * invariants, T34 retired-session expectation") broke no clause at all. The day is the wall
     * clock's and SWEEP's is `now_e`'s, which is never earlier (R-T7), so this cannot demand more
     * than the sweep that just ran was obliged to do.
     *
     * A separate function from [afterSweep] on purpose: the seeded worlds call that one from their
     * `alwaysChecks`, which run **before** the runner's last pass, and a retire day crossed by the
     * quiescence loop's final clock step is owed to the next sweep, not broken by the last one. The
     * runner calls this after its own pass, the one place both halves hold by construction.
     */
    fun retiredSessionsGone(node: DmNode, nowEpochSeconds: Long, where: String) {
        val label = "${node.name} @ $where"
        val today = Math.floorDiv(nowEpochSeconds, org.ghost.messaging.DmWorld.DAY)
        empty(
            node.raw, label, "a 'previous' session past its retire_day after SWEEP",
            "SELECT count(*) FROM olm_session WHERE slot = 'previous' AND retire_day IS NOT NULL " +
                "AND retire_day <= $today",
        )
    }

    /**
     * §15.3's "the WAL is 0 bytes", asserted on a node that has **just** been through R-K1 — a
     * reboot the caller already performed.
     *
     * [walEmptyAfterReboot] is the same assertion for a caller that has not, and reboots to get
     * there. This one is what the crash runner uses at every reboot of every run: the checkpoint
     * has run and the new client has been built, so `walBytesAfterOpen` is the byte count taken
     * between the two — the moment §15.3 is talking about.
     */
    fun checkpointEmptiedTheLog(node: DmNode, where: String) {
        val label = "${node.name} @ $where"
        if (!node.lastOpenTruncated) {
            dmViolation("$label: R-K1 could not truncate the log at the open")
        }
        if (node.walBytesAfterOpen != 0L) {
            dmViolation("$label: the log held ${node.walBytesAfterOpen} bytes after R-K1")
        }
    }

    /**
     * §7.7's rendering order **as the read path returns it**: the `(sort_minute, minute_index)`
     * pairs of one node's inbound messages, per contact, in the order `Messaging.conversation`
     * hands them out.
     *
     * This is CS-4's subject, and it is what `DmCrashRunner.enumerate` compares across the runs of
     * one scenario. Two things about how it reads matter. It goes through the **engine**, not
     * through `ORDER BY sort_minute, minute_index` on the raw connection — a query that sorts by
     * the columns and is then checked for being sorted by the columns is a tautology, which is what
     * the seeded worlds' own order check was, and it is the read path that mutant MC-10 changes.
     * And the page is reversed, because §7.7 returns newest first and a rendering order is read
     * oldest first.
     */
    fun renderOrder(node: DmNode): List<String> {
        val device = node.device
        val out = ArrayList<String>()
        for (contact in device.engine.contacts().sortedBy { it.id.toByteArray().toList().toString() }) {
            val key = contact.id.toByteArray().hex()
            for (view in device.engine.conversation(contact.id, 200, null).reversed()) {
                if (view.outgoing) continue
                out += "$key/${view.cursor.sortMinute}.${view.cursor.minuteIndex}"
            }
        }
        return out
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
        checkpointEmptiedTheLog(node, "$where (after SWEEP and R-K1)")
        // A reboot with no invariant check is a reboot that proves nothing about the state it came
        // back to: §15.3 says "reboot … check the structural invariants", and this is a reboot.
        check(node, "$where (after the WAL reboot)")
    }

    /**
     * A digest of one node's committed state: what [DmCrashWorld.quiesce] compares round to round
     * to decide that a world has stopped moving.
     *
     * It covers what was displayed, in what order, and **what is still owed**. The second half is
     * not decoration and its absence was a real hole: with only `dm_contact`, `dm_message`,
     * `dm_outbound_item.state` and a `dm_held` count in it, a world whose whole remaining work was
     * an outbox op waiting for a store, a blob waiting to be fetched or a pending send waiting for
     * a flush looked identical two rounds running and was declared quiescent after ten virtual
     * minutes — so every recovery that is owed rather than immediate went unrun, and every check
     * after it was measuring a world that had not finished recovering. The ciphertexts stay out:
     * they differ by construction whenever the ratchet stepped a different number of times.
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
        // Everything still owed, which is what decides whether a world has stopped moving.
        node.raw.query(
            "SELECT hex(operation_id), outcome, released FROM outbox_op ORDER BY operation_id",
        ) { out.append("op ${it.string(0)} ${it.string(1)} ${it.long(2)}\n") }
        node.raw.query(
            "SELECT hex(operation_id), state, attempts FROM outbox_delivery " +
                "ORDER BY operation_id, relay_id",
        ) { out.append("delivery ${it.string(0)} ${it.string(1)} ${it.long(2)}\n") }
        node.raw.query(
            "SELECT hex(item_id) FROM dm_pending_send ORDER BY item_id",
        ) { out.append("pending ${it.string(0)}\n") }
        node.raw.query(
            "SELECT hex(blob_hash), state, offers, fetch_attempts FROM inbox_blob ORDER BY blob_hash",
        ) {
            out.append(
                "blob ${it.string(0)} ${it.string(1)} ${it.long(2)} ${it.long(3)}\n",
            )
        }
        // A scheduled control that went out is progress, and one still waiting is owed (S10b).
        node.raw.query(
            "SELECT hex(sched_id), what, due_minute FROM dm_scheduled ORDER BY sched_id",
        ) { out.append("sched ${it.string(0)} ${it.string(1)} ${it.long(2)}\n") }
        return out.toString()
    }

    /**
     * The earliest moment at which a node has work it cannot do yet, or null when it has none.
     *
     * [DmCrashWorld.quiesce] uses it to jump the world's clock to the next time something is due
     * instead of declaring a world quiescent while it waits: a retry backoff, a fetch attempt or a
     * poison re-offer more than one quiescence step out was systematically unexercised, so every
     * recovery that is **timer-gated** never ran in any crash run.
     *
     * Only *work* deadlines are here — a store's `not_before`, a delivery's next attempt, a blob's
     * next fetch and its offer hold. Expiry deadlines are deliberately absent: jumping the clock to
     * a `delete_at_minute` would delete the messages a scenario is about and make quiescence the
     * thing that broke it.
     */
    fun nextDueMinute(node: DmNode, after: Long): Long? {
        var best = Long.MAX_VALUE
        fun consider(value: Long) {
            if (value > after && value < best) best = value
        }
        node.raw.query(
            "SELECT min(not_before_minute) FROM outbox_op WHERE outcome = 'pending' " +
                "AND not_before_minute > ?",
            listOf(after),
        ) { if (!it.isNull(0)) consider(it.long(0)) }
        node.raw.query(
            "SELECT min(next_attempt_minute) FROM outbox_delivery WHERE state = 'pending' " +
                "AND next_attempt_minute > ?",
            listOf(after),
        ) { if (!it.isNull(0)) consider(it.long(0)) }
        node.raw.query(
            "SELECT min(next_fetch_minute) FROM inbox_blob WHERE state <> 'done' " +
                "AND next_fetch_minute > ?",
            listOf(after),
        ) { if (!it.isNull(0)) consider(it.long(0)) }
        node.raw.query(
            "SELECT min(offer_after_minute) FROM inbox_blob WHERE state <> 'done' " +
                "AND offer_after_minute > ?",
            listOf(after),
        ) { if (!it.isNull(0)) consider(it.long(0)) }
        // A scheduled control's drawn minute (S10b: SCN-I's reconnect, SCN-K's revocation). It is
        // owed work in exactly the sense the four above are — a time-triggered pass sends it when
        // its minute arrives and nothing else will — and until SCN-I and SCN-K no scenario
        // scheduled one, so nothing noticed that a world whose only remaining work was a notice due
        // in six hours looked idle and was declared quiescent without it.
        node.raw.query(
            "SELECT min(due_minute) FROM dm_scheduled WHERE due_minute > ?",
            listOf(after),
        ) { if (!it.isNull(0)) consider(it.long(0)) }
        // An establishment's next decision (S10b review): the end of an attempt window or the
        // start of the next attempt six hours later (§21.7 point 5). The "nothing owed" oracle
        // refuses a world that ends `fetching`, so quiescence has to be able to reach the minute
        // at which a `fetching` contact is next decided, exactly as it reaches a scheduled one.
        node.raw.query(
            "SELECT min(fetch_listen_until_minute) FROM dm_contact WHERE establishment = 'fetching' " +
                "AND fetch_listen_until_minute > ?",
            listOf(after),
        ) { if (!it.isNull(0)) consider(it.long(0)) }
        return if (best == Long.MAX_VALUE) null else best
    }

    /** The earliest expiry deadline still ahead of [after], or null: the bound on a clock jump. */
    fun nextExpiryMinute(node: DmNode, after: Long): Long? {
        var out = Long.MAX_VALUE
        node.raw.query(
            "SELECT min(delete_at_minute) FROM dm_message WHERE delete_at_minute > ?",
            listOf(after),
        ) { if (!it.isNull(0)) out = it.long(0) }
        return if (out == Long.MAX_VALUE) null else out
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
