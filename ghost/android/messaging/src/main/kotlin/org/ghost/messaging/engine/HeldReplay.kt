package org.ghost.messaging.engine

import org.ghost.crypto.bridge.L1
import org.ghost.messaging.port.DmClock
import org.ghost.messaging.port.DmEnvelopes
import org.ghost.messaging.store.ContactStore
import org.ghost.messaging.store.HeldStore
import org.ghost.sync.api.SyncDatabase

/**
 * **HELD** (Phase 9 design §7.2, §8.3, §22.8.1): the held rows of a contact, replayed after the
 * user accepted its key change.
 *
 * **The order is the whole of §22.8.1.** A contact whose Olm identity changed sends several PreKey
 * messages of **one** new session before the user decides. vodozemac does not consume fallback
 * keys, and it decrypts a later chain index by skipping keys, so a second `sessionInbound` on the
 * same PreKey data succeeds and returns the **same** `session_id`: the insert then breaks
 * `UNIQUE (contact_id, session_id)` or the `olm_prekey_used` primary key, an abort §21.4 rule 5
 * classes as a bug — and a crash loop, because HELD has no offer counter to stop it. `held_id` is
 * random, so a replay in row order was also an arbitrary permutation against Olm's
 * 40-skipped-keys window.
 *
 * So the rows are parsed first, grouped by `session_id`, the groups ordered by their smallest
 * `consume_minute` and the rows inside a group by the inner chain index (`held_id` breaking ties),
 * and **each row runs through `RECV`'s own R7 dispatch** ([ReceiveStep.replayHeld]): a `session_id`
 * that matches a slot decrypts on that slot; otherwise `(gen_id, session_id)` in `olm_prekey_used`
 * is a replay; otherwise `sessionInbound` with the row's `gen_id` and `prov_env`. Either order
 * against a `RECV` pass that created the session first is then correct, which is why §22.8.1 rule
 * 3's "HELD before the peek" is a preference and not a requirement.
 *
 * **One transaction per row** (§22.8.1 rule 2), like `RECV`'s one per blob: a row that drops must
 * not roll back the ones already applied, and each row's ratchet step has to commit with the
 * deletion of the row it came from.
 *
 * **What this file may not do**, and what gate G-DM2 checks by reading it: §21.7 point 7's "RECV,
 * BUNDLE and HELD never call `Outbox.enqueue`, `Namespaces.*`, `Registrations` or
 * `Capabilities.put`". A replay is local work on ciphertext this device already holds; nothing
 * about it reaches a relay (T28, and the behavioural half is `NoReflexTest`).
 */
internal class HeldReplay(
    private val database: SyncDatabase,
    private val envelopes: DmEnvelopes,
    private val receiveStep: ReceiveStep,
    private val clock: DmClock,
    private val contexts: SelfContexts,
    private val counters: DmCounters,
) {
    private val contacts = ContactStore()
    private val held = HeldStore()
    private val expiry = ExpiryClock(database, clock)

    /** How one replay pass went. Counts only (T3). */
    class Report(val applied: Int, val dropped: Int) {
        /** Whether anything at all was replayed. */
        val touched: Boolean get() = applied + dropped > 0

        override fun toString(): String = "Report(applied=$applied, dropped=$dropped)"
    }

    /**
     * Replays every live held row of one contact, in §22.8.1's order.
     *
     * A row is deleted whatever its outcome — applied, duplicate, replay, undecryptable — because
     * the decision it was waiting for has been taken and no later pass could do better with it.
     * A row past its `hold_until_minute` is not read at all ([HeldStore.heldFor]) and is left for
     * SWEEP, which owns deletion by time (slice S9).
     *
     * **Two things stop the pass rather than dropping a row**, and both are states in which a
     * deletion would destroy the only copy of a ciphertext for a reason that is not the row's:
     *  - the DM context closing under it (`CRYPTO_UNAVAILABLE`, here and at the parse);
     *  - the contact leaving the two trust states a session may be built in. `RECV` drops a
     *    blocked or revoked contact before any session call (R5, §7.4) and the replay owes the
     *    same guard: the list this loop walks was read **before** the first transaction, and a
     *    `revocation` TLV inside an earlier row revokes the contact and deletes its held rows
     *    (§8.5) while the loop still holds them in memory. Without the guard the next group
     *    would run `sessionInbound` and insert an `olm_session` row for a revoked contact, which
     *    §8.2 rule 4 forbids, and show its messages, which §8.5 does.
     */
    @Suppress("ReturnCount")
    fun replay(contactId: ByteArray): Report {
        val self = contexts.get() ?: return Report(0, 0)
        val now = clock.nowEpochSeconds()

        // The read and the parse happen outside the per-row transactions, like every other step's
        // native work (§7.2's "each step is exactly one transaction", §22.11 item 17): a parse
        // inside the writing transaction would commit half a replay while reporting an error.
        //
        // `hold_until_minute` is compared against `now_e` (R-T7): a row past its hold is SWEEP's,
        // and a clock stepped backwards must not hand it back to the replay.
        val rows = database.transaction { tx ->
            held.heldFor(tx.sql, contactId, expiry.nowMinute(tx.sql))
        }
        if (rows.isEmpty()) return Report(0, 0)
        // Null: the library went away mid-parse. Nothing is deleted and nothing is counted — the
        // next pass reads the same rows.
        val ordered = order(self, rows) ?: return Report(0, 0)

        var applied = 0
        var dropped = 0
        for (parsed in ordered) {
            val outcome: ReceiveStep.Result? = database.transaction { tx ->
                // The contact row is gone (`deleteContact`, and the held rows cascaded with it):
                // there is nothing left to replay and nothing to count.
                val contact = contacts.contact(tx.sql, contactId)
                    ?: return@transaction null
                // RECV's R5, re-read inside every row's own transaction: see the KDoc above.
                if (contact.trust != ContactStore.Trust.UNVERIFIED &&
                    contact.trust != ContactStore.Trust.VERIFIED
                ) {
                    return@transaction null
                }
                // A row whose ciphertext did not open or whose L1 did not parse: counted here,
                // inside the transaction that deletes it, so a pass that stops early cannot count
                // the same row twice.
                parsed.broken?.let { reason ->
                    held.deleteHeld(tx, parsed.row.heldId)
                    counters.drop(reason)
                    return@transaction ReceiveStep.Result.DROPPED
                }
                // The user's decision pinned the new identity; a contact that went back to
                // `changed` under a **third** key while this pass ran keeps its new rows, and
                // this one is no longer replayable under the pin it was held for. (`changed` is
                // refused by the trust guard above; this catches the rest.)
                if (contact.pinnedIdentity?.contentEquals(parsed.row.identity) != true) {
                    held.deleteHeld(tx, parsed.row.heldId)
                    return@transaction ReceiveStep.Result.DROPPED
                }
                val result = receiveStep.replayHeld(
                    tx = tx,
                    self = self,
                    contact = contact,
                    row = parsed.row,
                    l1 = parsed.l1,
                    sessionId = parsed.sessionId,
                    bindingSeconds = parsed.groupMinute,
                    now = now,
                )
                if (result != ReceiveStep.Result.CRYPTO_UNAVAILABLE) {
                    held.deleteHeld(tx, parsed.row.heldId)
                }
                result
            }
            when (outcome) {
                null -> return Report(applied, dropped)
                ReceiveStep.Result.APPLIED -> applied += 1
                ReceiveStep.Result.CRYPTO_UNAVAILABLE -> return Report(applied, dropped)
                else -> dropped += 1
            }
        }
        return Report(applied, dropped)
    }

    /** A held row with its ciphertext opened and its Olm header read (§22.8.1 rule 1). */
    private class Parsed(
        val row: HeldStore.HeldRow,
        val l1: ByteArray,
        val sessionId: ByteArray,
        val chainIndex: Long,
        /**
         * The **group's** smallest `consume_minute`, which is R-SS1's session-age input for every
         * row of the group (§22.13 item 3). Never the row's own: see [order].
         */
        val groupMinute: Long = 0,
        /** Why this row cannot be replayed, or null; the caller counts it and deletes the row. */
        val broken: DmCounters.Reason? = null,
    )

    /**
     * §22.8.1 rule 1: grouped by `session_id`, the groups by their smallest `consume_minute`, the
     * rows inside a group by the inner chain index, `held_id` breaking every remaining tie.
     *
     * Null when the library went away mid-parse: the caller then replays nothing, because a row
     * that did not parse for want of a context is not a row that cannot be replayed.
     *
     * A row whose `l1_env` does not open under the content key, or whose L1 does not parse as a
     * PreKey message, is left out of the order and **deleted** by the caller's loop as a drop: it
     * cannot be replayed and nothing later could change that.
     *
     * **Each row carries its group's minute, not its own** (§22.13 item 3a). The group order and
     * R-SS1's input have to be the **same** number or the invariant that justifies the
     * substitution is not the one the code keeps: §22.8.4 rule 2 drops a first flight older than
     * both stored responder sessions, so the groups must reach `admitNewInbound` in nondecreasing
     * binding order. Groups are ordered by their smallest `consume_minute`, but the row that
     * reaches `admitNewInbound` is the one with the lowest **chain index**, and §7.7's gap hold
     * tolerates a chain order that is not the arrival order. Feeding that row's own minute would
     * present the groups out of order and `drop(stale_session)` a whole group — every message of a
     * session, lost inside the decision that released it.
     */
    private fun order(self: SelfContext, rows: List<HeldStore.HeldRow>): List<Parsed>? {
        val parsed = ArrayList<Parsed>(rows.size)
        val broken = ArrayList<Parsed>()
        for (row in rows) {
            val l1 = self.content.open(row.l1Env, row.heldId)
            if (l1 == null) {
                broken += Parsed(row, EMPTY, EMPTY, 0, broken = DmCounters.Reason.STATE_CORRUPT)
                continue
            }
            when (val header = envelopes.parseL1(l1, isPreKey = true)) {
                is L1.PreKey -> parsed += Parsed(row, l1, header.sessionId, header.chainIndex)
                // Not a statement about the bytes: the context closed. Nothing is deleted.
                L1.Unavailable -> return null
                // Only PreKey messages are ever held (§8.3: a normal message of a session under the
                // **old** pinned identity is shown, because it was authenticated to it).
                is L1.Normal, L1.Invalid ->
                    broken += Parsed(row, EMPTY, EMPTY, 0, broken = DmCounters.Reason.NON_CANONICAL)
            }
        }
        val firstConsume = HashMap<List<Byte>, Long>()
        for (item in parsed) {
            val key = item.sessionId.toList()
            val seen = firstConsume[key]
            if (seen == null || item.row.consumeMinute < seen) {
                firstConsume[key] = item.row.consumeMinute
            }
        }
        val ordered = parsed
            .map { Parsed(it.row, it.l1, it.sessionId, it.chainIndex, firstConsume.getValue(it.sessionId.toList())) }
            .sortedWith(
                compareBy<Parsed> { it.groupMinute }
                    .thenBy { it.sessionId.joinToString("") { b -> "%02x".format(b) } }
                    .thenBy { it.chainIndex }
                    .thenBy { it.row.heldId.joinToString("") { b -> "%02x".format(b) } },
            )
        // The unreplayable rows go last, so a broken row cannot delay a good one; each is deleted
        // by the loop above, which finds its pin check or its dispatch refuses it.
        return ordered + broken
    }

    private companion object {
        val EMPTY = ByteArray(0)
    }
}
