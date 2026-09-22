package org.ghost.messaging.engine

import org.ghost.crypto.bridge.DmSessions
import org.ghost.messaging.api.MediaPort
import org.ghost.messaging.api.MessageId
import org.ghost.messaging.port.DmCheckpoint
import org.ghost.messaging.port.DmClock
import org.ghost.messaging.port.DmEnvelopes
import org.ghost.messaging.store.ContactStore
import org.ghost.messaging.store.HeldStore
import org.ghost.messaging.store.MessageStore
import org.ghost.messaging.store.OwnerStore
import org.ghost.messaging.store.SessionStore
import org.ghost.storage.StorageFullException
import org.ghost.sync.api.NamespaceId
import org.ghost.sync.api.Namespaces
import org.ghost.sync.api.SyncDatabase
import org.ghost.sync.api.SyncTransaction

/** What one SWEEP pass removed. Counts only — never an id, a time or a contact (T3, T33). */
internal class SweepReport(
    val messages: Int,
    val held: Int,
    val requests: Int,
    val pendingSends: Int,
    val seenTags: Int,
    val pairKeys: Int,
    val offers: Int,
    val generations: Int,
    val retiredSessions: Int,
    val provisional: Int,
    val peerPq: Int,
    val namespaces: Int,
    val prunedKeys: Int,
    /** False when the log was still held by a reader; the need is kept and retried (§10.7). */
    val checkpointed: Boolean,
) {
    val rows: Int
        get() = messages + held + requests + pendingSends + seenTags + pairKeys + offers +
            generations + retiredSessions + provisional + peerPq + namespaces

    /** The same report with the checkpoint's answer, which is decided after the commit. */
    fun withCheckpoint(truncated: Boolean): SweepReport = SweepReport(
        messages, held, requests, pendingSends, seenTags, pairKeys, offers, generations,
        retiredSessions, provisional, peerPq, namespaces, prunedKeys, truncated,
    )

    override fun toString(): String =
        "SweepReport(rows=$rows, pruned=$prunedKeys, checkpointed=$checkpointed)"
}

/**
 * **SWEEP** (Phase 9 design §7.2, §10.6, §10.7, §21.3 point 5, §21.12 point 3): the one
 * transaction that makes an expired message actually stop existing, followed by the checkpoint
 * that makes its pages leave the write-ahead log.
 *
 * Everything else in the ephemeral design decides *when* a row dies; this is what kills it. The
 * read filter of §10.7 point 4 hides an expired row from the screen and the DAO lint proves it,
 * but hidden is not gone: until this step runs, the ciphertext is on the disk under SQLCipher and
 * a seizure with the database key reads it.
 *
 * **One transaction, then two things after the commit** (§7.2's SWEEP row):
 * `checkpointTruncate()` and the notification count. Both are after the commit because both are
 * outside the database — the checkpoint pragma refuses to run inside a transaction at all, and a
 * notification posted before a commit is one a rollback would leave on the screen.
 *
 * **What it deletes**, in the order §10.6 lists and in the order the dependencies demand:
 *
 *  1. **held rows past `hold_until_minute`** — first, so that a generation whose last holder
 *     expires in this same pass can be erased in this same pass (§5.4, §22.13 item 10);
 *  2. **expired messages** (`delete_at_minute ≤ now_e`), at most [BATCH] per transaction, with
 *     their reactions, outbound items, ops, retained blobs and pending sends by `ON DELETE
 *     CASCADE`, and `MediaPort.onMessagesDeleted(tx, ids)` inside the same transaction;
 *  3. **expired requests** (`request_until_day`), each cascading its contact, session, pair keys
 *     and rows (§12.3);
 *  4. **pending sends past their `fail_after_hour`** whose message is still live (R-T5);
 *  5. **`dm_seen` tags past `until_day`** (D3's window, §21.10 point 3);
 *  6. **pair keys and offered roots past their windows**, after ratcheting forward — [PairKeySteps]
 *     owns both halves and MC-21 is the order;
 *  7. **bundle generations past `delete_after_day`**, never while a live held row names one;
 *  8. **retired `previous` sessions** at `retire_day`, and **`prov_env` past
 *     `prov_erase_minute`**;
 *  9. **stale `dm_peer_pq` rows** past their usable week (§22.8.6 rule 2);
 * 10. **orphaned namespaces** — `Namespaces.remove` for each `dm_orphan_namespace` row, deleting
 *     the row when it answers true (§21.12 point 3, R-M1);
 * 11. **skipped Olm keys older than 51 days** in every live session (`sessionPrune`, §7.7 point 4,
 *     mutant MC-30);
 * 12. **`dm_self.expiry_clock_minute`**, raised to `now_e` (R-T7).
 *
 * **What it must never do: `Outbox.cancel`** (§10.6, §21.10 point 2, mutant **ME-21**).
 *
 * > SWEEP never calls `Outbox.cancel` for a DM op: ops run to their outcome or deadline.
 *
 * The temptation is obvious — the message is gone, why keep storing it — and it is exactly wrong.
 * A cancel is **relay-visible**: it withdraws deliveries that were already scheduled, so a HIGH-mode
 * 5-minute message whose `not_before` falls after its own expiry would produce a different pattern
 * on the wire from a 1-hour one, which is the whole of NI-DM4. What the op still carries is E2E
 * ciphertext **no key on this device opens** — the item and its retained blob cascade away with
 * the message row here, and the Phase 7 payload is bounded by the op's outcome or its
 * `deadline_hour` (§21.10 point 2), which is what the T25 physical scan uses as its bound. There
 * is no call to `Outbox` anywhere in this file, and gate G-DM2 is what keeps it that way: `Sweeper.kt`
 * is on the gate's `REMOVE_ONLY` list, which permits `Namespaces.remove` and **nothing else**.
 *
 * **`now_e`, not the wall clock** (R-T7, §10.3): `max(floor_minute(wall), expiry_clock_minute)`,
 * and every sweep raises the stored half. A clock stepped backwards — by the user, by NTP, across
 * a reboot — never delays a deletion; a forward step deletes early, which is data loss and not a
 * leak, and is declared.
 */
internal class Sweeper(
    private val database: SyncDatabase,
    private val namespaces: Namespaces,
    private val envelopes: DmEnvelopes,
    private val pairKeys: PairKeySteps,
    private val checkpoint: DmCheckpoint,
    private val clock: DmClock,
    private val contexts: SelfContexts,
    private val media: MediaPort,
) {
    private val messages = MessageStore()
    private val contacts = ContactStore()
    private val held = HeldStore()
    private val sessions = SessionStore()
    private val owner = OwnerStore()

    /**
     * §10.7: a checkpoint that answered `busy = 1` is **not** forgotten — the need is kept here, in
     * memory, and retried at the next sweep. It is in memory on purpose: a column for it would be
     * one more time-shaped fact in the DM tables (T33), and the state it describes ("this process
     * has pages in the log it could not free") does not survive the process anyway — R-K1's open
     * checkpoint is what covers the restart.
     */
    private var checkpointDue: Boolean = false

    /**
     * Runs one SWEEP. Safe to call at any time and from any of the five triggers of §10.7.
     *
     * **A full disk does not stop the pass.** SWEEP is the first step of every actor pass
     * (§13.7's order), so a `StorageFullException` propagating out of it would take `RECV`,
     * `OUTCOME` and the bundle claims with it — a device that cannot delete would also stop
     * receiving, which is the opposite of what a disk-full device needs. `SQLITE_FULL` is a failed
     * **write** and a state of the device, not a bug (§13.1, §21.12 point 1): SQLite rolls its own
     * transaction back, nothing partial is committed, and the next sweep finds the same rows and
     * tries again. The report then reads as a sweep that deleted nothing, which is true.
     *
     * Nothing else is caught. A CHECK violation, a trigger abort or a constraint failure is a bug
     * in a rule this file is supposed to keep, and it belongs where it can be seen.
     */
    fun sweep(): SweepReport = try {
        sweepOrThrow()
    } catch (e: StorageFullException) {
        SweepReport(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, checkpointed = false)
    }

    private fun sweepOrThrow(): SweepReport {
        val nowE = expiryClockMinute()
        val today = DmTime.day(nowE)
        val week = DmTime.week(nowE)
        // Resolved **before** the transaction, like every other caller of `SelfContexts` since the
        // S8 review (§22.12 item 18b): `get()` opens a transaction of its own when its cache is
        // cold, and `SyncDatabase` refuses a nested one outright.
        val canPrune = contexts.get() != null && envelopes.isAvailable()
        val report = database.transaction { tx -> inside(tx, nowE, today, week, canPrune) }
        // After the commit, and outside any transaction: the pragma refuses to run inside one.
        val truncated = if (report.rows > 0 || report.prunedKeys > 0 || checkpointDue) {
            checkpoint.truncate()
        } else {
            // Nothing was freed and nothing is owed, so there is nothing to truncate. Running the
            // pragma anyway would be a write on every pass of an idle device (§2.3's own reason
            // for making the Phase 7 GC checkpoint conditional).
            true
        }
        checkpointDue = !truncated
        return report.withCheckpoint(truncated)
    }

    /**
     * The next minute at which **anything** of this device becomes due: the wake the actor timer
     * and the alarm are set to (§10.7 triggers 1 and 5, §21.9 rule 1's
     * `min(next delete_at_minute, t_pub, next due_minute, next week boundary, next EST timer)`).
     *
     * Null means nothing is pending, which both the timer and the alarm read as "cancel" — and
     * cancelling is a rule rather than tidiness: an alarm left standing is an expiry minute a
     * rooted examiner can read out of the system's alarm table (L7-D7).
     *
     * `t_pub` and the week boundary are **not** in this minimum; see §22.14's forward note for why
     * and for what the slice that adds them must do.
     */
    fun nextWakeMinute(): Long? {
        val nowMinute = expiryClockMinute()
        return database.transaction { tx ->
            listOfNotNull(
                messages.nextDeleteAtMinute(tx.sql, nowMinute),
                held.nextHoldDeadline(tx.sql, nowMinute),
                held.nextDueMinute(tx.sql, nowMinute),
                sessions.nextProvisionalErase(tx.sql, nowMinute),
                contacts.nextFetchDeadline(tx.sql, nowMinute),
            ).minOrNull()
        }
    }

    /** The live unread count the notification port is given after a commit (§10.6, §10.7). */
    fun unreadCount(): Int {
        val nowMinute = expiryClockMinute()
        return database.transaction { tx -> messages.unreadCount(tx.sql, nowMinute) }
    }

    /** R-T7: `now_e = max(floor_minute(wall), dm_self.expiry_clock_minute)`. */
    private fun expiryClockMinute(): Long {
        val wall = DmTime.floorMinute(clock.nowEpochSeconds())
        val stored = database.transaction { tx -> owner.self(tx.sql)?.expiryClockMinute }
        return maxOf(wall, stored ?: wall)
    }

    @Suppress("LongMethod")
    private fun inside(
        tx: SyncTransaction,
        nowE: Long,
        today: Long,
        week: Long,
        canPrune: Boolean,
    ): SweepReport {
        // 1. Held rows first: a generation whose last holder expires now is erasable now (§5.4).
        val heldRows = held.deleteExpiredHeld(tx, nowE)

        // 2. Expired messages, with the media port inside the same transaction (§10.6).
        val expired = messages.expiredMessages(tx.sql, nowE, BATCH)
        if (expired.isNotEmpty()) {
            media.onMessagesDeleted(tx, expired.map { MessageId(it) })
        }
        var messageRows = 0
        for (messageId in expired) messageRows += messages.deleteMessage(tx, messageId)

        // 3. Requests past their day: the contact goes and everything of it cascades (§12.3).
        //
        // This deletes the contact row directly rather than through `ContactSteps.deleteContact`,
        // and the difference is the orphan namespaces §21.12 point 3 makes that step record
        // fail-closed. A contact in `request` has none: `X_c` is registered by SEND's step S7 and
        // by the contact half of KEEPER, both of which refuse a contact the user cannot send to,
        // and `P_c` by `EST-START`, which a request never reaches. So there is nothing to record,
        // and recording nothing is correct here rather than a gap — which is worth saying, because
        // the S7 review found the opposite shape (a delete that committed with no orphan row).
        var requestRows = 0
        for (contactId in contacts.expiredRequests(tx.sql, today, BATCH)) {
            requestRows += contacts.deleteContact(tx, contactId)
        }

        // 4. R-T5: an item that can no longer be stored anywhere fails, with its pending row.
        var pendingRows = 0
        for (pending in messages.expiredPendingSends(tx.sql, nowE, BATCH)) {
            messages.failPending(tx, pending.itemId)
            pendingRows += 1
        }

        // 5. D3's tags (§21.10 point 3).
        val seenRows = messages.deleteSeenTags(tx, today)

        // 6. Derive, then erase (§21.3 point 5, mutant MC-21).
        val pair = pairKeys.sweep(tx, nowE)

        // 7. Generations past their retention, never one a live held row names (§5.4, §22.13 item 10).
        var generationRows = 0
        for (genId in owner.erasableGenerations(tx.sql, today)) {
            generationRows += owner.deleteGeneration(tx, genId)
        }

        // 8. Retired sessions and expired provisional material (§8.7, §22.8.5 rule 4).
        val retired = sessions.deleteRetiredSessions(tx, today)
        val provisional = sessions.eraseExpiredProvisional(tx, nowE)

        // 9. Peer X-Wing keys past their usable week (§22.8.6 rule 2).
        val peerPqRows = contacts.deleteStalePeerPq(tx, week)

        // 10. Orphaned namespaces (§21.12 point 3). The one restricted call this file may make.
        var namespaceRows = 0
        for (namespace in contacts.orphans(tx.sql)) {
            if (namespaces.remove(tx, NamespaceId(namespace))) {
                contacts.deleteOrphan(tx, namespace)
                namespaceRows += 1
            }
        }

        // 11. The skipped-key age bound of §7.7 point 4 (mutant MC-30).
        val pruned = if (canPrune) pruneSkippedKeys(tx, today) else 0

        // 12. R-T7: the expiry clock only moves forward.
        owner.raiseExpiryClock(tx, nowE)

        return SweepReport(
            messages = messageRows,
            held = heldRows,
            requests = requestRows,
            pendingSends = pendingRows,
            seenTags = seenRows,
            pairKeys = pair.erased,
            offers = pair.offersErased + pair.offersDeleted,
            generations = generationRows,
            retiredSessions = retired,
            provisional = provisional,
            peerPq = peerPqRows,
            namespaces = namespaceRows,
            prunedKeys = pruned,
            checkpointed = false,
        )
    }

    /**
     * §7.7 point 4, as S0′ adopted it (V-15, Q67): every **live** session loses the skipped message
     * keys whose first-seen day is at least `FRESH + 2σ` = 51 days old.
     *
     * Without it, P-7 and T34 keep the declared exception §21.3 point 6 names: a root-carrying
     * message whose Olm key survives as a skipped key opens a pair envelope of a week whose pair
     * keys this sweep has just erased. Retired sessions need no prune — they are deleted whole at
     * their `retire_day`, a few lines above.
     *
     * A session whose state does not re-wrap is left alone rather than deleted: `StateCorrupt` is a
     * typed outcome (§2.1 rule 2) and a sweep is not the place to decide a session is unusable; the
     * next `decrypt` answers the same code and `UNACK_MAX` or the user's reset resolves it.
     * `Unavailable` (a locked or wiped context) stops the loop: there is nothing to prune with.
     */
    private fun pruneSkippedKeys(tx: SyncTransaction, today: Long): Int {
        var removed = 0
        for ((contactId, session) in sessions.allSessions(tx.sql)) {
            val result = envelopes.prune(
                contactId = contactId,
                slot = DmSessions.StoredSlot(session.sessionId, session.stateEnv),
                today = today.toInt(),
            )
            when (result) {
                is DmSessions.Pruned.Ok -> {
                    if (result.removed > 0) {
                        sessions.setStateEnv(tx, contactId, session.slot, result.stateEnv)
                        removed += result.removed.toInt()
                    }
                }
                DmSessions.Pruned.StateCorrupt -> Unit
                DmSessions.Pruned.Unavailable -> return removed
            }
        }
        return removed
    }

    companion object {
        /** §10.6: "at most 500 per transaction". */
        const val BATCH: Int = 500
    }
}
