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

    /** One sweep may take several transactions (§10.6 bounds the transaction, not the sweep). */
    operator fun plus(other: SweepReport): SweepReport = SweepReport(
        messages + other.messages,
        held + other.held,
        requests + other.requests,
        pendingSends + other.pendingSends,
        seenTags + other.seenTags,
        pairKeys + other.pairKeys,
        offers + other.offers,
        generations + other.generations,
        retiredSessions + other.retiredSessions,
        provisional + other.provisional,
        peerPq + other.peerPq,
        namespaces + other.namespaces,
        prunedKeys + other.prunedKeys,
        checkpointed = checkpointed && other.checkpointed,
    )

    /**
     * True when a batch was filled, so more rows of the same kind are already due. §10.6 bounds
     * one **transaction** at [Sweeper.BATCH]; a device that comes back to thousands of expired
     * rows drains them over several transactions of one sweep, not over several sweeps — the
     * leftovers have deadlines in the **past**, and every "next wake" query is strictly in the
     * future, so nothing would be scheduled to come back for them.
     */
    val batchWasFull: Boolean
        get() = messages >= Sweeper.BATCH || requests >= Sweeper.BATCH || pendingSends >= Sweeper.BATCH

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
 *     CASCADE`, and `MediaPort.onMessagesDeleted(tx, ids)` inside the same transaction; the `M_c`
 *     orphan rule (Phase 11 design §5.1) reads its candidates before this cascade and records the
 *     orphan after it — post-cascade the upload is over, the descriptor is final and the media
 *     ops read as released, which is exactly the "or SWEEP" clause of the rule's producers;
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
    private val mediaOrphans: MediaOrphanSteps,
    /**
     * §11.1's media half (the S8 review's R1): key erasures that ran outside SWEEP —
     * `VIEW-ONCE-OPEN`, the outcome/deadline sender cleanups — record a busy or failed
     * checkpoint here, and this sweep re-asks the pragma for them. Defaulted where no
     * media layer shares the state; `MessagingRuntime` wires the one shared instance.
     */
    private val mediaCheckpoint: MediaCheckpointState = MediaCheckpointState(),
) {
    private val messages = MessageStore()
    private val contacts = ContactStore()
    private val held = HeldStore()
    private val sessions = SessionStore()
    private val owner = OwnerStore()
    private val expiry = ExpiryClock(database, clock)

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
     * The guard covers the **deletion** and the checkpoint separately, because they fail
     * differently and one of them must not erase the other's answer: see the comment at the
     * checkpoint below.
     *
     * Nothing else is caught. A CHECK violation, a trigger abort or a constraint failure is a bug
     * in a rule this file is supposed to keep, and it belongs where it can be seen.
     */
    fun sweep(): SweepReport {
        val report = try {
            deleteOrThrow()
        } catch (e: StorageFullException) {
            NOTHING
        }
        // After the commit, and outside any transaction: the pragma refuses to run inside one.
        //
        // It is **outside** the `catch` above on purpose (found by the S9 review). While the whole
        // pass was one guarded block, a `SQLITE_FULL` raised by the pragma — which is a write, and
        // exactly the state a disk-full device is in — discarded the counts of a transaction that
        // had already committed *and* skipped the `checkpointDue = !truncated` below, so the debt
        // was lost: the next sweep saw `rows = 0`, ran no pragma, and the freed plaintext pages
        // stayed in the `-wal` for the life of the process. A failed checkpoint is the same kind
        // of answer as a busy one and is kept the same way (§10.7, mutant ME-10).
        //
        // The media debt (§11.1, [MediaCheckpointState]) stands in the same `owed`: a sweep
        // that deleted nothing still re-asks the pragma when a media key erasure's checkpoint
        // stayed busy — the erased key's pre-image sits in the `-wal` until some pass runs
        // the pragma, and without this the next pass after a busy `VIEW-ONCE-OPEN` was an
        // idle sweep that owed nothing and truncated nothing (the S8 review's R1).
        val owed = report.rows > 0 || report.prunedKeys > 0 || checkpointDue || mediaCheckpoint.due
        val truncated = if (owed) {
            try {
                checkpoint.truncate()
            } catch (e: StorageFullException) {
                false
            }
        } else {
            // Nothing was freed and nothing is owed, so there is nothing to truncate. Running the
            // pragma anyway would be a write on every pass of an idle device (§2.3's own reason
            // for making the Phase 7 GC checkpoint conditional).
            true
        }
        checkpointDue = !truncated
        // A successful pragma truncates the whole log: it pays the media components' debt
        // together with this sweep's. A failed one leaves both flags standing.
        if (truncated) mediaCheckpoint.clearedBySweep()
        return report.withCheckpoint(truncated)
    }

    private fun deleteOrThrow(): SweepReport {
        val nowE = expiryClockMinute()
        val today = DmTime.day(nowE)
        val week = DmTime.week(nowE)
        // Resolved **before** the transaction, like every other caller of `SelfContexts` since the
        // S8 review (§22.12 item 18b): `get()` opens a transaction of its own when its cache is
        // cold, and `SyncDatabase` refuses a nested one outright. `self` also feeds the `M_c`
        // orphan rule's recording (§5.1's "or SWEEP"): a locked context cannot derive `M_c` from
        // the card, and the rule records nothing until a pass where it can.
        val self = contexts.get()
        val canPrune = self != null && envelopes.isAvailable()
        val nowSeconds = expiry.nowSeconds()
        // §10.6's 500 bounds a **transaction**, and this loop is why that is the right reading. A
        // device back after a long absence has more expired rows than one transaction may take,
        // and the leftovers are in the **past** — while every "next wake" query is strictly in the
        // future (`> now_e`), so a sweep that stopped at the batch would schedule nothing to come
        // back for them and they would wait for an unrelated trigger. `MAX_BATCHES` keeps one
        // sweep from becoming unbounded work on the actor thread; what it does not drain, the next
        // pass does, and the passes themselves are frequent.
        //
        // The loop tests the **last** transaction and not the running total: `batchWasFull` is a
        // property of one batch, and a total that had once reached 500 would stay above it and run
        // the loop to its bound every time.
        var last = database.transaction { tx -> inside(tx, nowE, today, week, canPrune, self, nowSeconds) }
        var report = last
        var batches = 1
        while (last.batchWasFull && batches < MAX_BATCHES) {
            // The skipped-key prune runs in the first transaction only: it is per session, not per
            // row, and repeating it would be work with no second effect.
            last = database.transaction { tx -> inside(tx, nowE, today, week, canPrune = false, self, nowSeconds) }
            report += last
            batches += 1
        }
        return report
    }

    /**
     * The next wake of this device: the minute at which **anything** becomes due, and the delay to
     * it (§10.7 triggers 1 and 5, §21.9 rule 1's `min(next delete_at_minute, t_pub, next
     * due_minute, next week boundary, next EST timer)`).
     *
     * Null means nothing is pending, which both the timer and the alarm read as "cancel" — and
     * cancelling is a rule rather than tidiness: an alarm left standing is an expiry minute a
     * rooted examiner can read out of the system's alarm table (L7-D7).
     *
     * **The delay is measured against `now_e`, not against the wall clock**, and it is computed
     * here because this is the only side that knows `now_e` (R-T7, §10.3). Before the S9 review
     * the port carried the absolute minute and each wake subtracted its own `clock.now`: a device
     * whose clock had been stepped back a day then scheduled the sweep a day late, and the
     * deletion R-T7 exists to protect waited for an unrelated trigger. `Sweeper` already compares
     * every deadline below against `now_e`, so the subtraction belongs beside the comparison.
     *
     * `t_pub` and the week boundary are **not** in this minimum; see §22.14's forward note for why
     * and for what the slice that adds them must do.
     */
    class Wake(
        /** The deadline itself, in unix seconds on the minute grid. */
        val minute: Long,
        /** `max(0, minute − now_e)`: what the timer sleeps and what the alarm adds to elapsed realtime. */
        val delaySeconds: Long,
    ) {
        override fun toString(): String = "Wake(in ${delaySeconds}s)"
    }

    fun nextWake(): Wake? {
        val nowSeconds = expiry.nowSeconds()
        val nowMinute = DmTime.floorMinute(nowSeconds)
        val next = database.transaction { tx ->
            listOfNotNull(
                messages.nextDeleteAtMinute(tx.sql, nowMinute),
                held.nextHoldDeadline(tx.sql, nowMinute),
                held.nextDueMinute(tx.sql, nowMinute),
                sessions.nextProvisionalErase(tx.sql, nowMinute),
                contacts.nextFetchDeadline(tx.sql, nowMinute),
            ).minOrNull()
        } ?: return null
        return Wake(next, maxOf(0L, next - nowSeconds))
    }

    /** The deadline half of [nextWake], for a caller that wants the minute and not the delay. */
    fun nextWakeMinute(): Long? = nextWake()?.minute

    /** The live unread count the notification port is given after a commit (§10.6, §10.7). */
    fun unreadCount(): Int {
        val nowMinute = expiryClockMinute()
        return database.transaction { tx -> messages.unreadCount(tx.sql, nowMinute) }
    }

    /** R-T7: `now_e = max(floor_minute(wall), dm_self.expiry_clock_minute)`. */
    private fun expiryClockMinute(): Long = expiry.nowMinute()

    @Suppress("LongMethod")
    private fun inside(
        tx: SyncTransaction,
        nowE: Long,
        today: Long,
        week: Long,
        canPrune: Boolean,
        self: SelfContext?,
        nowSeconds: Long,
    ): SweepReport {
        // 1. Held rows first: a generation whose last holder expires now is erasable now (§5.4).
        val heldRows = held.deleteExpiredHeld(tx, nowE)

        // 2. Expired messages, with the media port inside the same transaction (§10.6).
        //    The `M_c` orphan rule's candidates (§5.1's "or SWEEP") are read **before** the
        //    deletion: they are the contacts with `out` objects whose message is expiring, and the
        //    cascade below takes the objects — and the media-op mapping — with the messages.
        //    Evaluating the rule after the deletion is what lets the expired-descriptor path
        //    record the orphan at all: post-cascade nothing of the upload remains to block it,
        //    and no later transaction looks at the contact's media rows again.
        val mediaOrphanCandidates = mediaOrphans.candidates(tx.sql, nowE)
        val expired = messages.expiredMessages(tx.sql, nowE, BATCH)
        if (expired.isNotEmpty()) {
            media.onMessagesDeleted(tx, expired.map { MessageId(it) })
        }
        var messageRows = 0
        for (messageId in expired) messageRows += messages.deleteMessage(tx, messageId)
        for (contactId in mediaOrphanCandidates) {
            mediaOrphans.recordIfOrphaned(tx, self, contactId, nowSeconds)
        }

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
        //
        // A row whose namespace `:sync` does not hold at all is discharged as well (phase review
        // ENG-7). `remove` answers false both for "ops or fetched rows are left" and for "unknown
        // namespace", and only the first is a reason to wait: block, delete and a rejected or
        // blocked request record both of a card's namespaces whether or not anything registered
        // them — a contact deleted before it sent or fetched, a request, a responder that never
        // fetched the initiator's bundle — so those rows were kept for ever, where L7-D7 bounds
        // them at 7 days, and each is an HKDF output of the deleted card.
        var namespaceRows = 0
        for (namespace in contacts.orphans(tx.sql)) {
            val id = NamespaceId(namespace)
            if (namespaces.listening(tx, id) == null || namespaces.remove(tx, id)) {
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

        /**
         * How many of those transactions one sweep will run: 10 000 expired rows, which is far
         * more than a device reaches in a normal absence and still a bounded amount of work for
         * the actor thread, which is the thread every facade call waits on (§13.7).
         */
        const val MAX_BATCHES: Int = 20

        /** A pass that deleted nothing: what a full disk leaves behind (§21.12 point 1). */
        private val NOTHING = SweepReport(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, checkpointed = false)
    }
}
