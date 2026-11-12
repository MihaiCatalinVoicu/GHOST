package org.ghost.messaging.engine

import org.ghost.crypto.bridge.DmRevocations
import org.ghost.messaging.port.DmClock
import org.ghost.messaging.port.DmCrypto
import org.ghost.messaging.port.DmRandom
import org.ghost.messaging.store.ContactStore
import org.ghost.messaging.store.HeldStore
import org.ghost.sync.api.SyncDatabase

/**
 * The two **scheduled controls** of Phase 9 design §8.5 and §8.6 — the revocation notice and the
 * reconnect notice — and the step that sends them when their minute arrives.
 *
 * **Why they are scheduled at all, and why the offsets are persisted.** Both are user actions that
 * touch *every* contact at once, and a burst of k deposits into k inboxes inside one relay session
 * shows a degree of k (RP §3.8): AD-1 would read the whole contact list off the wire from a single
 * "I lost my phone". So each contact's notice is due at its own offset — `U[0, 24 h]` for a
 * revocation, `U[0, 48 h]` for a reconnect — **drawn at the action and written to
 * `dm_scheduled.due_minute`**, because an offset kept in memory collapses back into a burst at the
 * next process start.
 *
 * **They are time-triggered, not hint-triggered** (§21.9 rules 1 and 2). A due control goes out
 * from the actor timer, a database open or a relay session start, and never from an `INBOX` hint
 * or a facade call: otherwise a card holder with AD-1 could deposit a probe during this device's
 * session and watch the due notices follow a minute later (mutant PM-30, twin NI-DM6).
 *
 * **What this file may not do** is call `Outbox.enqueue` itself: it asks [SendStep], whose file is
 * the one gate G-DM2 allows for it, and whose CONTROL path is the same transaction a user send
 * takes — so a reconnect notice to a contact with no usable session becomes a pending item and
 * waits for the bundle, which is §21.8's own reason for making every outgoing L0 an item.
 */
internal class ScheduledSteps(
    private val database: SyncDatabase,
    private val crypto: DmCrypto,
    private val sendStep: SendStep,
    private val establishment: EstablishmentSteps,
    private val clock: DmClock,
    private val random: DmRandom,
    private val contexts: SelfContexts,
) {
    private val contacts = ContactStore()
    private val scheduled = HeldStore()

    // ------------------------------------------------------------------ actions

    /**
     * §8.6 `reconnect(contacts)`: schedules one `session_reset` control per re-added contact, each
     * at a `U[0, 48 h]` offset drawn now.
     *
     * The contact receives an intro PreKey message from the **same** Olm identity, so it builds a
     * new session under R-SS1 with no key-change warning, detects the renewal and drops its out
     * keys for this device (§21.3 point 2). New roots follow in both directions once the sessions
     * are acknowledged, and pair envelopes then open both ways again.
     *
     * Returns how many were accepted and scheduled. A contact the user cannot send to — blocked,
     * revoked, a request — is skipped rather than refused, because `reconnect` is a list action
     * and one stale id must not lose the rest.
     */
    fun reconnect(contactIds: List<ByteArray>): Int {
        contexts.get() ?: return 0
        val nowMinute = DmTime.floorMinute(clock.nowEpochSeconds())
        var scheduledCount = 0
        for (contactId in contactIds) {
            val offset = drawOffset(RECONNECT_SPREAD_SECONDS)
            val schedId = random.bytes(SCHED_ID_BYTES)
            val done = database.transaction { tx ->
                val contact = contacts.contact(tx.sql, contactId) ?: return@transaction false
                if (!sendable(contact)) return@transaction false
                scheduled.putScheduled(
                    tx = tx,
                    schedId = schedId,
                    contactId = contactId,
                    what = HeldStore.WHAT_RECONNECT,
                    payload = null,
                    dueMinute = nowMinute + offset,
                )
                true
            }
            if (done) scheduledCount += 1
        }
        return scheduledCount
    }

    /**
     * §8.5 `issueRevocation(reason)`: mints the certificate v2 for **this** identity. Local, and
     * nothing is sent (§8.5: "Issuing is local").
     *
     * **It returns the 102 bytes rather than storing them**, and that is a deviation from §13.2's
     * `Unit` signature with a reason: schema v5 has no column for a self-issued certificate —
     * `dm_scheduled.payload` hangs off a contact and `dm_self` has none — and reopening migration
     * 5 for one row of public, signed, contact-visible bytes is a worse trade than handing them
     * back. [notifyContactsOfRevocation] takes them again.
     */
    fun issueRevocation(reason: DmRevocations.Reason): ByteArray? {
        contexts.get() ?: return null
        val issuedMinute = DmTime.floorMinute(clock.nowEpochSeconds()) / DmTime.MINUTE
        return when (val issued = crypto.issueRevocation(issuedMinute, reason)) {
            is DmRevocations.Issued.Ok -> issued.certificate
            DmRevocations.Issued.NonCanonical, DmRevocations.Issued.Unavailable -> null
        }
    }

    /**
     * §8.5 `notifyContactsOfRevocation()`: one CONTROL message per contact with the `revocation`
     * TLV, each due at its own `U[0, 24 h]` offset drawn now and persisted.
     *
     * Nothing is published in a namespace contacts poll (RP F8, T31): the certificate travels
     * inside E2E, to inboxes this device already writes to.
     *
     * The certificate is verified before anything is scheduled, so a caller cannot fan out bytes
     * that no recipient would accept — it is this device's own certificate and the check is cheap.
     */
    fun notifyContactsOfRevocation(certificate: ByteArray): Int {
        val self = contexts.get() ?: return 0
        if (crypto.verifyRevocation(certificate, self.identityPk) !is DmRevocations.Verified.Ok) {
            return 0
        }
        val nowMinute = DmTime.floorMinute(clock.nowEpochSeconds())
        val targets = database.transaction { tx ->
            contacts.contacts(tx.sql).filter { sendable(it) }.map { it.contactId }
        }
        var count = 0
        for (contactId in targets) {
            val offset = drawOffset(REVOCATION_SPREAD_SECONDS)
            val schedId = random.bytes(SCHED_ID_BYTES)
            val done = database.transaction { tx ->
                val contact = contacts.contact(tx.sql, contactId) ?: return@transaction false
                if (!sendable(contact)) return@transaction false
                scheduled.putScheduled(
                    tx = tx,
                    schedId = schedId,
                    contactId = contactId,
                    what = HeldStore.WHAT_REVOCATION,
                    payload = certificate,
                    dueMinute = nowMinute + offset,
                )
                true
            }
            if (done) count += 1
        }
        return count
    }

    // ------------------------------------------------------------- the due step

    /**
     * §21.9 rule 1: the controls whose drawn minute has arrived, sent and their rows retired.
     *
     * **At most [MAX_CONTROLS_PER_PASS] control per pass, across every contact** (§22.13 item 15).
     * The offsets keep k notices from becoming k deposits into k inboxes inside one relay session
     * (RP §3.8), and both callers make a long offline gap the *likely* case rather than the corner
     * one — §8.6 says a restored device has no token until it obtains a trial or a pack, so it
     * cannot deposit at all right after `reconnect(contacts)`, and a revocation is issued when the
     * phone is lost. A device that comes back after the whole spread finds every row due, and an
     * uncapped loop would send them all in the one session the spread exists to thin out. The cap
     * is what actually bounds the degree an observer reads off the wire; the offsets decide the
     * order and the delay.
     *
     * **The row is retired inside the send's own transaction** (`scheduledId`), so a crash between
     * the deposit and the deletion cannot deposit the notice twice. A second `sendControl` mints a
     * fresh `message_id` and takes a fresh ratchet step, so neither D3 nor D2b would dedup it.
     *
     * **A transient failure keeps the row and takes a fresh minute.** `NO_REPLICAS`,
     * `STORAGE_FULL` and `CRYPTO_UNAVAILABLE` are exactly the outcomes §21.7 point 4 retries for a
     * pending item, and none of them says anything about this notice — one relay set momentarily
     * short of quorum must not be the reason a contact never learns that a device was lost. Two of
     * the three never reach the send's transaction (they are refused before it opens, or they
     * throw and roll it back with the retirement inside it); the third, a context that closes
     * between the seal and the enqueue, is answered from inside it, so the re-schedule is a
     * `putScheduled` and restores the row whichever happened. The fresh minute is drawn from the
     * notice's own spread, which keeps the privacy property of the first draw and also keeps a
     * contact this device cannot reach from holding the head of the queue for ever.
     *
     * A **permanent** refusal — a contact blocked, revoked or deleted between the drawn minute and
     * now — deletes the row here: the send's transaction refused before reaching the deletion, and
     * the user's own later action supersedes the notice. §21.8 point 4's rescheduling of a
     * **FAILED** control (one that was enqueued and failed) is an outcome and therefore OUTCOME's;
     * it is still deferred (§22.13 item 9).
     */
    fun runDue(limit: Int = MAX_CONTROLS_PER_PASS): Int {
        contexts.get() ?: return 0
        val now = clock.nowEpochSeconds()
        val nowMinute = DmTime.floorMinute(now)
        val due = database.transaction { tx ->
            scheduled.due(tx.sql, nowMinute, limit)
        }
        var sent = 0
        for (row in due) {
            val outcome = when (row.what) {
                HeldStore.WHAT_RECONNECT -> sendStep.sendControl(
                    contactId = row.contactId,
                    control = SendStep.Control.RECONNECT,
                    revocation = ByteArray(0),
                    sessionReset = true,
                    scheduledId = row.schedId,
                )
                HeldStore.WHAT_REVOCATION -> sendStep.sendControl(
                    contactId = row.contactId,
                    control = SendStep.Control.REVOCATION,
                    revocation = row.payload ?: ByteArray(0),
                    sessionReset = false,
                    scheduledId = row.schedId,
                )
                // A `what` no version of this engine writes: the row is not a control anybody can
                // send, so it goes rather than being retried for ever.
                else -> null
            }
            if (outcome != null && outcome.establish) {
                // The reconnect notice of §8.6 is exactly the message that has to travel as an
                // intro envelope, so it is also the one most likely to find no usable session.
                establishment.estStart(row.contactId, userRetry = true)
            }
            if (outcome != null && transient(outcome.outcome)) {
                // `putScheduled` and not an UPDATE: one transient outcome — the context closing
                // between the seal and the enqueue — is answered from **inside** the send's
                // transaction, which by then has already retired the row. The UPDATE-then-INSERT
                // pair restores it either way, under the same `sched_id`, and it is the same
                // guarded write `reconnect` and `notifyContactsOfRevocation` use (gate G-DM4: no
                // REPLACE anywhere).
                database.transaction { tx ->
                    scheduled.putScheduled(
                        tx = tx,
                        schedId = row.schedId,
                        contactId = row.contactId,
                        what = row.what,
                        payload = row.payload,
                        dueMinute = nowMinute + drawOffset(spreadOf(row.what)),
                    )
                }
            } else {
                // Idempotent: the send's own transaction deleted it whenever it got that far.
                database.transaction { tx -> scheduled.deleteScheduled(tx, row.schedId) }
            }
            if (outcome?.outcome == SendStep.Outcome.QUEUED) sent += 1
        }
        return sent
    }

    // --------------------------------------------------------------- internals

    /**
     * A uniform offset in `[0, spread)` seconds, floored to the minute (T13: `due_minute` is on
     * the minute grid, and a second inside it would be a time the schema does not carry).
     *
     * The randomness is the DM random port, which is the same source every other secret-free
     * draw of the engine uses; a biased modulo over 2^32 is about one part in 10^4 at a 48-hour
     * spread, which no observer can measure against a 2 880-minute range.
     */
    private fun drawOffset(spread: Long): Long =
        DmTime.floorMinute(Math.floorMod(random.u32(), spread))

    /** §8.2 rule 6: a control is a send, so only `unverified` and `verified` receive one. */
    private fun sendable(contact: ContactStore.ContactRow): Boolean =
        contact.trust == ContactStore.Trust.UNVERIFIED ||
            contact.trust == ContactStore.Trust.VERIFIED

    /**
     * The outcomes that say nothing about this notice and everything about this minute: the week's
     * slot table cannot span two operators, the disk is full, or the DM context is closed. They
     * are §21.7 point 4's own retry set, read here for the control a `dm_scheduled` row carries.
     */
    private fun transient(outcome: SendStep.Outcome): Boolean =
        outcome == SendStep.Outcome.NO_REPLICAS ||
            outcome == SendStep.Outcome.STORAGE_FULL ||
            outcome == SendStep.Outcome.CRYPTO_UNAVAILABLE

    /** The spread a retry is re-drawn from: the same one the action drew from. */
    private fun spreadOf(what: String): Long = when (what) {
        HeldStore.WHAT_REVOCATION -> REVOCATION_SPREAD_SECONDS
        else -> RECONNECT_SPREAD_SECONDS
    }

    companion object {
        /** §8.6: the reconnect spread, `U[0, 48 h]`. */
        const val RECONNECT_SPREAD_SECONDS: Long = 48 * DmTime.HOUR

        /** §8.5: the revocation spread, `U[0, 24 h]`. */
        const val REVOCATION_SPREAD_SECONDS: Long = 24 * DmTime.HOUR

        /** `dm_scheduled.sched_id` is 16 random bytes, like every other id of the schema (T33). */
        const val SCHED_ID_BYTES: Int = 16

        /**
         * How many due controls one pass may send, across every contact (§22.13 item 15).
         *
         * One. A relay session sees at most one scheduled deposit, whatever happened while the
         * device was offline, which is the degree RP §3.8 lets an observer read. The cost is that
         * a backlog of k notices drains over k time-triggered passes — the actor timer, a database
         * open and a relay session start — rather than inside the drawn spread, and that is the
         * right trade: the spread exists for the degree, not for the latency.
         */
        const val MAX_CONTROLS_PER_PASS: Int = 1
    }
}
