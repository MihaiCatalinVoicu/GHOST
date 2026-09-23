package org.ghost.messaging.engine

import org.ghost.crypto.bridge.DmPairing
import org.ghost.crypto.bridge.DmSeal
import org.ghost.messaging.port.DmEnvelopes
import org.ghost.messaging.store.ContactStore
import org.ghost.messaging.store.MessageStore
import org.ghost.sync.api.SyncTransaction

/**
 * §21.3 point 5, **both halves**: pair week keys ratcheted forward to `week(now)`, and then erased
 * past their window — in **one** transaction, in that order.
 *
 * > SWEEP first derives and stores, for every live in-generation, `K_w` for every week up to
 * > `week(now)` from the newest stored key, then erases keys past `start(w + 1) + FRESH`, in one
 * > transaction.
 *
 * **Why the order is the rule and not an optimisation** (mutant **MC-21**). `K_{w+1}` is derived
 * from `K_w` and from nothing else — that is what lets §6.3 erase the root on both sides — so a
 * sweep that erased first would destroy the only material the derivation could start from. A
 * recipient that did not run for about 52 days would erase its newest in-key and then have nothing
 * left to ratchet with, and RS2's "pair envelopes open after a 60-day absence" would be false.
 *
 * **What that failure actually looks like**, because the first version of this file described it
 * wrongly and then arranged for it (S9 review, and see [advance]): not a conversation that "falls
 * to `NO_SEAL_KEY` and re-establishes" — a recipient has no way to start a re-establishment — but
 * every later pair envelope of that conversation dropped as `unknown_seal`, silently, until the
 * *user* happens to send something. There is no second chance and no counter the user sees. A
 * sweep that cannot ratchet must therefore not erase the seed it would have ratcheted from, and
 * the way this file keeps that true is by always being able to ratchet.
 *
 * **What erasure buys** is **P-7** and **T34** (§6.3, §21.3 point 6): for an ISO week `w` with
 * `now ≥ start(w + 1) + 45 d`, no key on the device and nothing derivable from either seed opens a
 * pair-mode envelope of that week. Opening and recognition keys are one row and go together
 * (R-S6), so an attacker who seizes the device cannot even *recognise* which envelopes of that week
 * belonged to which conversation — which is the who-talked-to-whom-when history that T25 alone
 * does not protect. S7 shipped the derivation half and said so in its own header; this is the half
 * it named (§22.12 item 13). The privacy world that *proves* P-7 and T34 is S11's; what is here is
 * the mechanism it will measure.
 *
 * **The two directions have different windows**, because they are different secrets:
 *  - **in** (keys this device accepts envelopes under, §6.3 "Recipient (me)"): keep `K_w` while
 *    `now < start(w + 1) + FRESH`. No legitimate blob sealed under `K_w` can be accepted after
 *    that instant anyway — its author minute is before `start(w + 1)` by the sender's clock, and
 *    R9 refuses content older than `FRESH`.
 *  - **out** (the key this device seals with, §6.3 "Sender c", §22.8.5 rule 1): keep
 *    `K_{week(now)}` of the newest generation, and the key of an earlier week only while a live
 *    retryable item of that contact could still be re-encrypted under it. A user retry keeps its
 *    author minute, and R9 at the peer requires the key's week to equal the author's week, so an
 *    out key erased too early turns every cross-week retry into provisional mode or a
 *    relay-visible re-establishment (MC-33).
 *
 * **It runs inside SWEEP and only there** (§21.3 point 5, §7.2's SWEEP row). S7 drove it from the
 * time-triggered branch of the actor pass, because SWEEP did not exist yet and the safe placement
 * for a step with no owner is the restricted one. §21.9 rule 2 names SWEEP among the steps a
 * hint-triggered pass **does** run, and the reason holds here: the ratchet writes `dm_pair_key`
 * rows and nothing else — no store, no registration, no capability, no namespace change — so no
 * relay can see that it happened, which is what T28 forbids. What must not follow an arrival is
 * relay-visible behaviour, and deriving a week key is not.
 */
internal class PairKeySteps(
    private val envelopes: DmEnvelopes,
) {
    private val contacts = ContactStore()
    private val messages = MessageStore()

    /** How many week keys were derived and how many rows were erased in one pass. */
    class Report(val derived: Int, val erased: Int, val offersErased: Int, val offersDeleted: Int) {
        val total: Int get() = derived + erased + offersErased + offersDeleted

        override fun toString(): String =
            "PairKeys(derived=$derived, erased=$erased, offers=$offersErased/$offersDeleted)"
    }

    /**
     * §21.3 point 5 in one transaction: derive, **then** erase. Called by `Sweeper` inside the
     * SWEEP transaction, with [nowE] the expiry clock of R-T7 rather than the raw wall clock.
     */
    fun sweep(tx: SyncTransaction, nowE: Long): Report {
        val week = DmTime.week(nowE)
        val derived = advanceAll(tx, week)
        var erased = 0
        var offersErased = 0
        var offersDeleted = 0
        for (contact in contacts.contacts(tx.sql)) {
            erased += eraseIn(tx, contact.contactId, nowE)
            erased += eraseOut(tx, contact.contactId, week, nowE)
            val offers = eraseOffers(tx, contact.contactId, nowE)
            offersErased += offers.first
            offersDeleted += offers.second
        }
        return Report(derived, erased, offersErased, offersDeleted)
    }

    private fun advanceAll(tx: SyncTransaction, week: Long): Int {
        var derived = 0
        for (contact in contacts.contacts(tx.sql)) {
            if (contact.trust == ContactStore.Trust.BLOCKED ||
                contact.trust == ContactStore.Trust.REVOKED
            ) {
                continue
            }
            for (rootGen in advancingInGenerations(tx, contact.contactId)) {
                derived += advance(tx, contact.contactId, ContactStore.DIRECTION_IN, week, rootGen)
            }
            derived += advance(tx, contact.contactId, ContactStore.DIRECTION_OUT, week, null)
        }
        return derived
    }

    /**
     * The **in** generations that keep ratcheting (§6.3 "Recipient (me)"): every generation from
     * the newest **acknowledged** one upwards — the newest, and each older one down to and
     * including the first whose offer is acknowledged.
     *
     * §6.3: "a generation stops advancing (no new week keys) once a pair envelope under a newer
     * generation from c opens". A generation below an acknowledged one is exactly that, and stops;
     * every generation at or above the newest acknowledged one may still be the one the contact
     * seals under, because none newer has opened. Until slice S13 only the newest generation
     * advanced, so between minting a new offer and the contact's first envelope under it the
     * contact's envelopes in a new week were dropped as `unknown_seal`.
     *
     * **Why not just the newest two (the S13 review).** S13's first version advanced the newest and
     * the one before it, which is the rule only while at most one offer is unacknowledged. Two can
     * be: an offer that rode once on a message that was lost, and whose re-attachments were then
     * deferred or never sent, is replaced at `base_week + 3` by §22.8.6 rule 2 (`pqStale`) while
     * still unacknowledged — and the contact, which never received either, still seals under the
     * acknowledged generation below both. The two-generation rule stopped that one at the next
     * week boundary and dropped every later envelope of the contact, silently. The overlap is
     * still small: generations above the acknowledged one exist only between a replacement and its
     * acknowledgement, and each is re-attached until then (R-S5's candidate count assumed two).
     *
     * Whether a generation is acknowledged is read from its own `dm_pair_offer` row. A generation
     * with in keys and **no** row is treated as a stopping point too: SWEEP deletes a row only once
     * its secrets are gone (acknowledged, or erased unacknowledged at `start(b + 1) + FRESH`, or
     * discarded by a renewal) and a higher generation exists (§21.3 point 3), so a missing row is
     * in the common case an acknowledged one, and in the others a root the contact has not used for
     * at least 45 days or can no longer hold — keeping everything below it advancing would ratchet
     * keys for nothing, against P-7.
     */
    private fun advancingInGenerations(tx: SyncTransaction, contactId: ByteArray): List<Int> {
        val generations = contacts.pairKeys(tx.sql, contactId, ContactStore.DIRECTION_IN)
            .map { it.rootGen }
            .distinct()
            .sortedDescending()
        val offers = contacts.pairOffers(tx.sql, contactId).associateBy { it.rootGen }
        val out = ArrayList<Int>()
        for (generation in generations) {
            out += generation
            val offer = offers[generation]
            if (offer == null || offer.acknowledged) break
        }
        return out
    }

    /**
     * Ratchets one generation of one direction of one contact forward to [week].
     *
     * Which generations advance is the caller's: on the sending side only the newest ("the
     * sender keeps `K_{week(now)}` of the newest generation", §6.3), on the receiving side every
     * generation from the newest acknowledged one upwards ([advancingInGenerations]: §6.3's "a
     * generation stops advancing once a pair envelope under a newer generation from c opens").
     *
     * **It walks the whole gap, in windows** (S9 review). §21.3 point 5 says "`K_w` for every week
     * up to `week(now)` from the newest stored key", and the first version of this code refused to
     * ratchet at all once the gap passed eight week-indices — while [eraseIn], in the same
     * transaction, erased the newest key anyway, because that key really is past
     * `start(w + 1) + FRESH`. The device was then left with **nothing** of the generation: not
     * "falls to `NO_SEAL_KEY` and re-establishes", which the comment claimed, but every later pair
     * envelope of that conversation dropped as `unknown_seal`, silently, until a re-establishment
     * the recipient cannot trigger. That is exactly defect (3) of CR-13, which §21.3 point 5 was
     * written to remove, and it fired at a gap of nine — under RS2's own 60-day absence, which
     * lands on eight or nine depending on the weekday the conversation started.
     *
     * The gap is closed in windows of [DmPairing.MAX_WINDOW_WEEKS], because that is what one JNI
     * call answers; the last key of one window is the base of the next, which is what
     * [DmPairing.From.WEEK_KEY] exists for. The keys in between are derived, stored and — for all
     * but the last few weeks — erased again by [eraseIn] in this same transaction, which is the
     * ratchet's cost and not a residue: nothing of them is ever committed.
     */
    private fun advance(
        tx: SyncTransaction,
        contactId: ByteArray,
        direction: String,
        week: Long,
        /** The generation to advance; null for the newest (the sender's rule, §6.3). */
        generation: Int?,
    ): Int {
        val rows = contacts.pairKeys(tx.sql, contactId, direction)
        if (rows.isEmpty()) return 0
        val newestGen = generation ?: rows.maxOf { it.rootGen }
        val newest = rows.filter { it.rootGen == newestGen }.maxByOrNull { it.week } ?: return 0
        if (newest.week >= week) return 0
        if (week - newest.week > MAX_CATCH_UP_WEEKS) {
            // Beyond this the gap is not an absence any more, it is a clock: `now_e` only ever
            // moves forward (R-T7), so a wall clock set years ahead is stored and stays. Deriving
            // a key per week of it would be work with no message to open at the end of it, and
            // every key of the generation is past its erasure however far the ratchet ran. The
            // conversation re-establishes at the user's next send (§6.8 rule 4); §22.14 records
            // what the peer's messages do until then.
            return 0
        }
        val pairDirection = if (direction == ContactStore.DIRECTION_IN) {
            DmSeal.PairDirection.IN
        } else {
            DmSeal.PairDirection.OUT
        }
        var baseWeek = newest.week
        var keyEnv = newest.openEnv
        var derived = 0
        while (baseWeek < week) {
            val toWeek = minOf(week, baseWeek + DmPairing.MAX_WINDOW_WEEKS)
            val keys = envelopes.pairKeys(
                contactId = contactId,
                direction = pairDirection,
                rootGen = newest.rootGen,
                from = DmPairing.From.WEEK_KEY,
                keyEnv = keyEnv,
                baseWeek = baseWeek,
                fromWeek = baseWeek + 1,
                toWeek = toWeek,
            )
            if (keys !is DmPairing.KeysResult.Ok || keys.weeks.isEmpty()) return derived
            for (key in keys.weeks) {
                contacts.putPairKey(
                    tx = tx,
                    contactId = contactId,
                    direction = direction,
                    rootGen = newest.rootGen,
                    week = key.week,
                    recognitionKey = key.recognitionKey,
                    openEnv = key.openEnv,
                )
            }
            derived += keys.weeks.size
            val last = keys.weeks.last()
            // A window that did not reach its own end would loop forever on the same base.
            if (last.week <= baseWeek) return derived
            baseWeek = last.week
            keyEnv = last.openEnv
        }
        return derived
    }

    /**
     * §6.3 "Recipient (me)": `K_w` is erased in the first sweep at or after
     * `start(w + 1) + FRESH`, by the expiry clock (§10.3 R-T7) and not by the raw wall clock.
     *
     * `FRESH` here is the 45-day horizon and **not** `FRESH(bucket)`: the window is a property of
     * the week key, which serves every message of that week whatever its timer, so it takes the
     * longest of them (§21.10 point 3 keeps `FRESH = 45 d` for the pair-key window explicitly).
     */
    private fun eraseIn(tx: SyncTransaction, contactId: ByteArray, nowE: Long): Int {
        var erased = 0
        for (row in contacts.pairKeys(tx.sql, contactId, ContactStore.DIRECTION_IN)) {
            if (nowE < DmTime.weekStart(row.week + 1) + DmTimers.FRESH_SECONDS) continue
            erased += contacts.deletePairKey(
                tx,
                contactId,
                ContactStore.DIRECTION_IN,
                row.rootGen,
                row.week,
            )
        }
        return erased
    }

    /**
     * §6.3 "Sender c" and §22.8.5 rule 1: the out key of the current week of the newest generation
     * stays, every other one goes unless a live retryable item still needs it.
     *
     * A key of a **future** week cannot exist (the ratchet stops at `week(now)`), and one of an
     * older generation is kept under the same item rule — a FAILED item authored under the previous
     * root is retried with the key that sealed it, or not at all.
     */
    private fun eraseOut(tx: SyncTransaction, contactId: ByteArray, week: Long, nowE: Long): Int {
        val rows = contacts.pairKeys(tx.sql, contactId, ContactStore.DIRECTION_OUT)
        if (rows.isEmpty()) return 0
        val newestGen = rows.maxOf { it.rootGen }
        val needed = messages.retryableItemWeeks(tx.sql, contactId, nowE)
        var erased = 0
        for (row in rows) {
            if (row.rootGen == newestGen && row.week >= week) continue
            if (row.week in needed) continue
            erased += contacts.deletePairKey(
                tx,
                contactId,
                ContactStore.DIRECTION_OUT,
                row.rootGen,
                row.week,
            )
        }
        return erased
    }

    /**
     * §6.3 and §21.3 point 3: an offered root's **secret** is erased at
     * `start(base_week + 1) + FRESH` if a pair envelope under it never opened, and the row itself
     * is deleted only once a higher generation exists.
     *
     * Erasing the secret is what P-7 needs; keeping the row is what §21.3 point 3 needs, because
     * `root_gen` is a per-contact counter and a repeated number is a root the peer silently drops
     * ("not greater than the stored out generation", §6.3).
     *
     * Returns (secrets erased, rows deleted).
     */
    private fun eraseOffers(tx: SyncTransaction, contactId: ByteArray, nowE: Long): Pair<Int, Int> {
        val offers = contacts.pairOffers(tx.sql, contactId)
        if (offers.isEmpty()) return 0 to 0
        val highest = offers.maxOf { it.rootGen }
        var erased = 0
        var deleted = 0
        for (offer in offers) {
            val expired = nowE >= DmTime.weekStart(offer.baseWeek + 1) + DmTimers.FRESH_SECONDS
            if (expired) erased += contacts.eraseOfferSecrets(tx, contactId, offer.rootGen)
            // §21.3 point 3: "SWEEP may delete a row with `root_env = NULL` only if a row of a
            // higher generation exists". The store's own guard refuses a row whose root is still
            // there, so this decides only the generation half.
            if (offer.rootGen < highest) deleted += contacts.deleteOffer(tx, contactId, offer.rootGen)
        }
        return erased to deleted
    }

    companion object {
        /**
         * How many week-indices one pass will ratchet across: **two years**.
         *
         * It is not a bound on absence — RS2's 60 days, a year abroad and a phone left in a drawer
         * are all inside it, and [advance] walks them in windows of
         * [DmPairing.MAX_WINDOW_WEEKS]. It is a bound on the **clock**: `now_e` only ever moves
         * forward (R-T7), so a wall clock set to 2099 is stored and never comes back, and without
         * a bound the ratchet would derive four thousand keys per direction per contact inside one
         * transaction, on the actor thread, for a week nothing will ever seal under.
         *
         * The previous value was 8, which is **below** the 60-day absence RS2 asserts; see
         * [advance] for what it cost.
         */
        const val MAX_CATCH_UP_WEEKS: Long = 104
    }
}
