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
 * left to ratchet with: every later pair envelope of that conversation would go unrecognised, the
 * conversation would fall to `NO_SEAL_KEY` and re-establish, and RS2's "pair envelopes open after a
 * 60-day absence" would be false.
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
            derived += advance(tx, contact.contactId, ContactStore.DIRECTION_IN, week)
            derived += advance(tx, contact.contactId, ContactStore.DIRECTION_OUT, week)
        }
        return derived
    }

    /**
     * Ratchets one direction of one contact forward to [week].
     *
     * Only the **newest** generation advances: §6.3's "a generation stops advancing (no new week
     * keys) once a pair envelope under a newer generation from c opens", and, on the sending
     * side, "the sender keeps `K_{week(now)}` of the newest generation".
     */
    private fun advance(
        tx: SyncTransaction,
        contactId: ByteArray,
        direction: String,
        week: Long,
    ): Int {
        val rows = contacts.pairKeys(tx.sql, contactId, direction)
        if (rows.isEmpty()) return 0
        val newestGen = rows.maxOf { it.rootGen }
        val newest = rows.filter { it.rootGen == newestGen }.maxByOrNull { it.week } ?: return 0
        if (newest.week >= week) return 0
        if (week - newest.week > MAX_CATCH_UP_WEEKS) {
            // A device offline for longer than the FRESH window has no usable key of this
            // generation left: §6.3 erases every `K_w` at `start(w + 1) + FRESH`, so ratcheting
            // across the gap would produce keys whose weeks are already past their erasure. The
            // conversation re-establishes at the user's next send (§6.8 rule 4), which is the
            // declared behaviour of RS2's 60-day absence.
            return 0
        }
        val keys = envelopes.pairKeys(
            contactId = contactId,
            direction = if (direction == ContactStore.DIRECTION_IN) {
                DmSeal.PairDirection.IN
            } else {
                DmSeal.PairDirection.OUT
            },
            rootGen = newest.rootGen,
            from = DmPairing.From.WEEK_KEY,
            keyEnv = newest.openEnv,
            baseWeek = newest.week,
            fromWeek = newest.week + 1,
            toWeek = week,
        )
        if (keys !is DmPairing.KeysResult.Ok) return 0
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
        return keys.weeks.size
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
         * How many weeks one pass will ratchet across. `FRESH = 45 d` is between six and seven
         * weeks, so a key more than eight weeks old has no live successor worth deriving, and the
         * bound also keeps one pass from walking a device's whole absence.
         */
        const val MAX_CATCH_UP_WEEKS: Long = 8
    }
}
