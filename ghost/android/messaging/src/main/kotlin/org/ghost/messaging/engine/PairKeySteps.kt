package org.ghost.messaging.engine

import org.ghost.crypto.bridge.DmPairing
import org.ghost.crypto.bridge.DmSeal
import org.ghost.messaging.port.DmClock
import org.ghost.messaging.port.DmEnvelopes
import org.ghost.messaging.store.ContactStore
import org.ghost.sync.api.SyncDatabase
import org.ghost.sync.api.SyncTransaction

/**
 * The **derivation** half of §21.3 point 5: pair week keys ratcheted forward to `week(now)`.
 *
 * > SWEEP first derives and stores, for every live in-generation, `K_w` for every week up to
 * > `week(now)` from the newest stored key, then erases keys past `start(w + 1) + FRESH`, in one
 * > transaction.
 *
 * **Scope, declared.** SWEEP is slice S9's, and so is the **erasure** half — the part that makes
 * P-7 and T34 true, and the part mutant MC-21 ("erase before ratcheting") is about. What S7
 * cannot defer is the derivation: without it, a conversation that crosses a week boundary stops
 * recognising its peer's pair envelopes (no in key for the new week) and stops sealing in pair
 * mode (no out key), and falls to `NO_SEAL_KEY`, a bundle fetch and a relay-visible
 * re-establishment — a regression §6.8 rule 4 calls a bug and L7-D6 would have to declare.
 *
 * **Time-triggered, never blob-triggered** (§21.9 rule 1, T28). It runs from the actor timer, a
 * database open and a relay session start, like every other step whose timing must not depend on
 * what arrived.
 *
 * **Forward only, from the newest stored key.** `K_{w+1} = HKDF(K_w, "pair-next")` needs only the
 * previous week's key, which is why §6.3 lets both sides erase the root: the sender "erases the
 * root as soon as `K_b` is computed", and the recipient erases its offer once a pair envelope
 * under it opens. A step that re-derived from the root each week would have made those erasures
 * impossible.
 */
internal class PairKeySteps(
    private val database: SyncDatabase,
    private val envelopes: DmEnvelopes,
    private val clock: DmClock,
) {
    private val contacts = ContactStore()

    /** How many week keys this pass derived. */
    fun run(): Int {
        val week = DmTime.week(clock.nowEpochSeconds())
        return database.transaction { tx ->
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
            derived
        }
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

    companion object {
        /**
         * How many weeks one pass will ratchet across. `FRESH = 45 d` is between six and seven
         * weeks, so a key more than eight weeks old has no live successor worth deriving, and the
         * bound also keeps one pass from walking a device's whole absence.
         */
        const val MAX_CATCH_UP_WEEKS: Long = 8
    }
}
