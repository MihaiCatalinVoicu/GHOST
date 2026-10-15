package org.ghost.messaging.engine

import org.ghost.crypto.bridge.DmCards
import org.ghost.messaging.port.DmClock
import org.ghost.messaging.port.DmCrypto
import org.ghost.messaging.store.ContactStore
import org.ghost.messaging.store.MediaOrphanStore
import org.ghost.storage.SqlExecutor
import org.ghost.sync.api.SyncTransaction

/**
 * The `M_c` orphan rule (Phase 11 design §5.1, T33): `M_c` is **not kept as history**.
 *
 * Revision 2 of the design kept `M_c` registered for the contact's lifetime, so a seized device
 * showed "has sent media to c" long after the media expired. The rule now: when every `out` object
 * of c is past its upload (`uploaded`, or `failed` past its deadline), its descriptor item has a
 * final outcome (or is `failed` past the deadline), and every media op of c has been released, the
 * transaction that makes it so deletes c's `media_upload` rows — they hold the only foreign key
 * into `M_c`'s `sync_namespace` row, so no retry is possible any more — and records `M_c` in
 * `dm_orphan_namespace`; SWEEP then removes the namespace and its credentials exactly as F9
 * §21.12 point 3 does for `X_c` and `P_c` (local only: `M_c` is `LOCAL`, never redeemed, and
 * nothing is registered at a relay for it).
 *
 * **The producers.** §13.5 names the transactions that may complete the condition: `MEDIA-OUTCOME`
 * and `MEDIA-DEADLINE` (slice S5's sender pipeline), F9 `OUTCOME` for the descriptor (wired here:
 * [OutcomeStep] calls [recordIfOrphaned] from a kind-5 item's terminal outcome), and `SWEEP`
 * (wired here: the expired-message cascade, via [candidates] + [recordIfOrphaned]) — a later
 * `MEDIA-COMMIT` to c deletes a pending orphan row in its own transaction and registers again
 * (slice S5). Blocking or deleting the contact records `M_c` with `X_c` and `P_c`
 * ([ContactSteps.recordOrphans]), and re-adding the card forgets the rows
 * ([ContactSteps.forgetOrphans]).
 *
 * **All in the caller's transaction.** The recording is one guarded UPDATE-then-INSERT and one
 * `DELETE` beside the effect that completed the condition — a crash rolls both back together, and
 * a re-execution finds the condition still complete and records once (the orphan insert is
 * idempotent and the upload delete is a no-op the second time).
 *
 * **No network, ever** (G-DM1, G-DM2): nothing here enqueues or removes a namespace; the removal
 * is SWEEP's alone.
 */
internal class MediaOrphanSteps(
    private val crypto: DmCrypto,
    private val clock: DmClock,
) {
    private val orphans = MediaOrphanStore()
    private val contacts = ContactStore()

    /**
     * §5.1's rule for one contact, evaluated and — when complete — recorded, in the caller's
     * transaction. [self] is the caller's resolved [SelfContext] (resolved **before** the
     * transaction, per the S8 rule): null (a locked or missing context) means `M_c` cannot be
     * derived from the card and nothing is recorded — the next producer's pass tries again.
     * [nowSeconds] is the caller's clock for the deadline clauses (`now_e` in seconds from SWEEP,
     * the wall clock from OUTCOME — both hour-grid comparable).
     *
     * Returns true when the rule's condition held and the orphan row is present after this call.
     * The recording is idempotent — the guarded insert adds no second row and the upload delete
     * is a no-op the second time — so a re-execution (after this call, or after
     * [ContactSteps.recordOrphans] recorded the same row at block or delete) still reports true
     * while recording nothing; the producers call it for effect and never count recordings.
     */
    fun recordIfOrphaned(
        tx: SyncTransaction,
        self: SelfContext?,
        contactId: ByteArray,
        nowSeconds: Long,
    ): Boolean {
        if (orphans.uploadBlockers(tx.sql, contactId, nowSeconds) > 0) return false
        if (orphans.descriptorBlockers(tx.sql, contactId, nowSeconds) > 0) return false
        if (orphans.opBlockers(tx.sql, contactId, nowSeconds) > 0) return false
        if (self == null) return false
        val row = contacts.contact(tx.sql, contactId) ?: return false
        // A blocked contact's card was erased at block, which recorded the orphans then; there is
        // nothing to derive from and nothing to add.
        val cardEnv = row.cardEnv ?: return false
        val card = self.content.open(cardEnv, contactId) ?: return false
        val derived = crypto.deriveCard(card, ORPHAN_SLOT)
        if (derived !is DmCards.DeriveResult.Ok) return false
        try {
            orphans.deleteUploadsOf(tx, derived.values.mediaNamespace)
            contacts.addOrphan(tx, derived.values.mediaNamespace)
        } finally {
            derived.values.clearSecrets()
        }
        return true
    }

    /** The wall-clock convenience for producers that run outside SWEEP (OUTCOME). */
    fun recordIfOrphaned(tx: SyncTransaction, self: SelfContext?, contactId: ByteArray): Boolean =
        recordIfOrphaned(tx, self, contactId, clock.nowEpochSeconds())

    /** SWEEP's candidate contacts: [MediaOrphanStore.candidates]. */
    fun candidates(sql: SqlExecutor, nowMinute: Long): List<ByteArray> = orphans.candidates(sql, nowMinute)

    companion object {
        /**
         * The slot the orphan bookkeeping derives with. `M_c` is **slot-independent** — only the
         * bearer secrets carry the slot (§21.2 point 1) — so any slot yields the same namespace,
         * and the secrets this call also produces are wiped by the caller.
         */
        private const val ORPHAN_SLOT: Int = 0
    }
}
