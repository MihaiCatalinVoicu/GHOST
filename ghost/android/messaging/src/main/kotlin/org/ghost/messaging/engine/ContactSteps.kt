package org.ghost.messaging.engine

import org.ghost.crypto.bridge.DmCards
import org.ghost.messaging.port.DmCrypto
import org.ghost.messaging.port.DmRandom
import org.ghost.messaging.store.ContactStore
import org.ghost.messaging.store.HeldStore
import org.ghost.messaging.store.MediaOrphanStore
import org.ghost.messaging.store.MessageStore
import org.ghost.sync.api.SyncDatabase
import org.ghost.sync.api.SyncTransaction

/**
 * Contacts from cards, requests, block and delete (Phase 9 design §12).
 *
 * **Nothing here reaches a relay.** Rule R-E1: "Adding a card is local: it never registers,
 * fetches or stores anything until the user sends." Blocking and deleting are local too (§12.4),
 * and the two namespaces a deleted contact leaves behind are **recorded** in
 * `dm_orphan_namespace` for SWEEP to remove once their ops are released (§21.12 point 3) rather
 * than removed here — which is also why this file is not on gate G-DM2's allowlist and must not
 * become so.
 *
 * **Deferred to slice S9.** SWEEP is S9's, so an orphan namespace row waits for it, and a request
 * that passes `request_until_day` is deleted by it. Both are recorded in the design's forward
 * notes; until S9 lands, an orphan row is inert state and a stale request keeps its cap slot.
 */
internal class ContactSteps(
    private val database: SyncDatabase,
    private val crypto: DmCrypto,
    private val random: DmRandom,
    private val contexts: SelfContexts,
    /**
     * The establishment steps, for the one thing block and delete owe a contact that is still
     * fetching: closing its `P_c` window ([EstablishmentSteps.abandonFetch]). The call itself has
     * to be made from a file gate G-DM2 allows, which this one is deliberately not.
     */
    private val establishment: EstablishmentSteps,
) {
    private val store = ContactStore()
    private val messages = MessageStore()
    private val held = HeldStore()
    private val mediaOrphans = MediaOrphanStore()

    /** What [addContact] did (§13.2). */
    enum class AddResult {
        /** A new contact row, its conversation, and nothing else (rule R-E1). */
        ADDED,

        /** The bytes are not a card v2 of this version (§3.3's fail-closed parse). */
        INVALID_CARD,

        /** The card is this identity's own. */
        OWN_CARD,

        /** The same card is already a contact: a no-op (rule R-E3). */
        ALREADY_KNOWN,

        /**
         * A different card for an `identity_pk` that is already a contact. Phase 9 has no card
         * rotation (C-16, §12.5), so this is refused rather than applied.
         */
        CARD_CHANGED,

        /** The identity is revoked: terminal (§8.5). */
        REVOKED_IDENTITY,

        /** `MAX_CONTACTS` (§12.6). */
        LIMIT_REACHED,

        /** The DM context is closed or the library is missing (§13.2). */
        CRYPTO_UNAVAILABLE,

        /** ACTIVATE has not run: there is no identity to add a contact to. */
        NOT_ACTIVATED,
    }

    /** What a request decision did (§12.3). */
    enum class RequestResult {
        /** The trust state moved. */
        DONE,

        /** No such contact, or it is not in `request`. */
        NOT_A_REQUEST,

        /** The DM context is closed or ACTIVATE has not run. */
        UNAVAILABLE,
    }

    /** A contact as the facade renders it: no times, no keys (§13.2 `contacts`). */
    class ContactView(
        val contactId: ByteArray,
        val trust: ContactStore.Trust,
        val establishment: ContactStore.Establishment,
        val source: ContactStore.Source,
        val resetNeeded: Boolean,
        /** The §3.6 alias, decrypted into memory only. */
        val name: String? = null,
    ) {
        override fun toString(): String = "ContactView(trust=$trust, establishment=$establishment)"
    }

    /**
     * §12.1, §12.2 step 1: a card becomes a contact, locally.
     *
     * A card scanned in person starts `verified` — the scanned `identity_pk` authenticates the Olm
     * identity transitively through the bundle signature and binding v3, so no bundle MITM is
     * possible for that contact (§8.4) — and a card that arrived as a link starts `unverified`,
     * because a substituted link is a MITM.
     *
     * The parse is fail-closed and runs **before any row is written** (rule R-E2): the version,
     * the card index, the signature under `identity_pk`, and, here in Kotlin, that the card is not
     * this device's own. The own-card check is a byte comparison against what `ownCard` already
     * returns, which is why it is not in the crate (§2.6 function 3).
     */
    fun addContact(card: ByteArray, source: ContactStore.Source): AddResult {
        val self = contexts.get() ?: return if (crypto.isAvailable()) {
            AddResult.NOT_ACTIVATED
        } else {
            AddResult.CRYPTO_UNAVAILABLE
        }
        val parsed = when (val result = crypto.parseCard(card)) {
            is DmCards.ParseResult.Ok -> result.card
            DmCards.ParseResult.InvalidCard -> return AddResult.INVALID_CARD
            DmCards.ParseResult.Unavailable -> return AddResult.CRYPTO_UNAVAILABLE
        }
        if (parsed.identityPk.contentEquals(self.identityPk)) return AddResult.OWN_CARD

        val contactId = random.bytes(CONTACT_ID_BYTES)
        val conversationId = random.bytes(CONVERSATION_ID_BYTES)
        val nonce = random.bytes(org.ghost.messaging.store.ContentCipher.NONCE_BYTES)
        return database.transaction { tx ->
            val existing = store.contactByIdentity(tx.sql, parsed.identityPk)
            if (existing != null) {
                return@transaction whenKnown(existing, card, self)
            }
            if (store.contactCount(tx.sql) >= MAX_CONTACTS) return@transaction AddResult.LIMIT_REACHED
            val cardEnv = self.content.seal(nonce, contactId, card)
            store.insertContact(
                tx = tx,
                contactId = contactId,
                identityPk = parsed.identityPk,
                cardEnv = cardEnv,
                cardIndex = parsed.cardIndex,
                trust = trustOf(source),
                source = source,
                requestUntilDay = null,
            )
            store.insertConversation(tx, conversationId, contactId)
            forgetOrphans(tx, card)
            AddResult.ADDED
        }
    }

    /**
     * The `dm_orphan_namespace` rows of a card that is live again (phase review ENG-7).
     *
     * A card deleted while its namespaces still had ops left rows that SWEEP discharges once those
     * ops end. Added again before then, the same card derives the same namespaces: without this,
     * the next sweep after the old ops ended removed the **new** contact's inbox and bundle
     * namespaces — an open fetch window among them. `M_c` is deleted with the other two (Phase 11
     * design §5.1: a later media send to the re-added contact deletes a pending orphan row in its
     * own transaction and registers the namespace again).
     */
    private fun forgetOrphans(tx: SyncTransaction, card: ByteArray) {
        val derived = crypto.deriveCard(card, ORPHAN_SLOT)
        if (derived !is DmCards.DeriveResult.Ok) return
        store.deleteOrphan(tx, derived.values.inboxNamespace)
        store.deleteOrphan(tx, derived.values.bundleNamespace)
        store.deleteOrphan(tx, derived.values.mediaNamespace)
        derived.values.clearSecrets()
    }

    /**
     * Rule R-E3: re-adding the **identical** card of an existing contact is a no-op; any other
     * difference is refused in Phase 9, because there is no card rotation (§12.5). A blocked
     * contact's card was erased at block, so re-adding one is refused too — §8.3's state machine
     * says unblocking deletes the row and the user adds the card again, which is a
     * [ContactSteps.unblock] followed by a fresh [addContact].
     */
    private fun whenKnown(
        existing: ContactStore.ContactRow,
        card: ByteArray,
        self: SelfContext,
    ): AddResult {
        if (existing.trust == ContactStore.Trust.REVOKED) return AddResult.REVOKED_IDENTITY
        val storedEnv = existing.cardEnv ?: return AddResult.CARD_CHANGED
        val stored = self.content.open(storedEnv, existing.contactId) ?: return AddResult.CARD_CHANGED
        return if (stored.contentEquals(card)) AddResult.ALREADY_KNOWN else AddResult.CARD_CHANGED
    }

    /** §13.2 `contacts`: ids and enums only, never a time (T33); the alias decrypts here, into memory only. */
    fun contacts(): List<ContactView> = database.transaction { tx ->
        val self = contexts.get()
        store.contacts(tx.sql).map { row ->
            val name = self?.let { s ->
                row.nameEnv?.let { env -> s.content.open(env, row.contactId)?.toString(Charsets.UTF_8) }
            }
            ContactView(row.contactId, row.trust, row.establishment, row.source, row.resetNeeded, name)
        }
    }

    /** Phase 13 §3.6 (`conversationTimer`): the conversation's own timer code, null when off. */
    fun conversationTimer(contactId: ByteArray): org.ghost.messaging.api.Timer? =
        database.transaction { tx ->
            store.conversation(tx.sql, contactId)?.timerCode?.let { org.ghost.messaging.api.Timer.ofCode(it) }
        }

    /** Phase 13 §3.6 (`conversationSummaries`): contact id, live unread count, newest live message
     * minute - never a text, never a key (T33). */
    fun conversationSummaries(nowMinute: Long): List<org.ghost.messaging.api.ConversationSummary> =
        database.transaction { tx ->
            val contacts = store.contacts(tx.sql)
            val summaries = org.ghost.messaging.store.MessageStore().conversationSummaries(
                tx.sql,
                contacts.map { it.contactId },
                { id -> store.conversation(tx.sql, id)?.conversationId },
                nowMinute,
            )
            contacts.mapNotNull { row ->
                val (unread, newest) = summaries[row.contactId] ?: return@mapNotNull null
                org.ghost.messaging.api.ConversationSummary(row.contactId, unread, newest ?: 0L)
            }
        }

    /** Phase 13 §3.6 (`rename`): seals the alias under the content key with the contact id as the
     * associated data (the card's own pattern), or clears it. False when there is no such contact. */
    fun rename(contactId: ByteArray, name: String?): Boolean {
        val self = contexts.get() ?: if (crypto.isAvailable()) return false else return false
        return database.transaction { tx ->
            if (store.contact(tx.sql, contactId) == null) return@transaction false
            if (name == null) {
                store.setName(tx, contactId, null)
            } else {
                val nonce = random.bytes(org.ghost.messaging.store.ContentCipher.NONCE_BYTES)
                store.setName(tx, contactId, self.content.seal(nonce, contactId, name.toByteArray(Charsets.UTF_8)))
            }
            true
        }
    }

    /** §13.2's add followed by the §3.6 alias in the same state (the alias rides the card's identity key). */
    fun addContact(card: ByteArray, source: ContactStore.Source, name: String?): AddResult {
        val result = addContact(card, source)
        if (name != null && (result == AddResult.ADDED || result == AddResult.ALREADY_KNOWN)) {
            val self = contexts.get() ?: return result
            val parsed = (crypto.parseCard(card) as? DmCards.ParseResult.Ok)?.card ?: return result
            database.transaction { tx ->
                val row = store.contactByIdentity(tx.sql, parsed.identityPk) ?: return@transaction
                val nonce = random.bytes(org.ghost.messaging.store.ContentCipher.NONCE_BYTES)
                store.setName(tx, row.contactId, self.content.seal(nonce, row.contactId, name.toByteArray(Charsets.UTF_8)))
            }
        }
        return result
    }

    /**
     * §12.3: `acceptRequest` makes a request `unverified`, which is the first state sending is
     * allowed from (§8.2 rule 6). Nothing is sent, and the requester cannot tell (T28).
     */
    fun acceptRequest(contactId: ByteArray): RequestResult =
        moveRequest(contactId, ContactStore.Trust.UNVERIFIED, forget = contexts.get())

    /**
     * §12.3: `blockRequest` keeps the identity, so later requests from it are dropped at `RECV`
     * R5 before any state change.
     */
    fun blockRequest(contactId: ByteArray): RequestResult {
        val self = contexts.get() ?: return RequestResult.UNAVAILABLE
        return database.transaction { tx ->
            val row = store.contact(tx.sql, contactId)
                ?: return@transaction RequestResult.NOT_A_REQUEST
            if (row.trust != ContactStore.Trust.REQUEST) {
                return@transaction RequestResult.NOT_A_REQUEST
            }
            if (!blockRows(tx, self, row)) return@transaction RequestResult.UNAVAILABLE
            RequestResult.DONE
        }
    }

    /**
     * §12.3: `rejectRequest` deletes the contact with everything that hangs off it — the session,
     * the pair keys, the rows — in one transaction, by the schema's own cascades.
     *
     * A later intro envelope from the same identity creates a **fresh** request, with a new
     * `contact_id`, which is why D3's tags do not stop it and why §21.4 point 4's freshness bound
     * is what keeps a relay from resurrecting a rejected requester for ever (L7-D8).
     */
    fun rejectRequest(contactId: ByteArray): RequestResult {
        val self = contexts.get() ?: return RequestResult.UNAVAILABLE
        return database.transaction { tx ->
            val row = store.contact(tx.sql, contactId)
                ?: return@transaction RequestResult.NOT_A_REQUEST
            if (row.trust != ContactStore.Trust.REQUEST) {
                return@transaction RequestResult.NOT_A_REQUEST
            }
            if (!deleteRows(tx, self, row)) return@transaction RequestResult.UNAVAILABLE
            RequestResult.DONE
        }
    }

    /**
     * [forget], when given, is the context that opens the request's card so an accepted request
     * forgets the orphan rows its card left, as [addContact] does (phase review ENG-7). It is
     * resolved before the transaction opens, like [block]'s.
     */
    private fun moveRequest(
        contactId: ByteArray,
        to: ContactStore.Trust,
        forget: SelfContext? = null,
    ): RequestResult =
        database.transaction { tx ->
            val row = store.contact(tx.sql, contactId)
                ?: return@transaction RequestResult.NOT_A_REQUEST
            if (row.trust != ContactStore.Trust.REQUEST) {
                return@transaction RequestResult.NOT_A_REQUEST
            }
            store.setTrust(tx, contactId, to)
            if (forget != null) {
                row.cardEnv?.let { forget.content.open(it, contactId) }?.let { forgetOrphans(tx, it) }
            }
            RequestResult.DONE
        }

    /**
     * §12.4 `block`: local, and the card goes with it.
     *
     * The contact's deposits still land in this inbox — they are charged to this identity's own
     * allowance — and are dropped when they arrive: a pair hint no longer matches (the keys are
     * gone) and an intro envelope hits the blocked identity at `RECV` R5. Nothing is sent, the
     * contact is not told, and copies on its device are not touched; the Phase 13 UI says all
     * three (FR-4.7).
     */
    fun block(contactId: ByteArray): Boolean {
        // Resolved before the transaction opens, like every other step's crypto (§7.2's "each step
        // is exactly one transaction", §22.11 item 17). `SelfContexts.get()` opens a transaction of
        // its own when its cache is cold — after `onActivated`, `onRestored` or a context close —
        // and a nested one on the same thread is an exception out of the facade, not a result.
        val self = contexts.get() ?: return false
        return database.transaction { tx ->
            val row = store.contact(tx.sql, contactId) ?: return@transaction false
            blockRows(tx, self, row)
        }
    }

    /**
     * §12.4 `unblock`: the blocked row is deleted, and the user must add the card again — the card
     * was erased at block, so unblocking cannot silently restore an address.
     */
    fun unblock(contactId: ByteArray): Boolean {
        val self = contexts.get() ?: return false
        return database.transaction { tx ->
            val row = store.contact(tx.sql, contactId) ?: return@transaction false
            if (row.trust != ContactStore.Trust.BLOCKED) return@transaction false
            deleteRows(tx, self, row)
        }
    }

    /**
     * §8.7 `resetSession(c)`: a user action that deletes **both** session rows (R-SS0) and leaves
     * the contact to the one-shot bundle fetch of §5.5.
     *
     * It is not a key change and it is not a reconnect: the contact's Olm identity is unchanged, so
     * the first flight of the new session reaches it as an ordinary renewal under R-SS1, with no
     * warning and no notice TLV (§8.3's "an intro PreKey message with `OI′ = OI` … a content-free
     * session-renewed contact event"). What it *is* is the user's answer to a conversation that
     * stopped working — a `reset_needed` contact whose bundle named an identity this device could
     * not build on, a session whose state is corrupt — and the design gives it a `reset` control
     * (§21.8 point 1) rather than a silent delete, because a session deleted on one side and kept
     * on the other is exactly the state that produces nothing at all.
     *
     * True when the rows were deleted; the caller sends the control and runs `EST-START`.
     */
    fun resetSession(contactId: ByteArray): Boolean {
        contexts.get() ?: return false
        return database.transaction { tx ->
            val row = store.contact(tx.sql, contactId) ?: return@transaction false
            if (row.trust != ContactStore.Trust.UNVERIFIED &&
                row.trust != ContactStore.Trust.VERIFIED
            ) {
                return@transaction false
            }
            tx.sql.exec("DELETE FROM olm_session WHERE contact_id = ?", listOf(contactId))
            // The candidate of an earlier attempt is not reused: §21.7 point 2 has `EST-START`
            // forget the namespace's tombstones so the bundle can be fetched again, and a reset is
            // the user saying the stored one did not work.
            store.deleteBundleCandidate(tx, contactId)
            store.setResetNeeded(tx, contactId, false)
            true
        }
    }

    /** §12.4 `deleteContact`: every row of the contact, and its namespaces recorded as orphans. */
    fun deleteContact(contactId: ByteArray): Boolean {
        val self = contexts.get() ?: return false
        return database.transaction { tx ->
            val row = store.contact(tx.sql, contactId) ?: return@transaction false
            deleteRows(tx, self, row)
        }
    }

    /**
     * The rows a block clears: the card, both sessions, the pair keys and offers, the peer keys,
     * the pending sends, the held rows and the scheduled controls — §12.4's list, all of it. The
     * conversation's messages are kept until their timers, which the UI may delete.
     *
     * **[recordOrphans] runs first and may refuse.** Everything after it erases the card the two
     * namespaces are derived from, so an orphan row not written before it can never be written
     * afterwards: `X_c` and `P_c` would keep their `:sync` rows, relay sets and credentials for
     * good, with nothing left on the device able to name them. That breaks §21.12 point 3 and the
     * "≤ 7 d" of L7-D7, which is the only thing that makes the residue declarable. Refusing the
     * block instead — the DM context is closed, so the user is locked out of everything else too —
     * leaves a state the same action succeeds from once it reopens.
     *
     * The fetch window closes before the rows go, because after them nothing can: the actor only
     * visits `fetching` contacts and `block` makes this one `card_only` (§12.4, L7-D6).
     */
    private fun blockRows(
        tx: SyncTransaction,
        self: SelfContext,
        row: ContactStore.ContactRow,
    ): Boolean {
        if (!recordOrphans(tx, self, row)) return false
        establishment.abandonFetch(tx, row)
        clearKeyMaterial(tx, row)
        store.block(tx, row.contactId)
        return true
    }

    /** Everything a delete takes: the contact row, and the cascades of the schema behind it. */
    private fun deleteRows(
        tx: SyncTransaction,
        self: SelfContext,
        row: ContactStore.ContactRow,
    ): Boolean {
        if (!recordOrphans(tx, self, row)) return false
        establishment.abandonFetch(tx, row)
        // `dm_conversation`, `dm_message`, `dm_outbound_item`, `dm_outbound_op`,
        // `dm_pending_send`, `dm_pair_key`, `dm_pair_offer`, `dm_peer_pq`, `dm_bundle_candidate`,
        // `dm_held` and `dm_scheduled` all cascade from `dm_contact` (§13.6 step 5), so one
        // delete is the whole contact.
        store.deleteContact(tx, row.contactId)
        return true
    }

    /**
     * §12.4's list of what a block erases, and the state changes the rows it erases owed.
     *
     * A pending send is **failed**, not merely deleted: `dm_pending_send` is the only thing that
     * could ever have resolved its `dm_outbound_item` (left `pending`, still holding the sealed
     * L0) and its `dm_message` (left `queued`, which the UI shows as still on its way). Deleting
     * the row alone stranded both, and with the conversation timer off (`timer_code = 0`, so
     * `delete_at_minute IS NULL`) neither ever expires either.
     *
     * `dm_held` and `dm_scheduled` are in §12.4's list and in §7.2's KEYDEC row ("held rows
     * (deleted on block)"). Nothing writes either table before slice S8, so both DELETEs are inert
     * today; they are here because the list is the rule, and a step that quietly implements six of
     * its eight items is how the other two get missed on the day the writers land.
     */
    private fun clearKeyMaterial(tx: SyncTransaction, row: ContactStore.ContactRow) {
        for (pending in messages.pendingSends(tx.sql, row.contactId)) {
            messages.failPending(tx, pending.itemId)
        }
        tx.sql.exec("DELETE FROM olm_session WHERE contact_id = ?", listOf(row.contactId))
        tx.sql.exec("DELETE FROM dm_pair_key WHERE contact_id = ?", listOf(row.contactId))
        tx.sql.exec("DELETE FROM dm_pair_offer WHERE contact_id = ?", listOf(row.contactId))
        tx.sql.exec("DELETE FROM dm_peer_pq WHERE contact_id = ?", listOf(row.contactId))
        tx.sql.exec("DELETE FROM dm_bundle_candidate WHERE contact_id = ?", listOf(row.contactId))
        tx.sql.exec("DELETE FROM dm_pending_send WHERE contact_id = ?", listOf(row.contactId))
        // The two S8 tables go through their DAO, which is where their bounded reads live: a raw
        // read of `dm_held` written outside it is how the unbounded recovery query of §22.13
        // item 8 escaped the one place that could have caught it.
        held.deleteHeldFor(tx, row.contactId)
        held.deleteScheduledFor(tx, row.contactId)
    }

    /**
     * §21.12 point 3: `X_c`, `P_c` and `M_c` become `dm_orphan_namespace` rows, and **SWEEP** calls
     * `Namespaces.remove` for each once the contact's ops are released. The removal is not here:
     * gate G-DM2 gives `Namespaces.remove` to the establishment steps and to SWEEP alone, and
     * doing it inline would withdraw a namespace whose last op is still in flight.
     *
     * The residue lasts at most until that op's deadline (≤ 7 d) and is declared in L7-D7.
     * `M_c` (Phase 11 design §5.1) is the third: registered only at a media send and never
     * redeemed, it is recorded with the other two so a block or delete cannot leave the
     * contact's media namespace behind. The recording is §5.1's one indivisible act: the
     * contact's `media_upload` rows hold the **only other foreign key** into `M_c`'s
     * `sync_namespace` row, so they are deleted **in this transaction**, beside the orphan
     * insert ([MediaOrphanStore.deleteUploadsOf], the producer's shape) — left behind, they
     * would let SWEEP's discharge DELETE the namespace and die on
     * `SQLITE_CONSTRAINT_FOREIGNKEY`, and the exception would roll back the entire sweep pass
     * (T25: expired messages stop being erased; the self-heal is unreachable, a blocked
     * contact's card is gone and [MediaOrphanSteps.recordIfOrphaned] returns false for it).
     *
     * **False means "do not proceed".** The namespaces are derived from the card, so once the card
     * is gone they cannot be recomputed; an early return that let the delete commit anyway would
     * leave a `:sync` residue nothing on the device can name and no bound can cover. A blocked row
     * is the one contact that legitimately has no card — block recorded its orphans already — so
     * unblocking it proceeds without recording them twice.
     */
    private fun recordOrphans(
        tx: SyncTransaction,
        self: SelfContext,
        row: ContactStore.ContactRow,
    ): Boolean {
        if (row.trust == ContactStore.Trust.BLOCKED && row.cardEnv == null) return true
        val cardEnv = row.cardEnv ?: return false
        val card = self.content.open(cardEnv, row.contactId) ?: return false
        val derived = crypto.deriveCard(card, ORPHAN_SLOT)
        if (derived !is DmCards.DeriveResult.Ok) return false
        store.addOrphan(tx, derived.values.inboxNamespace)
        store.addOrphan(tx, derived.values.bundleNamespace)
        // §5.1's indivisible act, with the orphan insert above: the contact's media_upload rows
        // hold the only other foreign key into M_c's sync_namespace row, and SWEEP's discharge
        // of this row deletes that one (MediaOrphanSteps.recordIfOrphaned's deleteUploadsOf
        // shape — the same delete, in the same transaction as the recording).
        mediaOrphans.deleteUploadsOf(tx, derived.values.mediaNamespace)
        store.addOrphan(tx, derived.values.mediaNamespace)
        derived.values.clearSecrets()
        return true
    }

    private fun trustOf(source: ContactStore.Source): ContactStore.Trust = when (source) {
        ContactStore.Source.QR_IN_PERSON -> ContactStore.Trust.VERIFIED
        ContactStore.Source.LINK -> ContactStore.Trust.UNVERIFIED
        ContactStore.Source.REQUEST -> ContactStore.Trust.REQUEST
    }

    companion object {
        /** `dm_contact.contact_id` is 16 random bytes; Olm never sees it (§8.1). */
        const val CONTACT_ID_BYTES: Int = 16

        /** `dm_conversation.conversation_id`, likewise random and WITHOUT ROWID (T33). */
        const val CONVERSATION_ID_BYTES: Int = 16

        /** §12.6, and the bound on the hint work of rule R-S5. */
        const val MAX_CONTACTS: Int = 1_000

        /** §12.3: the request cap, counted at `RECV` R5. */
        const val MAX_PENDING_REQUESTS: Int = 64

        /**
         * The slot the orphan bookkeeping derives with. The namespaces `X_c` and `P_c` are
         * **slot-independent** — only the bearer secrets carry the slot (§21.2 point 1) — so any
         * slot yields the same two namespaces, and the secrets this call also produces are wiped
         * immediately.
         */
        private const val ORPHAN_SLOT: Int = 0
    }
}
