package org.ghost.messaging.engine

import org.ghost.crypto.bridge.DmCards
import org.ghost.messaging.port.DmCrypto
import org.ghost.messaging.port.DmRandom
import org.ghost.messaging.store.ContactStore
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
) {
    private val store = ContactStore()

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
        if (parsed.identityPk.contentEquals(ownIdentityPk(self))) return AddResult.OWN_CARD

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
            AddResult.ADDED
        }
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

    /** §13.2 `contacts`: ids and enums only, never a time (T33). */
    fun contacts(): List<ContactView> = database.transaction { tx ->
        store.contacts(tx.sql).map { row ->
            ContactView(row.contactId, row.trust, row.establishment, row.source, row.resetNeeded)
        }
    }

    /**
     * §12.3: `acceptRequest` makes a request `unverified`, which is the first state sending is
     * allowed from (§8.2 rule 6). Nothing is sent, and the requester cannot tell (T28).
     */
    fun acceptRequest(contactId: ByteArray): RequestResult =
        moveRequest(contactId, ContactStore.Trust.UNVERIFIED)

    /**
     * §12.3: `blockRequest` keeps the identity, so later requests from it are dropped at `RECV`
     * R5 before any state change.
     */
    fun blockRequest(contactId: ByteArray): RequestResult = database.transaction { tx ->
        val row = store.contact(tx.sql, contactId) ?: return@transaction RequestResult.NOT_A_REQUEST
        if (row.trust != ContactStore.Trust.REQUEST) return@transaction RequestResult.NOT_A_REQUEST
        blockRows(tx, row)
        RequestResult.DONE
    }

    /**
     * §12.3: `rejectRequest` deletes the contact with everything that hangs off it — the session,
     * the pair keys, the rows — in one transaction, by the schema's own cascades.
     *
     * A later intro envelope from the same identity creates a **fresh** request, with a new
     * `contact_id`, which is why D3's tags do not stop it and why §21.4 point 4's freshness bound
     * is what keeps a relay from resurrecting a rejected requester for ever (L7-D8).
     */
    fun rejectRequest(contactId: ByteArray): RequestResult = database.transaction { tx ->
        val row = store.contact(tx.sql, contactId) ?: return@transaction RequestResult.NOT_A_REQUEST
        if (row.trust != ContactStore.Trust.REQUEST) return@transaction RequestResult.NOT_A_REQUEST
        deleteRows(tx, row)
        RequestResult.DONE
    }

    private fun moveRequest(contactId: ByteArray, to: ContactStore.Trust): RequestResult =
        database.transaction { tx ->
            val row = store.contact(tx.sql, contactId)
                ?: return@transaction RequestResult.NOT_A_REQUEST
            if (row.trust != ContactStore.Trust.REQUEST) {
                return@transaction RequestResult.NOT_A_REQUEST
            }
            store.setTrust(tx, contactId, to)
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
    fun block(contactId: ByteArray): Boolean = database.transaction { tx ->
        val row = store.contact(tx.sql, contactId) ?: return@transaction false
        blockRows(tx, row)
        true
    }

    /**
     * §12.4 `unblock`: the blocked row is deleted, and the user must add the card again — the card
     * was erased at block, so unblocking cannot silently restore an address.
     */
    fun unblock(contactId: ByteArray): Boolean = database.transaction { tx ->
        val row = store.contact(tx.sql, contactId) ?: return@transaction false
        if (row.trust != ContactStore.Trust.BLOCKED) return@transaction false
        deleteRows(tx, row)
        true
    }

    /** §12.4 `deleteContact`: every row of the contact, and its namespaces recorded as orphans. */
    fun deleteContact(contactId: ByteArray): Boolean = database.transaction { tx ->
        val row = store.contact(tx.sql, contactId) ?: return@transaction false
        deleteRows(tx, row)
        true
    }

    /**
     * The rows a block clears: the card, both sessions, the pair keys and offers, the peer keys
     * and the pending sends. The conversation's messages are kept until their timers, which the
     * UI may delete (§12.4).
     */
    private fun blockRows(tx: SyncTransaction, row: ContactStore.ContactRow) {
        clearKeyMaterial(tx, row)
        store.block(tx, row.contactId)
        recordOrphans(tx, row)
    }

    /** Everything a delete takes: the contact row, and the cascades of the schema behind it. */
    private fun deleteRows(tx: SyncTransaction, row: ContactStore.ContactRow) {
        recordOrphans(tx, row)
        // `dm_conversation`, `dm_message`, `dm_outbound_item`, `dm_outbound_op`,
        // `dm_pending_send`, `dm_pair_key`, `dm_pair_offer`, `dm_peer_pq`, `dm_bundle_candidate`,
        // `dm_held` and `dm_scheduled` all cascade from `dm_contact` (§13.6 step 5), so one
        // delete is the whole contact.
        store.deleteContact(tx, row.contactId)
    }

    private fun clearKeyMaterial(tx: SyncTransaction, row: ContactStore.ContactRow) {
        tx.sql.exec("DELETE FROM olm_session WHERE contact_id = ?", listOf(row.contactId))
        tx.sql.exec("DELETE FROM dm_pair_key WHERE contact_id = ?", listOf(row.contactId))
        tx.sql.exec("DELETE FROM dm_pair_offer WHERE contact_id = ?", listOf(row.contactId))
        tx.sql.exec("DELETE FROM dm_peer_pq WHERE contact_id = ?", listOf(row.contactId))
        tx.sql.exec("DELETE FROM dm_bundle_candidate WHERE contact_id = ?", listOf(row.contactId))
        tx.sql.exec("DELETE FROM dm_pending_send WHERE contact_id = ?", listOf(row.contactId))
    }

    /**
     * §21.12 point 3: `X_c` and `P_c` become `dm_orphan_namespace` rows, and **SWEEP** calls
     * `Namespaces.remove` for each once the contact's ops are released. The removal is not here:
     * gate G-DM2 gives `Namespaces.remove` to the establishment steps and to SWEEP alone, and
     * doing it inline would withdraw a namespace whose last op is still in flight.
     *
     * The residue lasts at most until that op's deadline (≤ 7 d) and is declared in L7-D7.
     */
    private fun recordOrphans(tx: SyncTransaction, row: ContactStore.ContactRow) {
        val self = contexts.get() ?: return
        val cardEnv = row.cardEnv ?: return
        val card = self.content.open(cardEnv, row.contactId) ?: return
        val derived = crypto.deriveCard(card, ORPHAN_SLOT)
        if (derived !is DmCards.DeriveResult.Ok) return
        store.addOrphan(tx, derived.values.inboxNamespace)
        store.addOrphan(tx, derived.values.bundleNamespace)
        derived.values.clearSecrets()
    }

    private fun ownIdentityPk(self: SelfContext): ByteArray =
        self.card.card.copyOfRange(IDENTITY_PK_OFFSET, IDENTITY_PK_OFFSET + IDENTITY_PK_BYTES)

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
         * `card = version(1) || card_index(2) || identity_pk(32) || …` (§3.3), so the identity key
         * starts at byte 3. The offset is here rather than in the crate because the comparison it
         * serves — "is this my own card?" — is a byte comparison Kotlin makes (§2.6 function 3).
         */
        const val IDENTITY_PK_OFFSET: Int = 3

        /** An Ed25519 public key. */
        const val IDENTITY_PK_BYTES: Int = 32

        /**
         * The slot the orphan bookkeeping derives with. The namespaces `X_c` and `P_c` are
         * **slot-independent** — only the bearer secrets carry the slot (§21.2 point 1) — so any
         * slot yields the same two namespaces, and the secrets this call also produces are wiped
         * immediately.
         */
        private const val ORPHAN_SLOT: Int = 0
    }
}
