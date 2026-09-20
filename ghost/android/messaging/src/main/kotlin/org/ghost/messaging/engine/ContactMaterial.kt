package org.ghost.messaging.engine

import org.ghost.crypto.bridge.DmCards
import org.ghost.messaging.port.DmCrypto
import org.ghost.messaging.store.ContactStore

/**
 * A contact's card and what it derives (Phase 9 design §3.2, §5.1).
 *
 * `dm_contact.card_env` holds the 131-byte card v2 under the content key with the contact id as
 * associated data (§13.8), so a card cannot be moved to another contact's row and be believed.
 * Opening it and deriving from it is the one thing SEND, the establishment steps and KEEPER all
 * need, and it is here so that no step has to know how a card is stored.
 *
 * **Every derived value is a bearer secret or an envelope.** The two namespaces and the two
 * recognition keys are values Kotlin may hold (§3.2's closing sentence); the deposit and fetch
 * secrets go on the wire inside a credential v3 and are **zeroised by the caller** —
 * [DmCards.Derived.clearSecrets] — as soon as the credential or the verifier is built; the two
 * opening keys `KIO_c` and `KB_c` are transient envelopes that go straight back to the native
 * side (rule R-S6).
 */
internal class ContactMaterial(
    private val crypto: DmCrypto,
    private val contexts: SelfContexts,
) {
    /** The contact's card v2, or null when the row has none (a blocked contact) or it will not open. */
    fun card(contact: ContactStore.ContactRow): ByteArray? {
        val self = contexts.get() ?: return null
        val env = contact.cardEnv ?: return null
        return self.content.open(env, contact.contactId)
    }

    /** The card-level values of one relay slot, or null when the card is gone or unreadable. */
    fun derived(contact: ContactStore.ContactRow, slot: Int): DmCards.Derived? {
        val card = card(contact) ?: return null
        return fromCard(card, slot)
    }

    /** The same, from card bytes the caller already opened: the loop form the steps use. */
    fun fromCard(card: ByteArray, slot: Int): DmCards.Derived? =
        when (val result = crypto.deriveCard(card, slot)) {
            is DmCards.DeriveResult.Ok -> result.values
            else -> null
        }

    /**
     * The namespaces a card names. They are **slot-independent** (§21.2 point 1: only the bearer
     * secrets carry the slot), so this answers a question about `X_c` and `P_c` with one
     * derivation and wipes the secrets it also produced.
     */
    fun namespaces(card: ByteArray): Namespaces? {
        val derived = fromCard(card, ANY_SLOT) ?: return null
        return try {
            Namespaces(derived.inboxNamespace, derived.bundleNamespace)
        } finally {
            derived.clearSecrets()
        }
    }

    /** A contact's two namespaces (§5.1). */
    class Namespaces(val inbox: ByteArray, val bundle: ByteArray) {
        override fun toString(): String = "Namespaces(redacted)"
    }

    private companion object {
        /** Any slot yields the same two namespaces; the secrets it also yields are wiped. */
        const val ANY_SLOT = 0
    }
}
