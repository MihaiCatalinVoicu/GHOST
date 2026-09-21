package org.ghost.messaging.engine

import org.ghost.messaging.port.DmCrypto
import org.ghost.messaging.store.ContactStore
import org.ghost.messaging.store.HeldStore
import org.ghost.messaging.store.SessionStore
import org.ghost.sync.api.SyncDatabase
import java.security.MessageDigest

/**
 * **KEYDEC** (Phase 9 design §7.2, §8.3) and the safety numbers of §8.4.
 *
 * A key change is the one state in the DM engine that **never resolves itself** (declared,
 * L7-D17): the contact sits in `changed`, sending is refused before any native session call, and
 * new-key ciphertext waits in `dm_held` until the user acknowledges, verifies or blocks. This
 * class is the three user actions and the two reads they need.
 *
 * **What one acceptance does, in one transaction:**
 *  1. `pinned := pending`, `pending := NULL`, the trust state to `unverified` (acknowledge) or
 *     `verified` (verify), `verified_fp` set only by the second.
 *  2. **Both** `olm_session` rows go (R-SS0): "a session never outlives the identity it was
 *     created with" (§8.2 rule 5).
 *  3. The secrets of this device's offered roots for the contact are erased and its **out** keys
 *     for it deleted, so the next user message mints a new generation and offers a new root
 *     (§21.3 point 3) — a different device may now speak for that contact.
 *  4. The contact's `dm_peer_pq` rows go and its unacknowledged PQ offers are discarded
 *     (§22.8.6 rule 1): with no session left, no `peer_gen_id` names a key the new device holds,
 *     and a re-attached offer encapsulated to a pre-change key could never be opened.
 *
 * Then **HELD** runs, outside this transaction and in §22.8.1's order.
 *
 * **Nothing reaches a relay** (§8.3, T28, T31, NI-DM5): detection, holding, acknowledgement and
 * verification are local. The re-establishment that follows is the user's **next send** — there is
 * no automatic one, which is D10 and §8.7 together.
 */
internal class KeyDecision(
    private val database: SyncDatabase,
    private val crypto: DmCrypto,
    private val contexts: SelfContexts,
) {
    private val contacts = ContactStore()
    private val sessions = SessionStore()
    private val held = HeldStore()

    /** What a decision or a verification did (§13.2). Enums only. */
    enum class Outcome {
        /** The decision was applied; the caller runs HELD. */
        DONE,

        /** No such contact, or it is not in `changed` (for the two key-change decisions). */
        NOT_CHANGED,

        /** The scanned code is another version of the format (§8.4). */
        VERSION_MISMATCH,

        /** The scanned code is a safety number of another pair, or of another key. */
        MISMATCH,

        /** The DM context is closed or the library is missing (§13.2). */
        UNAVAILABLE,
    }

    /** A safety number as §13.2 renders it: the 60 digits and the 65 scannable bytes (§8.4). */
    class Number(val digits: String, val scannable: ByteArray) {
        /** Never shows the digits: they are a fingerprint of two identities (T3). */
        override fun toString(): String = "Number(redacted)"
    }

    // ------------------------------------------------------------ safety numbers

    /**
     * §8.4: the safety number of a contact's **pinned** Olm identity, or null when there is none
     * yet (a card added but never established) or the context is closed.
     *
     * No network I/O, no transaction that writes anything (T31).
     */
    fun safetyNumber(contactId: ByteArray): Number? = numberFor(contactId) { it.pinnedIdentity }

    /**
     * §8.4: the safety number the contact **would** have after an acknowledgement, computed with
     * `pending_identity` while the contact is `changed`.
     *
     * It exists so the user can verify before deciding rather than after: `verifyKeyChange` then
     * compares a code scanned against this number, and acknowledging without scanning is the
     * weaker of the two decisions FR-4.6 offers.
     */
    fun pendingSafetyNumber(contactId: ByteArray): Number? =
        numberFor(contactId) { it.pendingIdentity }

    private fun numberFor(
        contactId: ByteArray,
        peer: (ContactStore.ContactRow) -> ByteArray?,
    ): Number? {
        val self = contexts.get() ?: return null
        val contact = database.transaction { tx -> contacts.contact(tx.sql, contactId) } ?: return null
        val peerOlm = peer(contact) ?: return null
        val number = crypto.safetyNumber(
            ownIdentityPk = self.identityPk,
            ownOlm = self.olmIdentity,
            peerIdentityPk = contact.identityPk,
            peerOlm = peerOlm,
        ) ?: return null
        return Number(number.digits, number.scannable)
    }

    /**
     * §8.4's comparison of a scanned code: the version byte must match, the scanned `own` part
     * must be this device's `peer` part and the scanned `peer` part this device's `own` part.
     *
     * It is a **byte comparison of two public fingerprints** and not protocol logic, which is why
     * it is here and not behind the JNI surface: both sides of it came out of `safetyNumber`, and
     * a caller that got the halves the wrong way round would read its own number as the peer's —
     * the one mistake this comparison exists to catch.
     */
    private fun compare(computed: ByteArray, scanned: ByteArray): Outcome = when {
        scanned.size != computed.size -> Outcome.VERSION_MISMATCH
        scanned.isEmpty() || scanned[0] != computed[0] -> Outcome.VERSION_MISMATCH
        else -> {
            val half = (computed.size - 1) / 2
            val ownPart = computed.copyOfRange(1, 1 + half)
            val peerPart = computed.copyOfRange(1 + half, computed.size)
            val scannedOwn = scanned.copyOfRange(1, 1 + half)
            val scannedPeer = scanned.copyOfRange(1 + half, scanned.size)
            if (scannedOwn.contentEquals(peerPart) && scannedPeer.contentEquals(ownPart)) {
                Outcome.DONE
            } else {
                Outcome.MISMATCH
            }
        }
    }

    /**
     * §8.4 `markVerified`: the user scanned a contact's code and it matched, so the contact becomes
     * `verified` and `verified_fp` records **what** was compared.
     *
     * It is not a key-change decision: a contact in `changed` goes through [verifyKeyChange], which
     * compares the number of the **pending** identity and moves the pin as well.
     */
    fun markVerified(contactId: ByteArray, scanned: ByteArray): Outcome {
        val number = safetyNumber(contactId) ?: return Outcome.UNAVAILABLE
        val outcome = compare(number.scannable, scanned)
        if (outcome != Outcome.DONE) return outcome
        return markVerifiedManually(contactId, fingerprintOf(number))
    }

    /**
     * §8.4: the user compared the 60 digits by voice or in person and says they matched. Phase 13
     * states what the user asserted; the engine records the same fingerprint either way.
     */
    fun markVerifiedManually(contactId: ByteArray, fingerprint: ByteArray? = null): Outcome {
        val fp = fingerprint ?: safetyNumber(contactId)?.let { fingerprintOf(it) }
        ?: return Outcome.UNAVAILABLE
        return database.transaction { tx ->
            val contact = contacts.contact(tx.sql, contactId)
                ?: return@transaction Outcome.NOT_CHANGED
            when (contact.trust) {
                ContactStore.Trust.UNVERIFIED -> {
                    contacts.setTrust(tx, contactId, ContactStore.Trust.VERIFIED)
                    contacts.setVerifiedFp(tx, contactId, fp)
                    Outcome.DONE
                }
                // Already verified: record the comparison again and change nothing else. There is
                // no `verified → unverified` edge (§8.3's trigger), because a verification is only
                // ever cleared by a key change.
                ContactStore.Trust.VERIFIED -> {
                    contacts.setVerifiedFp(tx, contactId, fp)
                    Outcome.DONE
                }
                else -> Outcome.NOT_CHANGED
            }
        }
    }

    // -------------------------------------------------------------------- KEYDEC

    /**
     * §8.3 `acknowledgeKeyChange`: "explicit confirmation" (FR-4.6), without a comparison.
     *
     * The contact becomes `unverified`, because the user asserted nothing about the new key — a
     * contact scanned in person a year ago and acknowledged today is not verified any more, and
     * `verified_fp` is cleared to say so.
     */
    fun acknowledge(contactId: ByteArray): Outcome =
        accept(contactId, ContactStore.Trust.UNVERIFIED, verifiedFp = null)

    /**
     * §8.3 `verifyKeyChange`: the user scanned the contact's **new** code and it matched, so the
     * contact becomes `verified` with the new pin.
     */
    fun verifyKeyChange(contactId: ByteArray, scanned: ByteArray): Outcome {
        val number = pendingSafetyNumber(contactId) ?: return Outcome.NOT_CHANGED
        val outcome = compare(number.scannable, scanned)
        if (outcome != Outcome.DONE) return outcome
        return accept(contactId, ContactStore.Trust.VERIFIED, fingerprintOf(number))
    }

    private fun accept(
        contactId: ByteArray,
        trust: ContactStore.Trust,
        verifiedFp: ByteArray?,
    ): Outcome {
        contexts.get() ?: return Outcome.UNAVAILABLE
        return database.transaction { tx ->
            val contact = contacts.contact(tx.sql, contactId)
                ?: return@transaction Outcome.NOT_CHANGED
            if (contact.trust != ContactStore.Trust.CHANGED) return@transaction Outcome.NOT_CHANGED
            val pending = contact.pendingIdentity ?: return@transaction Outcome.NOT_CHANGED
            if (!contacts.acceptPendingIdentity(tx, contactId, trust, verifiedFp)) {
                return@transaction Outcome.NOT_CHANGED
            }
            // R-SS0: both rows, before any new session. A session never outlives the identity it
            // was created with (§8.2 rule 5), and the held rows this releases are first flights of
            // the **new** one.
            sessions.deleteSessions(tx, contactId)
            // §8.3: my offered roots' secrets and my out keys for c go, so the next user message
            // mints a new generation (§21.3 point 3). The offer **rows** stay: `root_gen` is a
            // counter a peer compares against, and a repeated number is a root it silently drops.
            contacts.deleteOutPairKeys(tx, contactId)
            contacts.discardOfferSecrets(tx, contactId)
            // §22.8.6 rule 1: no session survives, so no `peer_gen_id` names a live key.
            contacts.deletePeerPq(tx, contactId)
            // A held row of a superseded pending key cannot be replayed under the new pin; HELD
            // would refuse it row by row, and deleting them here keeps the cap honest.
            held.deleteHeldOtherThan(tx, contactId, pending)
            // A pending send queued before the change stays pending: the contact is sendable
            // again, and the user's next message starts the establishment that flushes it
            // (§21.7 point 4's "retried at the next time-triggered pass").
            Outcome.DONE
        }
    }

    /** `dm_contact.verified_fp = SHA-256(displayable digits)` (§8.4). */
    private fun fingerprintOf(number: Number): ByteArray =
        MessageDigest.getInstance("SHA-256").digest(number.digits.toByteArray(Charsets.US_ASCII))
}
