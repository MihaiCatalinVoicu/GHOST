package org.ghost.messaging.engine

import org.ghost.crypto.bridge.DmBundles
import org.ghost.messaging.port.DmClock
import org.ghost.messaging.port.DmEnvelopes
import org.ghost.messaging.store.ContactStore
import org.ghost.messaging.store.ContentCipher
import org.ghost.sync.api.SyncTransaction
import java.security.MessageDigest

/**
 * **`BUNDLE`** (Phase 9 design §21.7 point 3, §5.4, §5.5): one consumed bundle blob, opened and
 * verified, and the better candidate kept. Runs inside the caller's transaction, beside
 * `markConsumed`.
 *
 * Everything a clock decides stays here rather than in the crate: validity
 * (`now < start(bundle_week + 2)` and `bundle_week ≤ week(now) + 1`, §5.4) and the
 * `(bundle_week, bundle_rank)` rollback rule against `dm_contact.bundle_week_seen` — relays cannot
 * delete old bundles and at most five are live, so a replayed older one must not replace a newer
 * (mutant PM-22).
 *
 * **Why it is a file of its own.** It enqueues nothing, registers nothing and starts no session,
 * which is §21.7 point 7 and the static half of T28 — and gate G-DM2's allowlist is **by file**,
 * on the stated argument that a Kotlin file holds one step. While `BUNDLE` sat inside
 * `EstablishmentSteps.kt`, the allowlist entry that `EST-START`, `EST-READY` and `EST-END` need
 * covered it too, so the one establishment transaction that is driven **directly by an arriving
 * blob** was on the permitted side of T28 by accident. Here it is on the forbidden side, and the
 * gate fails the day a line of it reaches for a relay-visible call.
 */
internal class BundleStep(
    private val envelopes: DmEnvelopes,
    private val material: ContactMaterial,
    private val clock: DmClock,
    private val contexts: SelfContexts,
) {
    private val contacts = ContactStore()

    /** True when this blob produced or improved [contactId]'s candidate. */
    fun bundle(tx: SyncTransaction, contactId: ByteArray, blob: ByteArray): Boolean {
        val self = contexts.get() ?: return false
        val contact = contacts.contact(tx.sql, contactId) ?: return false
        val card = material.card(contact) ?: return false
        val derived = material.fromCard(card, BundleCandidates.ANY_SLOT) ?: return false
        return try {
            val opened = envelopes.openBundle(
                bundleKeyEnv = derived.bundleKeyEnv,
                bundleNamespace = derived.bundleNamespace,
                blob = blob,
                expectedIdentityPk = contact.identityPk,
                expectedCardIndex = contact.cardIndex,
            )
            if (opened !is DmBundles.OpenResult.Ok) return false
            val verified = opened.bundle
            val week = DmTime.week(clock.nowEpochSeconds())
            if (!BundleCandidates.isValid(verified.bundleWeek, week)) return false
            val seen = contact.bundleWeekSeen
            if (seen != null && verified.bundleWeek < seen) return false
            val plain = BundleCandidates.plain(verified)
            contacts.putBundleCandidate(
                tx = tx,
                contactId = contactId,
                bundleEnv = self.content.seal(
                    nonce = BundleCandidates.nonce(contactId, plain),
                    associatedData = contactId,
                    plaintext = plain,
                ),
                bundleWeek = verified.bundleWeek,
                bundleRank = verified.bundleRank,
            )
            contacts.setBundleWeekSeen(tx, contactId, verified.bundleWeek)
            true
        } finally {
            derived.clearSecrets()
        }
    }
}

/**
 * The layout of `dm_bundle_candidate.bundle_env` and the two clock rules around it, shared by the
 * step that writes a candidate ([BundleStep]) and the step that reads one back
 * ([EstablishmentSteps.estReady]).
 */
internal object BundleCandidates {

    /** The six fields a candidate row carries (§13.6's one `bundle_env`). */
    class Candidate(
        val bundleWeek: Long,
        val bundleRank: Int,
        val genId: Int,
        val olmIdentity: ByteArray,
        val fallbackKey: ByteArray,
        val xwingPublic: ByteArray,
    ) {
        override fun toString(): String = "Candidate(week=$bundleWeek, rank=$bundleRank)"
    }

    /**
     * §5.4 "Validity": a bundle of week `w` is valid while `now < start(w + 2)` and
     * `w ≤ week(now) + 1`. Both need a clock, which is why neither is in the crate.
     */
    fun isValid(bundleWeek: Long, currentWeek: Long): Boolean =
        bundleWeek + 2 > currentWeek && bundleWeek <= currentWeek + 1

    /**
     * The candidate plaintext: the six fields, then zeros to the 1 393 bytes the schema fixes
     * `bundle_env` at (1 421 = 1 393 + the content key's 28 bytes of overhead, §13.6).
     *
     * Padding to the sealed bundle's own length rather than to the fields' length is deliberate:
     * the column's CHECK is the one place a wrong layout shows up as a constraint failure instead
     * of as a silently short read, and a fixed length also means the row says nothing about which
     * fields it carries (T33).
     */
    fun plain(bundle: DmBundles.Verified): ByteArray {
        val out = ByteArray(CANDIDATE_PLAIN_BYTES)
        writeLong(out, 0, bundle.bundleWeek)
        writeInt(out, 8, bundle.bundleRank)
        writeInt(out, 12, bundle.genId)
        bundle.olmIdentity.copyInto(out, 16)
        bundle.fallbackKey.copyInto(out, 48)
        bundle.xwingPublic.copyInto(out, 80)
        return out
    }

    fun read(plain: ByteArray): Candidate {
        check(plain.size == CANDIDATE_PLAIN_BYTES) { "a bundle candidate has the wrong length" }
        return Candidate(
            bundleWeek = readLong(plain, 0),
            bundleRank = readInt(plain, 8),
            genId = readInt(plain, 12),
            olmIdentity = plain.copyOfRange(16, 48),
            fallbackKey = plain.copyOfRange(48, 80),
            xwingPublic = plain.copyOfRange(80, 80 + XWING_PUBLIC_BYTES),
        )
    }

    /**
     * The nonce of a candidate envelope, derived from the **whole plaintext** rather than drawn.
     *
     * Consuming the same bundle twice — a rolled-back `BUNDLE` sees its blob again (§7.8) — then
     * produces the same bytes, so the UPDATE-then-INSERT of `putBundleCandidate` is idempotent and
     * a re-offer cannot leave two candidates that differ only in a nonce.
     *
     * **It has to cover every sealed byte, not a chosen few.** An earlier form hashed
     * `contact_id ‖ OI ‖ F_g ‖ bundle_week` and left `bundle_rank`, `gen_id` and the 1 216-byte
     * X-Wing key out. `putBundleCandidate` replaces the row on a strictly greater
     * `(week, rank)`, so a contact publishing two validly signed bundles of one week with the same
     * Olm identity and fallback key but different generations would have sealed two different
     * plaintexts under the same `(content_key, nonce)` and the same associated data: a
     * ChaCha20-Poly1305 keystream and Poly1305 one-time key reused, which is an AEAD break and not
     * a degradation. Hashing the plaintext makes "same bytes ⇒ same nonce" and "different bytes ⇒
     * different nonce" the same statement.
     */
    fun nonce(contactId: ByteArray, plain: ByteArray): ByteArray =
        MessageDigest.getInstance("SHA-256").apply {
            update(contactId)
            update(plain)
        }.digest().copyOf(ContentCipher.NONCE_BYTES)

    private fun writeLong(out: ByteArray, at: Int, value: Long) {
        for (i in 0 until 8) out[at + i] = ((value shr (8 * (7 - i))) and 0xff).toByte()
    }

    private fun readLong(bytes: ByteArray, at: Int): Long {
        var value = 0L
        for (i in 0 until 8) value = (value shl 8) or (bytes[at + i].toLong() and 0xff)
        return value
    }

    private fun writeInt(out: ByteArray, at: Int, value: Int) {
        for (i in 0 until 4) out[at + i] = ((value shr (8 * (3 - i))) and 0xff).toByte()
    }

    private fun readInt(bytes: ByteArray, at: Int): Int {
        var value = 0
        for (i in 0 until 4) value = (value shl 8) or (bytes[at + i].toInt() and 0xff)
        return value
    }

    /**
     * The namespaces a card derives are slot-independent (§21.2 point 1): only the bearer secrets
     * carry the slot, so any slot answers a question about `X_c` or `P_c`.
     */
    const val ANY_SLOT: Int = 0

    /** An X-Wing encapsulation key (§5.3). */
    private const val XWING_PUBLIC_BYTES: Int = 1216

    /** `dm_bundle_candidate.bundle_env` is 1 421 bytes: 1 393 of plaintext plus 28 (§13.6). */
    private const val CANDIDATE_PLAIN_BYTES: Int = 1393
}
