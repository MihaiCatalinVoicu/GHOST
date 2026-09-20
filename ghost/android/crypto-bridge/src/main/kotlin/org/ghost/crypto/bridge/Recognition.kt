package org.ghost.crypto.bridge

import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * Recognition-hint matching (Phase 9 design §6.2, rules R-S5 and R-S6; §2.4 "What stays in
 * Kotlin: hint **matching** with recognition keys").
 *
 * ```
 * blob(B) = salt(16) || hint(16) || ChaCha20-Poly1305(...)
 * hint    = HMAC-SHA256(R_sel, "ghost/v1/dm-hint" || salt)[0..16]
 * ```
 *
 * **Why matching and not trial decryption (R-S5).** The recipient computes the hints of its
 * candidate **recognition** keys and opens with **at most one** key, the one whose hint matches.
 * There is no trial decryption across keys, so the partitioning-oracle attack on a non-committing
 * AEAD does not apply, and a hint match whose AEAD then fails is a forgery: dropped and counted,
 * never retried under another key. `PM-18` is the mutant that tries every key instead, and the
 * one-attempt spy of §15.2 is what catches it.
 *
 * **Why this is in Kotlin at all.** A recognition key recognises but does not open (rule R-S6), so
 * it is one of the three things §3.2 lets Kotlin hold in clear. The opening key stays wrapped and
 * only the native side ever sees it.
 *
 * **Cost (E-13).** At most 22 recognition keys per contact — the in-week pair keys of every live
 * root generation, the two provisional keys of each live session — plus the own card's `KIO_0`.
 * At `MAX_CONTACTS = 1 000` that is ≤ 22 001 HMAC-SHA256 evaluations for a blob nothing matches.
 * [matchFirst] therefore computes lazily and stops at the first match, and the caller supplies its
 * candidates most-recently-matched first, an order it keeps in memory and never persists (T33).
 */
object Recognition {

    /** The label of §6.2. */
    const val HINT_LABEL: String = "ghost/v1/dm-hint"

    /** The salt is the blob's first 16 bytes. */
    const val SALT_BYTES: Int = 16

    /** The hint is the next 16. */
    const val HINT_BYTES: Int = 16

    /** A blob shorter than this carries no header at all. */
    const val HEADER_BYTES: Int = SALT_BYTES + HINT_BYTES

    /**
     * The 16-byte hint [recognitionKey] produces for [salt].
     *
     * The label and the salt are fed to one HMAC in that order, exactly as §6.2 writes it.
     */
    fun hint(recognitionKey: ByteArray, salt: ByteArray): ByteArray {
        require(salt.size == SALT_BYTES) { "salt has the wrong length" }
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(recognitionKey, "HmacSHA256"))
        mac.update(HINT_LABEL.toByteArray(Charsets.US_ASCII))
        mac.update(salt)
        return mac.doFinal().copyOf(HINT_BYTES)
    }

    /** True when [blob]'s hint is the one [recognitionKey] produces for its own salt. */
    fun matches(blob: ByteArray, recognitionKey: ByteArray): Boolean {
        if (blob.size < HEADER_BYTES) return false
        val computed = hint(recognitionKey, blob.copyOfRange(0, SALT_BYTES))
        // Constant-time in the length of the hint. The value is not a secret — it is on the wire —
        // but a short-circuit here would be a timing signal about which candidate matched, and
        // the candidate order is per-contact state (T33).
        var difference = 0
        for (i in 0 until HINT_BYTES) {
            difference = difference or (computed[i].toInt() xor blob[SALT_BYTES + i].toInt())
        }
        return difference == 0
    }

    /**
     * The first candidate whose hint matches [blob], or null when none does — `drop(unknown_seal)`
     * of §6.5 step 2.
     *
     * [candidates] is walked in order and evaluated lazily, so the most-recently-matched contact
     * costs one HMAC and an unknown blob costs the whole set. The salt is hashed once per
     * candidate and the blob is read once.
     */
    fun <T> matchFirst(blob: ByteArray, candidates: Sequence<Candidate<T>>): Candidate<T>? {
        if (blob.size < HEADER_BYTES) return null
        val salt = blob.copyOfRange(0, SALT_BYTES)
        for (candidate in candidates) {
            val computed = hint(candidate.recognitionKey, salt)
            var difference = 0
            for (i in 0 until HINT_BYTES) {
                difference = difference or (computed[i].toInt() xor blob[SALT_BYTES + i].toInt())
            }
            if (difference == 0) return candidate
        }
        return null
    }

    /** One candidate key of [matchFirst]: its recognition key and what it stands for. */
    class Candidate<T>(
        /** `R_sel` (§6.2). */
        val recognitionKey: ByteArray,
        /** What the caller needs when this one matches: a key class, a row, a contact. */
        val value: T,
    ) {
        /** Never shows the key (T3). */
        override fun toString(): String = "Candidate(redacted)"
    }
}
