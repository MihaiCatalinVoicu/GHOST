package org.ghost.crypto.bridge

import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * Channel hint matching with recognition keys (Phase 10 design §5.6 CS-S5 and CS-S6, §6.3.2; the
 * DM rule of Phase 9 §6.2 R-S5 and R-S6 with the channel label):
 *
 * ```
 * blob(B) = salt(16) || hint(16) || ChaCha20-Poly1305(k, 0^12, AD, P)
 * hint    = HMAC-SHA256(R, "ghost/v1/ch-hint" || mode(1) || salt)[0..16]
 * ```
 *
 * The receiver computes the hints of its candidate (recognition key, mode) pairs — `R_ep(e)` with
 * mode 0x11 for the current and every retained epoch, `R_join(g)` with modes 0x12 and 0x13 for
 * each listened generation — and opens a blob with **at most one** key, the one whose hint
 * matches: no trial decryption across keys (the partitioning-oracle argument), and a match whose
 * AEAD then fails is a forgery, dropped and counted, never retried under another candidate.
 *
 * **Why this is in Kotlin.** A recognition key recognises and never opens (CS-S6): it is what §3.4
 * lets Kotlin hold in clear, and matching here keeps the opening keys (`K_ep`, `JK_g`) wrapped
 * until the one native `open` call. The label `ghost/v1/ch-hint` is the one channel literal G-M3
 * rule 4 admits in Kotlin: a MAC keyed by a secret the native side derived, not a derivation.
 */
object ChannelRecognition {

    /** The label of §5.6. */
    const val HINT_LABEL: String = "ghost/v1/ch-hint"

    /** The salt is the blob's first 16 bytes. */
    const val SALT_BYTES: Int = 16

    /** The hint is the next 16. */
    const val HINT_BYTES: Int = 16

    /** A blob shorter than this carries no header. */
    const val HEADER_BYTES: Int = SALT_BYTES + HINT_BYTES

    /** The 16-byte hint [recognitionKey] produces for [mode] and [salt]: label, mode, salt, in order. */
    fun hint(recognitionKey: ByteArray, mode: Int, salt: ByteArray): ByteArray {
        require(salt.size == SALT_BYTES) { "salt has the wrong length" }
        require(mode in 0..0xff) { "mode is one byte" }
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(recognitionKey, "HmacSHA256"))
        mac.update(HINT_LABEL.toByteArray(Charsets.US_ASCII))
        mac.update(mode.toByte())
        mac.update(salt)
        return mac.doFinal().copyOf(HINT_BYTES)
    }

    /** True when [blob]'s hint is the one [recognitionKey] produces for [mode] and its own salt. */
    fun matches(blob: ByteArray, recognitionKey: ByteArray, mode: Int): Boolean {
        if (blob.size < HEADER_BYTES) return false
        return sameHint(hint(recognitionKey, mode, blob.copyOfRange(0, SALT_BYTES)), blob)
    }

    /**
     * The first candidate whose hint matches [blob], or `null` — an unknown blob, dropped. Lazy:
     * [candidates] is walked in order and stops at the first match, so the caller lists the likely
     * ones first (the current epoch before the retained ones), an order it keeps in memory only.
     */
    fun <T> matchFirst(blob: ByteArray, candidates: Sequence<Candidate<T>>): Candidate<T>? {
        if (blob.size < HEADER_BYTES) return null
        val salt = blob.copyOfRange(0, SALT_BYTES)
        for (candidate in candidates) {
            if (sameHint(hint(candidate.recognitionKey, candidate.mode, salt), blob)) return candidate
        }
        return null
    }

    /** Constant time in the hint's length: the order of candidates is per-channel state (T33). */
    private fun sameHint(computed: ByteArray, blob: ByteArray): Boolean {
        var difference = 0
        for (i in 0 until HINT_BYTES) {
            difference = difference or (computed[i].toInt() xor blob[SALT_BYTES + i].toInt())
        }
        return difference == 0
    }

    /** One candidate of [matchFirst]: a recognition key, the mode it recognises, what it stands for. */
    class Candidate<T>(
        /** `R_ep(e)` or `R_join(g)`. */
        val recognitionKey: ByteArray,
        /** 0x11 for `R_ep`, 0x12 or 0x13 for `R_join`. */
        val mode: Int,
        /** What the caller needs when this one matches: the epoch or generation row. */
        val value: T,
    ) {
        /** Never shows the key (T3). */
        override fun toString(): String = "Candidate(mode=$mode, redacted)"
    }
}
