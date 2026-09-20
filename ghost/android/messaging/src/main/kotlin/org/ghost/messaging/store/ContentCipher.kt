package org.ghost.messaging.store

import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * The content key of Phase 9 design §13.8 and C-23: the envelope every `*_env` column of the
 * messaging tables carries.
 *
 * ```
 * env = nonce(12) || ChaCha20-Poly1305(content_key, nonce, AD = the row's key, plaintext)
 * ```
 *
 * **Why it exists.** Three reasons, and none of them is secrecy against a seized **unlocked**
 * device: the "no plaintext content column" rule of the schema (`Schema.kt`), a meaningful T25
 * byte scan (§10.9 point 2 looks for `body_env` bytes and for the plaintext canary in the raw
 * `.db` and `-wal`), and no plaintext left in SQLite's freed pages before `secure_delete` runs.
 *
 * **Why the row's key is the associated data.** A `body_env` moved to another message, a
 * `card_env` moved to another contact or an `l0_env` moved to another item would otherwise open
 * and be believed. The AD makes each envelope belong to the row it was written for, exactly as
 * §22.8.3 does for the state key's envelopes.
 *
 * **Why not the state key.** §2.5 draws the line: ratchet, KEM and seal **opening** secrets are
 * wrapped under `session_state_key` and never reach the JVM heap, while content, cards and names
 * are Kotlin's to render. Content is therefore this key's, and the two are different keys with
 * different wrappers so that one cannot stand in for the other.
 *
 * `ChaCha20-Poly1305` is a JDK 11+ and Android API 28+ transformation; `minSdk` is 29.
 */
internal class ContentCipher(key: ByteArray) {

    private val key: ByteArray

    init {
        require(key.size == KEY_BYTES) { "the content key is not 32 bytes" }
        this.key = key.copyOf()
    }

    /**
     * Seals [plaintext] for the row [associatedData] names.
     *
     * The nonce is drawn by the caller's CSPRNG rather than here, so the whole DM layer has one
     * source of randomness and a world can make it deterministic (§15.1).
     */
    fun seal(nonce: ByteArray, associatedData: ByteArray, plaintext: ByteArray): ByteArray {
        require(nonce.size == NONCE_BYTES) { "the nonce is not 12 bytes" }
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "ChaCha20"), IvParameterSpec(nonce))
        cipher.updateAAD(associatedData)
        val ciphertext = cipher.doFinal(plaintext)
        val out = ByteArray(NONCE_BYTES + ciphertext.size)
        nonce.copyInto(out)
        ciphertext.copyInto(out, NONCE_BYTES)
        return out
    }

    /**
     * Opens an envelope written for the row [associatedData] names, or null when it was not.
     *
     * Null rather than an exception: a stored envelope that does not open is a corrupted or moved
     * row, which every caller answers by dropping what it was about to render — never by
     * crashing a transaction that has already committed a session step.
     */
    fun open(envelope: ByteArray, associatedData: ByteArray): ByteArray? {
        if (envelope.size < NONCE_BYTES + TAG_BYTES) return null
        return try {
            val cipher = Cipher.getInstance(TRANSFORMATION)
            cipher.init(
                Cipher.DECRYPT_MODE,
                SecretKeySpec(key, "ChaCha20"),
                IvParameterSpec(envelope.copyOf(NONCE_BYTES)),
            )
            cipher.updateAAD(associatedData)
            cipher.doFinal(envelope, NONCE_BYTES, envelope.size - NONCE_BYTES)
        } catch (e: javax.crypto.AEADBadTagException) {
            null
        } catch (e: javax.crypto.IllegalBlockSizeException) {
            null
        } catch (e: javax.crypto.BadPaddingException) {
            null
        }
    }

    /** Zeroises the copy this object holds; called when the DM context closes (§2.5). */
    fun clear() {
        key.fill(0)
    }

    /** Never shows the key (T3). */
    override fun toString(): String = "ContentCipher(redacted)"

    companion object {
        /** The content key is 32 random bytes (§13.8). */
        const val KEY_BYTES: Int = 32

        /** ChaCha20-Poly1305 takes a 96-bit nonce. */
        const val NONCE_BYTES: Int = 12

        /** And produces a 128-bit tag. */
        const val TAG_BYTES: Int = 16

        /** What an envelope adds to its plaintext, which the schema's CHECKs are written for. */
        const val OVERHEAD: Int = NONCE_BYTES + TAG_BYTES

        private const val TRANSFORMATION = "ChaCha20-Poly1305"
    }
}
