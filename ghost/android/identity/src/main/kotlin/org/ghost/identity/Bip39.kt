package org.ghost.identity

import java.security.MessageDigest
import java.text.Normalizer

/**
 * BIP-39 mnemonic encoding of the 256-bit root entropy (FR-1.4: 24 words). GHOST uses the
 * mnemonic only as a human-readable backup of the entropy; keys are derived from the entropy with
 * HKDF (spec §7.1), not from the BIP-39 PBKDF2 seed. Wordlist: official English list, SHA-256
 * 2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda.
 */
object Bip39 {
    const val ENTROPY_BYTES = 32
    const val WORD_COUNT = 24

    val wordlist: List<String> by lazy {
        val words = Bip39Wordlist.WORDS
        check(words.size == 2048) { "BIP-39 wordlist must have 2048 words, got ${words.size}" }
        // Integrity self-check against the SHA-256 of the official english.txt (newline-terminated).
        val canonical = (words.joinToString("\n") + "\n").toByteArray(Charsets.UTF_8)
        val digest = sha256(canonical).joinToString("") { "%02x".format(it) }
        check(digest == Bip39Wordlist.SHA256_OF_FILE) { "BIP-39 wordlist integrity check failed" }
        words
    }

    private val wordIndex: Map<String, Int> by lazy { wordlist.withIndex().associate { it.value to it.index } }

    /**
     * Phase 13 §3.3 (F-U4): the mnemonic as 24 word indices, computed over a bit array the
     * caller zeroes — the encoder never builds a `String` of bits (`Bip39.kt`'s old builder
     * would have held the entire root in one immutable string). [indicesOfMnemonic] maps words
     * back for the round trip; the UI renders indices through [wordlist] and never joins them.
     */
    fun encodeIndices(entropy: ByteArray): IntArray {
        require(entropy.size in 16..32 && entropy.size % 4 == 0) { "entropy must be 16..32 bytes, multiple of 4" }
        val checksumBits = entropy.size * 8 / 32
        val totalBits = entropy.size * 8 + checksumBits
        val bits = IntArray(totalBits)
        try {
            var at = 0
            for (b in entropy) {
                for (shift in 7 downTo 0) bits[at++] = (b.toInt() ushr shift) and 1
            }
            val hash = sha256(entropy)
            for (shift in 7 downTo 8 - checksumBits) bits[at++] = (hash[0].toInt() ushr shift) and 1
            check(at == totalBits)
            val out = IntArray(totalBits / 11)
            for (w in out.indices) {
                var v = 0
                for (j in 0 until 11) v = (v shl 1) or bits[w * 11 + j]
                out[w] = v
            }
            return out
        } finally {
            bits.fill(0)
        }
    }

    /** The inverse of [encodeIndices] with the same validations as [decode]. */
    fun decodeIndices(indices: IntArray): ByteArray {
        require(indices.size in setOf(12, 15, 18, 21, 24)) { "invalid mnemonic length: ${indices.size} words" }
        require(indices.all { it in 0..2047 }) { "word index out of range" }
        val checksumBits = indices.size * 11 / 33
        val entropyBits = indices.size * 11 - checksumBits
        val bits = IntArray(indices.size * 11)
        try {
            var at = 0
            for (idx in indices) {
                for (shift in 10 downTo 0) bits[at++] = (idx ushr shift) and 1
            }
            val entropy = ByteArray(entropyBits / 8)
            for (i in entropy.indices) {
                var v = 0
                for (j in 0 until 8) v = (v shl 1) or bits[i * 8 + j]
                entropy[i] = v.toByte()
            }
            for (shift in 7 downTo 8 - checksumBits) {
                if (bits[entropyBits + (7 - shift)] != (sha256(entropy)[0].toInt() ushr shift) and 1) {
                    throw IllegalArgumentException("mnemonic checksum mismatch")
                }
            }
            return entropy
        } finally {
            bits.fill(0)
        }
    }

    /** Maps a rendered mnemonic to its indices (the backup check's reverse direction). */
    fun indicesOfMnemonic(words: List<String>): IntArray {
        val normalized = words.map { Normalizer.normalize(it.trim().lowercase(), Normalizer.Form.NFKD) }
        return IntArray(normalized.size) { i ->
            wordIndex[normalized[i]] ?: throw IllegalArgumentException("unknown mnemonic word")
        }
    }

    /** Encodes entropy (16..32 bytes, multiple of 4) as a mnemonic. GHOST always uses 32 bytes. */
    fun encode(entropy: ByteArray): List<String> {
        val indices = encodeIndices(entropy)
        try {
            return indices.map { wordlist[it] }
        } finally {
            indices.fill(0)
        }
    }

    /**
     * Decodes and validates a mnemonic. Rejects wrong word count, unknown words and checksum
     * mismatch (FR-1.4 acceptance: parser rejects checksum, version and length errors).
     */
    fun decode(words: List<String>): ByteArray = decodeIndices(indicesOfMnemonic(words))

    fun decode(phrase: String): ByteArray = decode(phrase.trim().split(Regex("\\s+")))

    private fun sha256(data: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(data)
}
