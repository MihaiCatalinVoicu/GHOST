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

    /** Encodes entropy (16..32 bytes, multiple of 4) as a mnemonic. GHOST always uses 32 bytes. */
    fun encode(entropy: ByteArray): List<String> {
        require(entropy.size in 16..32 && entropy.size % 4 == 0) { "entropy must be 16..32 bytes, multiple of 4" }
        val checksumBits = entropy.size * 8 / 32
        val hash = sha256(entropy)
        val bits = StringBuilder()
        for (b in entropy) bits.append(toBits(b))
        bits.append(toBits(hash[0]).substring(0, checksumBits))
        return bits.chunked(11).map { wordlist[it.toInt(2)] }
    }

    /**
     * Decodes and validates a mnemonic. Rejects wrong word count, unknown words and checksum
     * mismatch (FR-1.4 acceptance: parser rejects checksum, version and length errors).
     */
    fun decode(words: List<String>): ByteArray {
        val normalized = words.map { Normalizer.normalize(it.trim().lowercase(), Normalizer.Form.NFKD) }
        require(normalized.size in setOf(12, 15, 18, 21, 24)) { "invalid mnemonic length: ${normalized.size} words" }
        val bits = StringBuilder()
        for (w in normalized) {
            val idx = wordIndex[w] ?: throw IllegalArgumentException("unknown mnemonic word")
            bits.append(idx.toString(2).padStart(11, '0'))
        }
        val checksumBits = normalized.size * 11 / 33
        val entropyBits = bits.length - checksumBits
        val entropy = ByteArray(entropyBits / 8) { i -> bits.substring(i * 8, i * 8 + 8).toInt(2).toByte() }
        val expected = toBits(sha256(entropy)[0]).substring(0, checksumBits)
        if (bits.substring(entropyBits) != expected) throw IllegalArgumentException("mnemonic checksum mismatch")
        return entropy
    }

    fun decode(phrase: String): ByteArray = decode(phrase.trim().split(Regex("\\s+")))

    private fun toBits(b: Byte): String = (b.toInt() and 0xff).toString(2).padStart(8, '0')

    private fun sha256(data: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(data)
}
