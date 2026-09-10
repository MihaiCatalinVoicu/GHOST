package org.ghost.identity

import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * HKDF-SHA-256 (RFC 5869) on top of the platform HMAC. Every long-lived GHOST key branch is
 * `Hkdf.derive(ikm = rootEntropy, salt = null, info = label, length)` (spec v2.0 §7.1 step 3).
 * Test vectors: RFC 5869 Appendix A, cases 1–3.
 */
object Hkdf {
    private const val HASH_LEN = 32
    private const val HMAC = "HmacSHA256"

    fun extract(salt: ByteArray?, ikm: ByteArray): ByteArray {
        val effectiveSalt = if (salt == null || salt.isEmpty()) ByteArray(HASH_LEN) else salt
        return hmac(effectiveSalt, ikm)
    }

    fun expand(prk: ByteArray, info: ByteArray, length: Int): ByteArray {
        require(length in 1..(255 * HASH_LEN)) { "HKDF output length out of range: $length" }
        val out = ByteArray(length)
        var previous = ByteArray(0)
        var written = 0
        var counter = 1
        while (written < length) {
            val block = hmac(prk, previous + info + byteArrayOf(counter.toByte()))
            val take = minOf(block.size, length - written)
            block.copyInto(out, written, 0, take)
            written += take
            previous = block
            counter++
        }
        return out
    }

    fun derive(ikm: ByteArray, salt: ByteArray?, info: ByteArray, length: Int): ByteArray =
        expand(extract(salt, ikm), info, length)

    private fun hmac(key: ByteArray, data: ByteArray): ByteArray {
        val mac = Mac.getInstance(HMAC)
        mac.init(SecretKeySpec(key, HMAC))
        return mac.doFinal(data)
    }
}
