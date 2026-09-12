package org.ghost.identity

/**
 * z-base-32 (Zooko's human-oriented base-32) used for the public identity string and invite
 * payloads (FR-1.3). No padding; ASCII case-insensitive on input; strict alphabet on decode.
 */
object ZBase32 {
    private const val ALPHABET = "ybndrfg8ejkmcpqxot1uwisza345h769"
    private val decodeMap: IntArray = IntArray(128) { -1 }.also { m ->
        ALPHABET.forEachIndexed { i, c -> m[c.code] = i }
    }

    fun encode(data: ByteArray): String {
        val sb = StringBuilder((data.size * 8 + 4) / 5)
        var buffer = 0
        var bitsInBuffer = 0
        for (b in data) {
            buffer = (buffer shl 8) or (b.toInt() and 0xff)
            bitsInBuffer += 8
            while (bitsInBuffer >= 5) {
                bitsInBuffer -= 5
                sb.append(ALPHABET[(buffer shr bitsInBuffer) and 0x1f])
            }
        }
        if (bitsInBuffer > 0) sb.append(ALPHABET[(buffer shl (5 - bitsInBuffer)) and 0x1f])
        return sb.toString()
    }

    /** Decodes to exactly `expectedLength` bytes; throws on foreign characters or wrong length. */
    fun decode(text: String, expectedLength: Int): ByteArray {
        val expectedChars = (expectedLength * 8 + 4) / 5
        if (text.length != expectedChars) throw IllegalArgumentException("z-base-32 length mismatch")
        val out = ByteArray(expectedLength)
        var buffer = 0
        var bitsInBuffer = 0
        var index = 0
        for (ch in text) {
            // Only ASCII letters fold. Unicode lowercasing would map U+212A KELVIN SIGN to 'k' and
            // accept a second, non-ASCII spelling of the same payload.
            val c = if (ch in 'A'..'Z') ch + ('a' - 'A') else ch
            val v = if (c.code < 128) decodeMap[c.code] else -1
            if (v < 0) throw IllegalArgumentException("invalid z-base-32 character")
            buffer = (buffer shl 5) or v
            bitsInBuffer += 5
            if (bitsInBuffer >= 8) {
                bitsInBuffer -= 8
                if (index < expectedLength) out[index++] = ((buffer shr bitsInBuffer) and 0xff).toByte()
            }
        }
        // Trailing bits beyond the byte boundary must be zero, otherwise two different strings
        // would decode to the same bytes (non-canonical encodings are rejected).
        if (bitsInBuffer > 0 && (buffer and ((1 shl bitsInBuffer) - 1)) != 0) {
            throw IllegalArgumentException("non-canonical z-base-32 encoding")
        }
        return out
    }
}
