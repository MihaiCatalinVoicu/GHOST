package org.ghost.identity

import org.junit.Assert.assertEquals
import org.junit.Test

/** RFC 5869 Appendix A test vectors (SHA-256 cases 1–3). */
class HkdfTest {
    private fun hex(s: String): ByteArray = s.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
    private fun ByteArray.hex(): String = joinToString("") { "%02x".format(it) }

    @Test
    fun rfc5869Case1() {
        val okm = Hkdf.derive(
            ikm = hex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"),
            salt = hex("000102030405060708090a0b0c"),
            info = hex("f0f1f2f3f4f5f6f7f8f9"),
            length = 42,
        )
        assertEquals(
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865",
            okm.hex(),
        )
    }

    @Test
    fun rfc5869Case2LongInputs() {
        val ikm = hex((0x00..0x4f).joinToString("") { "%02x".format(it) })
        val salt = hex((0x60..0xaf).joinToString("") { "%02x".format(it) })
        val info = hex((0xb0..0xff).joinToString("") { "%02x".format(it) })
        val okm = Hkdf.derive(ikm, salt, info, 82)
        assertEquals(
            "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c" +
                "59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71" +
                "cc30c58179ec3e87c14c01d5c1f3434f1d87",
            okm.hex(),
        )
    }

    @Test
    fun rfc5869Case3EmptySaltAndInfo() {
        val okm = Hkdf.derive(hex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"), null, ByteArray(0), 42)
        assertEquals(
            "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8",
            okm.hex(),
        )
    }
}
