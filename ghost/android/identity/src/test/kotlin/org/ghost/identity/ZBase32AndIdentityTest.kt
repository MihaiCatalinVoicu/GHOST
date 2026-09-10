package org.ghost.identity

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import java.security.SecureRandom

class ZBase32AndIdentityTest {
    @Test
    fun zbase32RoundTripAllLengths() {
        val rnd = SecureRandom()
        for (len in 0..70) {
            val data = ByteArray(len).also(rnd::nextBytes)
            val enc = ZBase32.encode(data)
            assertTrue(enc.all { it in "ybndrfg8ejkmcpqxot1uwisza345h769" })
            assertArrayEquals(data, ZBase32.decode(enc, len))
        }
    }

    @Test
    fun zbase32RejectsForeignCharsAndLength() {
        assertThrows(IllegalArgumentException::class.java) { ZBase32.decode("yb0d", 2) } // '0' not in alphabet
        assertThrows(IllegalArgumentException::class.java) { ZBase32.decode("ybnd", 3) }
    }

    @Test
    fun identityRoundTripAndFormat() {
        val root = RootEntropy.generate()
        val id = root.publicIdentity()
        val text = id.encode()
        assertTrue(text.startsWith("ghost1"))
        assertEquals(GhostIdentity.ENCODED_LENGTH, text.length)
        assertEquals(id, GhostIdentity.parse(text))
        assertEquals(id, GhostIdentity.parse(text.uppercase().replaceFirst("GHOST1", "ghost1")))
    }

    @Test
    fun identityParserRejectsTamperVersionAndLength() {
        val text = RootEntropy.generate().publicIdentity().encode()
        // Every single-character change must be rejected (checksum or alphabet).
        val alphabet = "ybndrfg8ejkmcpqxot1uwisza345h769"
        var rejected = 0
        for (i in 6 until text.length) {
            val replacement = alphabet.first { it != text[i] }
            val tampered = text.substring(0, i) + replacement + text.substring(i + 1)
            try { GhostIdentity.parse(tampered) } catch (e: IllegalArgumentException) { rejected++ }
        }
        assertEquals(text.length - 6, rejected)
        assertThrows(IllegalArgumentException::class.java) { GhostIdentity.parse(text.dropLast(1)) }
        assertThrows(IllegalArgumentException::class.java) { GhostIdentity.parse("ghost2" + text.substring(6)) }
        assertThrows(IllegalArgumentException::class.java) { GhostIdentity.parse(text + "y") }
    }
}
