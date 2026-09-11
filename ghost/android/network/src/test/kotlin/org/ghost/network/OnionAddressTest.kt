package org.ghost.network

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * Kotlin half of invariant T6: no non-onion or mistyped destination can be constructed. Uses the
 * vector file shared with the Rust parser, so the two validators cannot drift apart.
 */
class OnionAddressTest {
    private data class Vector(val valid: Boolean, val input: String, val why: String)

    private val vectors: List<Vector> by lazy {
        // Unit tests run with the module directory as working directory.
        val file = File("../../protocol/test-vectors/onion_addresses.txt")
        assertTrue("shared vector file missing: ${file.absolutePath}", file.isFile)
        file.readLines(Charsets.UTF_8)
            .filter { it.isNotBlank() && !it.startsWith("#") }
            .map { line ->
                val parts = line.split('|', limit = 3)
                Vector(parts[0] == "valid", unescape(parts[1]), parts.getOrElse(2) { "" })
            }
    }

    /** Inputs may carry \uXXXX escapes (control and whitespace characters). */
    private fun unescape(s: String): String =
        Regex("""\\u([0-9A-Fa-f]{4})""").replace(s) { it.groupValues[1].toInt(16).toChar().toString() }

    @Test
    fun sharedVectors() {
        assertTrue(vectors.count { it.valid } >= 3 && vectors.count { !it.valid } >= 15)
        for (v in vectors) {
            if (v.valid) {
                val a = OnionAddress.parse(v.input)
                assertTrue(a.host.endsWith(".onion"))
                assertEquals(a.host, a.host.lowercase())
            } else {
                assertThrows("${v.input} must be rejected (${v.why})", IllegalArgumentException::class.java) {
                    OnionAddress.parse(v.input)
                }
                assertNull(OnionAddress.parseOrNull(v.input))
            }
        }
    }

    @Test
    fun normalizesCaseAndRoundTrips() {
        val a = OnionAddress.parse("DUCKDUCKGOGG42XJOC72X3SJASOWOARFBGCMVFIMAFTT6TWAGSWZCZAD.onion:443")
        assertEquals("duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion:443", a.toString())
        assertEquals(a, OnionAddress.parse(a.toString()))
    }
}
