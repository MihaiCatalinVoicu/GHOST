package org.ghost.crypto.bridge

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * `DmResultCodesTest` (Phase 9 design §2.6): the closed DM result-code list is one list, and this
 * class and the Rust `result.rs` agree on it.
 *
 * The Rust file is the numbering (§2.6 names the codes but fixes no bytes), so the test reads it
 * and compares, rather than restating the bytes a second time: a code added, removed or renumbered
 * on either side fails here.
 */
class DmResultCodesTest {

    private fun rustSource(name: String): File {
        // The module is ghost/android/crypto-bridge; the crate is ghost/client-core/dm.
        val file = File("../../client-core/dm/src/$name").canonicalFile
        assertTrue("$file must exist", file.isFile)
        return file
    }

    private fun rustResultSource(): File = rustSource("result.rs")

    @Test
    fun theKotlinAndRustCodeListsAgree() {
        val source = rustResultSource().readText()
        // `    Ok = 0x00,` preceded by its doc comment; the enum body is the only place a name is
        // followed by ` = 0x`.
        val rust = Regex("""^\s{4}(\w+) = 0x([0-9a-f]{2}),$""", RegexOption.MULTILINE)
            .findAll(source)
            .map { it.groupValues[1] to it.groupValues[2].toInt(16) }
            .toList()
        assertEquals(
            "the Rust enumeration lost or gained a code",
            DmCode.entries.size,
            rust.size,
        )
        // `name()` in Rust spells the code as §2.6 does, which is exactly the Kotlin enum name.
        val names = Regex("""DmCode::(\w+) => "([A-Z_]+)",""")
            .findAll(source)
            .associate { it.groupValues[1] to it.groupValues[2] }
        for ((variant, wire) in rust) {
            val spelled = names[variant] ?: error("Rust has no name() arm for $variant")
            val kotlin = DmCode.entries.firstOrNull { it.name == spelled }
                ?: error("Kotlin has no DmCode.$spelled")
            assertEquals("wire byte of $spelled", kotlin.wire, wire)
        }
    }

    @Test
    fun everyWireByteRoundTripsAndUndefinedBytesHaveNoCode() {
        val defined = DmCode.entries.map { it.wire }.toSet()
        assertEquals(DmCode.entries.size, defined.size)
        for (code in DmCode.entries) {
            assertSame(code, DmCode.fromWire(code.wire))
        }
        for (byte in 0..0xff) {
            if (byte in defined) assertNotNull(DmCode.fromWire(byte)) else assertNull(
                "0x%02x must be undefined".format(byte),
                DmCode.fromWire(byte),
            )
        }
    }

    /**
     * The field tags are one list too (Phase 9 design §2.6: the reply is `code(1) || TLV fields`).
     * A tag renumbered to an unused value is loud — [DmField.fromTag] returns null and the reply
     * decodes as `STATE_CORRUPT` — but two tags of equal-length payloads **swapped** would be
     * silent on both sides, and `ownCard` reads four 32-byte fields in a row. So this reads the
     * Rust enumeration the same way [theKotlinAndRustCodeListsAgree] reads `DmCode`.
     */
    @Test
    fun theKotlinAndRustFieldTagsAgree() {
        val source = rustSource("jni.rs").readText()
        val body = source.substringAfter("pub enum Field {").substringBefore("\n}")
        val rust = Regex("""^\s{4}(\w+) = 0x([0-9a-f]{2}),$""", RegexOption.MULTILINE)
            .findAll(body)
            .map { it.groupValues[1] to it.groupValues[2].toInt(16) }
            .toList()
        assertEquals(
            "the Rust enumeration lost or gained a field tag",
            DmField.entries.size,
            rust.size,
        )
        for ((variant, tag) in rust) {
            // `SessionId` is `SESSION_ID`, `L0` stays `L0`.
            val spelled = variant.replace(Regex("(?<=.)([A-Z])"), "_$1").uppercase()
            val field = DmField.entries.firstOrNull { it.name == spelled }
                ?: error("Kotlin has no DmField.$spelled for Rust Field::$variant")
            assertEquals("wire tag of $spelled", field.tag, tag)
        }
    }

    @Test
    fun everyFieldTagIsDistinctAndRoundTrips() {
        val tags = DmField.entries.map { it.tag }
        assertEquals(tags.size, tags.toSet().size)
        for (field in DmField.entries) {
            assertSame(field, DmField.fromTag(field.tag))
        }
        assertNull(DmField.fromTag(0x7f))
    }

    @Test
    fun aReplyDecodesItsCodeAndFields() {
        val reply = byteArrayOf(
            0x00, // OK
            0x07, 0, 0, 0, 1, 1, // SLOT_USED = previous
            0x0a, 0, 0, 0, 4, 0, 0, 0, 7, // PRUNED = 7
        )
        val result = DmResult.decode(reply)
        assertTrue(result.isOk)
        assertEquals(1, result.byte(DmField.SLOT_USED))
        assertEquals(7L, result.u32(DmField.PRUNED))
        assertNull(result.bytesOrNull(DmField.STATE))
    }

    @Test
    fun aCodeOnlyReplyDecodes() {
        val result = DmResult.decode(byteArrayOf(DmCode.DUPLICATE_OR_LOST.wire.toByte()))
        assertEquals(DmCode.DUPLICATE_OR_LOST, result.code)
    }

    @Test
    fun anEmptyOrNullReplyIsInternal() {
        assertEquals(DmCode.INTERNAL, DmResult.decode(null).code)
        assertEquals(DmCode.INTERNAL, DmResult.decode(ByteArray(0)).code)
    }

    @Test
    fun aMalformedReplyIsStateCorruptRatherThanAnException() {
        // Unknown code byte.
        assertEquals(DmCode.STATE_CORRUPT, DmResult.decode(byteArrayOf(0x42)).code)
        // Truncated header.
        assertEquals(DmCode.STATE_CORRUPT, DmResult.decode(byteArrayOf(0x00, 0x07, 0, 0)).code)
        // Unknown tag.
        assertEquals(
            DmCode.STATE_CORRUPT,
            DmResult.decode(byteArrayOf(0x00, 0x7f, 0, 0, 0, 0)).code,
        )
        // Length overruns the array.
        assertEquals(
            DmCode.STATE_CORRUPT,
            DmResult.decode(byteArrayOf(0x00, 0x07, 0, 0, 0, 9, 1)).code,
        )
        // Repeated tag.
        assertEquals(
            DmCode.STATE_CORRUPT,
            DmResult.decode(byteArrayOf(0x00, 0x07, 0, 0, 0, 1, 0, 0x07, 0, 0, 0, 1, 1)).code,
        )
    }

    @Test
    fun everyPrefixOfAValidReplyIsRefusedOrDecodesWithoutThrowing() {
        val reply = byteArrayOf(
            0x00,
            0x02, 0, 0, 0, 3, 1, 2, 3,
            0x03, 0, 0, 0, 2, 4, 5,
        )
        for (length in reply.indices) {
            val result = DmResult.decode(reply.copyOf(length))
            assertTrue(
                "prefix of length $length",
                result.code == DmCode.STATE_CORRUPT || result.code == DmCode.INTERNAL ||
                    result.isOk,
            )
        }
        val whole = DmResult.decode(reply)
        assertTrue(whole.isOk)
        assertTrue(byteArrayOf(1, 2, 3).contentEquals(whole.bytes(DmField.STATE)))
        assertTrue(byteArrayOf(4, 5).contentEquals(whole.bytes(DmField.SESSION_ID)))
    }
}
