package org.ghost.crypto.bridge

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * `DmResultCodesTest` (Phase 9 design §2.6): the closed DM result-code list is one list, the TLV
 * field tags are one list, and this class and the Rust crate agree on both.
 *
 * The Rust files are the numbering (§2.6 names the codes but fixes no bytes), so the tests read
 * `result.rs` and `jni.rs` and compare, rather than restating the bytes a second time: a code or a
 * tag added, removed or renumbered on either side fails here.
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

    /**
     * Per **function**, not only per list (review round 2, S4B2-01/R2-01): `DmSessions`' `when`
     * arms are exactly the code set the native function declares in `FUNCTION_CODES`, plus `OK`
     * and the `CRYPTO_UNAVAILABLE` Kotlin synthesises when the library is missing.
     *
     * A code with no arm falls into `unexpected` and throws `IllegalStateException`, which §2.6
     * reserves for `INTERNAL` — that is how a first flight past Olm's message gap turned an
     * ordinary inbound blob into three process deaths. An arm for a code the function cannot
     * return is the opposite drift: a surface that outlived its reason. Both fail here.
     */
    @Test
    fun everyFacadeFunctionHandlesExactlyTheCodesItsNativeFunctionCanReturn() {
        val rust = rustSource("jni.rs").readText()
        val table = rust.substringAfter("pub const FUNCTION_CODES").substringBefore("\n];")
        val spelling = Regex("""DmCode::(\w+) => "([A-Z_]+)",""")
            .findAll(rustResultSource().readText())
            .associate { it.groupValues[1] to it.groupValues[2] }
        val declared = Regex(
            """\(\s*"(\w+)"\s*,\s*&\[([^\]]*)]\s*,?\s*\)""",
            RegexOption.DOT_MATCHES_ALL,
        )
            .findAll(table)
            .associate { match ->
                match.groupValues[1] to Regex("""DmCode::(\w+)""")
                    .findAll(match.groupValues[2])
                    .map { code ->
                        val variant = code.groupValues[1]
                        spelling[variant] ?: error("Rust has no name() arm for $variant")
                    }
                    .toSet()
            }
        assertTrue("FUNCTION_CODES must be readable", declared.size >= 11)

        // The functions whose facade wrapper returns `null` (or ignores the reply) on **any**
        // non-OK code, so there are no arms to compare: a context that did not open, a card index
        // out of range, a generation that could not be sealed, a safety number that could not be
        // computed. They are named here so a new exported function cannot quietly join them.
        val nullOnFailure =
            setOf("ctxOpen", "ctxClose", "ownCard", "ownReadSecret", "bundleCreate", "safetyNumber")

        // **Every** facade source of the package, not `DmSessions.kt` alone (slice S7): the card,
        // bundle, seal, pairing and content facades each answer functions of the same closed
        // surface, and a facade added in a new file must be covered the day it exists rather than
        // the day somebody remembers to name it here.
        val facadeDir = File("src/main/kotlin/org/ghost/crypto/bridge").canonicalFile
        assertTrue("$facadeDir must exist", facadeDir.isDirectory)
        val sources = facadeDir.listFiles { file -> file.extension == "kt" }
            ?.sortedBy { it.name }
            .orEmpty()
        assertTrue("the facade package must hold sources", sources.size >= 6)
        val arms = LinkedHashMap<String, Set<String>>()
        for (source in sources) {
            Regex(
                """when \(result\.code\) \{(.*?)else -> unexpected\(result\.code, "(\w+)"\)""",
                RegexOption.DOT_MATCHES_ALL,
            )
                .findAll(source.readText())
                // Arm labels only (`DmCode.X ->`), and DM blocks only: the media facade
                // (MediaCrypto.kt, Phase 11 slice S2) answers the media surface's `when` blocks
                // in the same package, and MediaResultCodesTest owns those.
                .filter { it.groupValues[1].contains("DmCode.") }
                .forEach { match ->
                    val function = match.groupValues[2]
                    // Arm labels only, one arm or a comma-chain per line (the facade style the
                    // project's ktlint enforces) — a bare `DmCode\.X` reference is not an arm.
                    val codes = match.groupValues[1].lineSequence()
                        .filter { line -> "->" in line }
                        .flatMap { line -> Regex("""DmCode\.([A-Z_]+)""").findAll(line) }
                        .map { it.groupValues[1] }
                        .toSet()
                    val existing = arms[function]
                    if (existing != null) {
                        // Two blocks may answer one native function — `openOuter` has an intro
                        // arm and a symmetric one — but they must answer the **same** codes, or
                        // one of the two would leave a reachable code to `unexpected`.
                        assertEquals(
                            "$function is answered twice with different arms (${source.name})",
                            existing,
                            codes,
                        )
                    }
                    arms[function] = codes
                }
        }

        for ((function, codes) in declared) {
            if (function in nullOnFailure) {
                assertNull("$function must have no when block", arms[function])
                continue
            }
            val handled = arms[function] ?: error("DmSessions has no when block for $function")
            assertEquals(
                "$function: the facade arms and the native code set disagree",
                codes + "OK" + "CRYPTO_UNAVAILABLE",
                handled,
            )
        }
        for (function in arms.keys) {
            assertTrue(
                "DmSessions answers $function, which FUNCTION_CODES does not declare",
                function in declared,
            )
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

    /** Phase 9 review A-1: the native reply is erased once its fields are copied out. */
    @Test
    fun theReplyIsErasedOnceDecoded() {
        val reply = byteArrayOf(
            0x00, // OK
            0x02, 0, 0, 0, 3, 7, 8, 9, // STATE = 07 08 09
        )
        val result = DmResult.decode(reply)
        assertTrue(byteArrayOf(7, 8, 9).contentEquals(result.bytes(DmField.STATE)))
        assertTrue("the reply buffer still holds its fields", reply.all { it == 0.toByte() })
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
