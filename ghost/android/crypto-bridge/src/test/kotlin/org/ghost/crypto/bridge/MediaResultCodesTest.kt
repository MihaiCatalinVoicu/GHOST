package org.ghost.crypto.bridge

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * `MediaResultCodesTest` (Phase 11 design §13.2, G-M5): the closed media result-code list is one
 * list, the TLV field tags are one list, and this class and `ghost-client-dm`'s `jni_media.rs`
 * agree on both — the same drill `DmResultCodesTest` runs for the DM surface.
 *
 * The Rust files are the numbering (§13.2 names the codes but fixes no bytes), so the tests read
 * `jni_media.rs` and compare, rather than restating the bytes a second time: a code or a tag
 * added, removed or renumbered on either side fails here. The four `testVectors`-only field tags
 * (`0x14..0x17`) are host-only by design and are pinned here by name, exactly as the gate's
 * library half pins their symbols.
 */
class MediaResultCodesTest {

    private fun rustSource(): File {
        // The module is ghost/android/crypto-bridge; the surface lives in ghost/client-core/dm.
        val file = File("../../client-core/dm/src/jni_media.rs").canonicalFile
        assertTrue("$file must exist", file.isFile)
        return file
    }

    @Test
    fun theKotlinAndRustCodeListsAgree() {
        val source = rustSource().readText()
        val body = source.substringAfter("pub enum MediaCode {").substringBefore("\n}")
        // `    NonCanonical = 0x02,` — the enum body is the only place a name is followed by
        // ` = 0x` at four spaces (`from_u8`'s arms read `0x02 =>`, not `Name = 0x`).
        val rust = Regex("""^\s{4}(\w+) = 0x([0-9a-f]{2}),$""", RegexOption.MULTILINE)
            .findAll(body)
            .map { it.groupValues[1] to it.groupValues[2].toInt(16) }
            .toList()
        assertEquals(
            "the Rust enumeration lost or gained a code (§13.2's list is closed at 14)",
            MediaCode.entries.size,
            rust.size,
        )
        // `name()` in Rust spells the code as §13.2 does, which is exactly the Kotlin enum name.
        val names = Regex("""MediaCode::(\w+) => "([A-Z_]+)",""")
            .findAll(source)
            .associate { it.groupValues[1] to it.groupValues[2] }
        for ((variant, wire) in rust) {
            val spelled = names[variant] ?: error("Rust has no name() arm for $variant")
            val kotlin = MediaCode.entries.firstOrNull { it.name == spelled }
                ?: error("Kotlin has no MediaCode.$spelled")
            assertEquals("wire byte of $spelled", kotlin.wire, wire)
        }
    }

    @Test
    fun theKotlinAndRustFieldTagsAgree() {
        val source = rustSource().readText()
        val body = source.substringAfter("#[repr(u8)]\npub enum MediaField {").substringBefore("\n}")
        val rust = Regex("""^\s{4}(\w+) = 0x([0-9a-f]{2}),$""", RegexOption.MULTILINE)
            .findAll(body)
            .map { it.groupValues[1] to it.groupValues[2].toInt(16) }
            .toList()
        // The four `testVectors`-only tags: host-only, never in the shipped Kotlin enumeration
        // (G-M5's library half is what keeps their symbols out of shipped libraries).
        val hostOnly = setOf("PayloadKey", "ManifestKey", "Commitment", "OpId")
        val shipped = rust.filter { it.first !in hostOnly }
        assertEquals(
            "the Rust field list lost or gained a shipped field",
            MediaField.entries.size,
            shipped.size,
        )
        assertEquals("host-only fields", hostOnly, rust.map { it.first }.toSet() - shipped.map { it.first }.toSet())
        for ((variant, tag) in shipped) {
            val spelled = variant.replace(Regex("(?<=.)([A-Z])"), "_$1").uppercase()
            val field = MediaField.entries.firstOrNull { it.name == spelled }
                ?: error("Kotlin has no MediaField.$spelled for Rust MediaField::$variant")
            assertEquals("wire tag of $spelled", field.tag, tag)
        }
    }

    /**
     * Per **function**, not only per list: [MediaCrypto]'s `when` arms are exactly the code set
     * `MEDIA_FUNCTION_CODES` declares for the native function, plus `OK`. A code with no arm
     * falls into `unexpected` and throws — the poison-guard path that must stay unreachable for
     * codes a peer can provoke. An arm for a code the function cannot return is the opposite
     * drift. Both fail here.
     *
     * The two host-only entries (`testVectors`, `testSealBeginWithKey`) are answered by the test
     * wrappers of `MediaHostVectors`, not by the shipped facade; they are named so a third
     * host-only function cannot join them unnoticed.
     */
    @Test
    fun everyFacadeFunctionHandlesExactlyTheCodesItsNativeFunctionCanReturn() {
        val source = rustSource().readText()
        val table = source.substringAfter("pub const MEDIA_FUNCTION_CODES").substringBefore("\n];")
        val spelling = Regex("""MediaCode::(\w+) => "([A-Z_]+)",""")
            .findAll(source)
            .associate { it.groupValues[1] to it.groupValues[2] }
        val declared = Regex(
            """\(\s*"(\w+)"\s*,\s*&\[([^\]]*)]\s*,?\s*\)""",
            RegexOption.DOT_MATCHES_ALL,
        )
            .findAll(table)
            .associate { match ->
                match.groupValues[1] to Regex("""MediaCode::(\w+)""")
                    .findAll(match.groupValues[2])
                    .map { code ->
                        val variant = code.groupValues[1]
                        spelling[variant] ?: error("Rust has no name() arm for $variant")
                    }
                    .toSet()
            }
        assertTrue("MEDIA_FUNCTION_CODES must be readable", declared.size >= 10)

        // The two host-only entries are answered by the test source set's wrappers.
        val answeredInTestSource = setOf("testVectors", "testSealBeginWithKey")
        assertEquals(answeredInTestSource, declared.keys.filter { it.startsWith("test") }.toSet())

        // Every `when (result.code)` block of the facade package that answers **media** codes
        // (the block names MediaCode arms) — a facade added in a new file is covered the day it
        // exists, and the DM blocks (`DmCode` arms) are not mistaken for media ones.
        val facadeDir = File("src/main/kotlin/org/ghost/crypto/bridge").canonicalFile
        assertTrue("$facadeDir must exist", facadeDir.isDirectory)
        val sources = facadeDir.listFiles { file -> file.extension == "kt" }
            ?.sortedBy { it.name }
            .orEmpty()
        val arms = LinkedHashMap<String, Set<String>>()
        for (file in sources) {
            Regex(
                """when \(result\.code\) \{(.*?)else -> unexpected\(result\.code, "(\w+)"\)""",
                RegexOption.DOT_MATCHES_ALL,
            )
                .findAll(file.readText())
                .filter { it.groupValues[1].contains("MediaCode.") }
                .forEach { match ->
                    val function = match.groupValues[2]
                    // Arm labels only, one arm or a comma-chain per line (the facade style the
                    // project's ktlint enforces): a reference like sniff's
                    // `?: unexpected(MediaCode.INTERNAL, "sniff")` is not an arm and must not
                    // be counted as one.
                    val codes = match.groupValues[1].lineSequence()
                        .filter { line -> "->" in line }
                        .flatMap { line -> Regex("""MediaCode\.([A-Z_]+)""").findAll(line) }
                        .map { it.groupValues[1] }
                        .toSet()
                    val existing = arms[function]
                    if (existing != null) {
                        assertEquals(
                            "$function is answered twice with different arms (${file.name})",
                            existing,
                            codes,
                        )
                    }
                    arms[function] = codes
                }
        }

        for ((function, codes) in declared) {
            if (function in answeredInTestSource) continue
            val handled = arms[function] ?: error("the facade has no when block for $function")
            assertEquals(
                "$function: the facade arms and the native code set disagree",
                codes + "OK" + "CRYPTO_UNAVAILABLE",
                handled,
            )
        }
        for (function in arms.keys) {
            assertTrue(
                "the facade answers $function, which MEDIA_FUNCTION_CODES does not declare",
                function in declared,
            )
        }
    }

    @Test
    fun everyWireByteRoundTripsAndUndefinedBytesHaveNoCode() {
        val defined = MediaCode.entries.map { it.wire }.toSet()
        assertEquals(MediaCode.entries.size, defined.size)
        for (code in MediaCode.entries) {
            assertSame(code, MediaCode.fromWire(code.wire))
        }
        for (byte in 0..0xff) {
            if (byte in defined) assertNotNull(MediaCode.fromWire(byte)) else assertNull(
                "0x%02x must be undefined".format(byte),
                MediaCode.fromWire(byte),
            )
        }
    }

    @Test
    fun everyFieldTagIsDistinctAndRoundTrips() {
        val tags = MediaField.entries.map { it.tag }
        assertEquals(tags.size, tags.toSet().size)
        for (field in MediaField.entries) {
            assertSame(field, MediaField.fromTag(field.tag))
        }
        assertNull(MediaField.fromTag(0x00))
        assertNull(MediaField.fromTag(0x14))
    }

    @Test
    fun aReplyDecodesItsCodeAndFields() {
        // OK || SEALER_ID(i64 7) || OBJECT_ID(16 bytes 0x42).
        val objectId = ByteArray(16) { 0x42 }
        val reply = ByteArray(1 + 5 + 8 + 5 + 16)
        var at = 0
        reply[at++] = 0x00
        reply[at++] = 0x01; reply[at++] = 0; reply[at++] = 0; reply[at++] = 0; reply[at++] = 8
        reply[at++] = 0; reply[at++] = 0; reply[at++] = 0; reply[at++] = 0; reply[at++] = 0; reply[at++] = 0; reply[at++] = 0; reply[at++] = 7
        reply[at++] = 0x03; reply[at++] = 0; reply[at++] = 0; reply[at++] = 0; reply[at++] = 16
        objectId.copyInto(reply, at)
        val result = MediaResult.decode(reply)
        assertTrue(result.isOk)
        assertEquals(7L, result.i64(MediaField.SEALER_ID))
        assertTrue(objectId.contentEquals(result.bytes(MediaField.OBJECT_ID)))
        assertNull(result.bytesOrNull(MediaField.KEY_ENV))
    }

    /** A `sealFinish` reply carries `key_env`: the native reply is erased once decoded. */
    @Test
    fun theReplyIsErasedOnceDecoded() {
        val reply = ByteArray(1 + 5 + 60)
        reply[0] = 0x00
        reply[1] = 0x0c
        reply[5] = 60
        for (i in 6..64) reply[i] = 0x5a
        val result = MediaResult.decode(reply)
        assertEquals(60, result.bytes(MediaField.KEY_ENV).size)
        assertTrue("the reply buffer still holds its fields", reply.all { it == 0.toByte() })
    }

    @Test
    fun aMalformedReplyIsInternalRatherThanAnException() {
        // Unknown code byte.
        assertEquals(MediaCode.INTERNAL, MediaResult.decode(byteArrayOf(0x42)).code)
        // Truncated header.
        assertEquals(MediaCode.INTERNAL, MediaResult.decode(byteArrayOf(0x00, 0x01, 0, 0)).code)
        // Unknown tag.
        assertEquals(
            MediaCode.INTERNAL,
            MediaResult.decode(byteArrayOf(0x00, 0x7f, 0, 0, 0, 0)).code,
        )
        // Length overruns the array.
        assertEquals(
            MediaCode.INTERNAL,
            MediaResult.decode(byteArrayOf(0x00, 0x01, 0, 0, 0, 9, 1)).code,
        )
        // Repeated tag.
        assertEquals(
            MediaCode.INTERNAL,
            MediaResult.decode(
                byteArrayOf(0x00, 0x01, 0, 0, 0, 1, 7, 0x01, 0, 0, 0, 1, 8),
            ).code,
        )
    }

    @Test
    fun anEmptyOrNullReplyIsInternal() {
        assertEquals(MediaCode.INTERNAL, MediaResult.decode(null).code)
        assertEquals(MediaCode.INTERNAL, MediaResult.decode(ByteArray(0)).code)
    }

    @Test
    fun everyPrefixOfAValidReplyIsRefusedOrDecodesWithoutThrowing() {
        val objectId = ByteArray(16) { 0x42 }
        val reply = ByteArray(1 + 5 + 16)
        reply[0] = 0x00
        reply[1] = 0x03
        reply[5] = 16
        objectId.copyInto(reply, 6)
        for (length in reply.indices) {
            val result = MediaResult.decode(reply.copyOf(length))
            assertTrue(
                "prefix of length $length",
                result.code == MediaCode.INTERNAL || result.isOk,
            )
        }
        val whole = MediaResult.decode(reply)
        assertTrue(whole.isOk)
        assertTrue(objectId.contentEquals(whole.bytes(MediaField.OBJECT_ID)))
    }
}
