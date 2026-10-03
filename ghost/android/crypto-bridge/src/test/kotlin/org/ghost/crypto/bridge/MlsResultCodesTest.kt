package org.ghost.crypto.bridge

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * `MlsResultCodesTest` (Phase 10 design §10.2: "`MlsResultCodesTest` enumerates the codes"): the
 * channel result codes, the commit reasons and the wire's field tags are one list each, and this
 * module and `ghost-client-mls` agree on all three — and every facade function of [ChannelCrypto]
 * answers exactly the codes its native function declares.
 *
 * The Rust files are the numbering, so the tests read `result.rs` and `jni.rs` and compare rather
 * than restate the bytes: a code, a reason or a tag added, removed, renumbered, made repeatable or
 * made a record on one side only fails here. A pure-JVM test: it needs no native library.
 */
class MlsResultCodesTest {

    private fun rust(name: String): String {
        // The module is ghost/android/crypto-bridge; the crate is ghost/client-core/mls.
        val file = File("../../client-core/mls/src/$name").canonicalFile
        assertTrue("$file must exist", file.isFile)
        return file.readText()
    }

    private fun enumBody(source: String, declaration: String): String =
        source.substringAfter(declaration).substringBefore("\n}")

    /** `NotAMember` is `NOT_A_MEMBER`, `KEnv` is `K_ENV`, `Ok` is `OK`. */
    private fun spelled(variant: String): String = variant.replace(Regex("(?<=.)([A-Z])"), "_$1").uppercase()

    @Test
    fun theKotlinAndRustCodeListsAgree() {
        val source = rust("result.rs")
        val rust = Regex("""^\s{4}(\w+) = (\d+),$""", RegexOption.MULTILINE)
            .findAll(enumBody(source, "pub enum Code {"))
            .map { it.groupValues[1] to it.groupValues[2].toInt() }
            .toList()
        assertEquals("the Rust enumeration lost or gained a code", MlsCode.entries.size, rust.size)
        val names = Regex("""Code::(\w+) => "([A-Z_]+)",""")
            .findAll(source)
            .associate { it.groupValues[1] to it.groupValues[2] }
        for ((variant, wire) in rust) {
            val name = names[variant] ?: error("Rust has no name() arm for $variant")
            val kotlin = MlsCode.entries.firstOrNull { it.name == name } ?: error("Kotlin has no MlsCode.$name")
            assertEquals("wire byte of $name", kotlin.wire, wire)
        }
    }

    @Test
    fun theKotlinAndRustCommitReasonsAgree() {
        val rust = Regex("""^\s{4}(\w+) = (\d+),$""", RegexOption.MULTILINE)
            .findAll(enumBody(rust("result.rs"), "pub enum CommitReason {"))
            .map { it.groupValues[1] to it.groupValues[2].toInt() }
            .toList()
        assertEquals(MlsCommitReason.entries.size, rust.size)
        for ((variant, wire) in rust) {
            val kotlin = MlsCommitReason.entries.firstOrNull { it.name == spelled(variant) }
                ?: error("Kotlin has no MlsCommitReason.${spelled(variant)}")
            assertEquals("wire byte of $variant", kotlin.wire, wire)
        }
    }

    /**
     * The field tags (two tags of equal-width payloads swapped would be silent on both sides), the
     * repeatable set (a list the decoder refused, or a scalar it let repeat) and the record set (a
     * record the decoder did not check).
     */
    @Test
    fun theKotlinAndRustFieldTagsAgree() {
        val source = rust("jni.rs")
        val rust = Regex("""^\s{4}(\w+) = 0x([0-9a-f]{2}),$""", RegexOption.MULTILINE)
            .findAll(enumBody(source, "pub enum Field {"))
            .map { it.groupValues[1] to it.groupValues[2].toInt(16) }
            .toList()
        assertEquals("the Rust enumeration lost or gained a tag", MlsField.entries.size, rust.size)
        for ((variant, tag) in rust) {
            val field = MlsField.entries.firstOrNull { it.name == spelled(variant) }
                ?: error("Kotlin has no MlsField.${spelled(variant)} for Rust Field::$variant")
            assertEquals("wire tag of ${field.name}", field.tag, tag)
        }
        fun list(name: String): Set<String> = Regex("""Field::(\w+)""")
            .findAll(source.substringAfter("pub const $name: &'static [Field] = &[").substringBefore("];"))
            .map { spelled(it.groupValues[1]) }
            .toSet()
        val repeatable = list("REPEATABLE")
        val records = list("RECORDS")
        assertTrue(repeatable.size >= 20 && records.size >= 17)
        assertEquals(repeatable, MlsField.entries.filter { it.repeatable }.map { it.name }.toSet())
        assertEquals(records, MlsField.entries.filter { it.record }.map { it.name }.toSet())
    }

    /**
     * Per **function**: every `when (reply.code)` block of the facade answers exactly the codes the
     * native function declares in `FUNCTION_CODES`, plus `OK` and the `CRYPTO_UNAVAILABLE` Kotlin
     * synthesises when the library is missing. A code with no arm would reach [mlsUnexpected] and
     * throw — which §10.2 reserves for `INTERNAL` — and an arm for a code the function cannot return
     * is a stale surface. Every exported function has a block; none outside the table does.
     */
    @Test
    fun everyFacadeFunctionHandlesExactlyTheCodesItsNativeFunctionCanReturn() {
        val result = rust("result.rs")
        val spelling = Regex("""Code::(\w+) => "([A-Z_]+)",""")
            .findAll(result)
            .associate { it.groupValues[1] to it.groupValues[2] }
        val table = rust("jni.rs").substringAfter("pub const FUNCTION_CODES").substringBefore("\n];")
        val declared = Regex("""\(\s*"(\w+)"\s*,\s*&\[([^\]]*)]\s*,?\s*\)""", RegexOption.DOT_MATCHES_ALL)
            .findAll(table)
            .associate { m ->
                m.groupValues[1] to Regex("""Code::(\w+)""").findAll(m.groupValues[2])
                    .map { spelling[it.groupValues[1]] ?: error("no name() arm for ${it.groupValues[1]}") }
                    .toSet()
            }
        assertEquals("FUNCTION_CODES has a row per exported function", 25, declared.size)

        val dir = File("src/main/kotlin/org/ghost/crypto/bridge").canonicalFile
        val arms = LinkedHashMap<String, Set<String>>()
        for (source in dir.listFiles { f -> f.extension == "kt" }.orEmpty().sortedBy { it.name }) {
            Regex(
                """when \(reply\.code\) \{(.*?)else -> mlsUnexpected\(reply\.code, "(\w+)"\)""",
                RegexOption.DOT_MATCHES_ALL,
            ).findAll(source.readText()).forEach { m ->
                val function = m.groupValues[2]
                val codes = Regex("""MlsCode\.([A-Z_]+)""").findAll(m.groupValues[1]).map { it.groupValues[1] }.toSet()
                assertNull("$function is answered twice (${source.name})", arms.put(function, codes))
            }
        }
        for ((function, codes) in declared) {
            val handled = arms[function] ?: error("the facade has no when block for $function")
            assertEquals("$function: the facade arms and the native code set disagree", codes + "OK" + "CRYPTO_UNAVAILABLE", handled)
        }
        for (function in arms.keys) assertTrue("the facade answers $function, which FUNCTION_CODES does not declare", function in declared)
    }

    /** The closed list as `MlsNative` declares it: §10.2's names minus the reserved function 16. */
    @Test
    fun mlsNativeDeclaresExactlyTheExportedEntriesOfTheClosedList() {
        val list = Regex("""\((\d+), "(\w+)", Availability::(Exported|Declared\("\w+"\))\)""")
            .findAll(rust("jni.rs"))
            .map { Triple(it.groupValues[1].toInt(), it.groupValues[2], it.groupValues[3] == "Exported") }
            .toList()
        val exported = list.filter { it.third }.map { it.second }.toSet()
        assertEquals(setOf("revealSeal", "revealOpen"), list.filter { !it.third }.map { it.second }.toSet())
        val declared = Regex("""internal external fun (\w+)""")
            .findAll(File("src/main/kotlin/org/ghost/crypto/bridge/MlsNative.kt").readText())
            .map { it.groupValues[1] }
            .toSet()
        assertEquals(exported, declared)
    }

    @Test
    fun everyWireByteRoundTripsAndUndefinedBytesHaveNoCode() {
        for (code in MlsCode.entries) assertSame(code, MlsCode.fromWire(code.wire))
        for (reason in MlsCommitReason.entries) assertSame(reason, MlsCommitReason.fromWire(reason.wire))
        for (field in MlsField.entries) assertSame(field, MlsField.fromTag(field.tag))
        val defined = MlsCode.entries.map { it.wire }.toSet()
        for (b in 0..0xff) if (b !in defined) assertNull(MlsCode.fromWire(b))
        assertNull(MlsField.fromTag(0))
        assertNull(MlsField.fromTag(0x7f))
        assertEquals((1..MlsField.entries.size).toList(), MlsField.entries.map { it.tag })
    }

    @Test
    fun aReplyDecodesItsFieldsListsAndRecords() {
        val change = MlsTlv().u8(MlsField.SCOPE, 1).put(MlsField.KEY, byteArrayOf(7)).put(MlsField.ENV, byteArrayOf(8, 9))
        val delete = MlsTlv().u8(MlsField.SCOPE, 2).put(MlsField.KEY, byteArrayOf(6))
        val body = MlsTlv().u32(MlsField.LEAF, 5).record(MlsField.CHANGE, change).record(MlsField.CHANGE, delete)
            .put(MlsField.ADDED, ByteArray(32) { 1 }).put(MlsField.ADDED, ByteArray(32) { 2 })
        val reply = byteArrayOf(0) + body.toByteArray()
        val decoded = MlsReply.decode(reply)
        assertTrue(decoded.isOk)
        assertEquals(5L, decoded.fields.u32(MlsField.LEAF))
        val changes = MlsChange.all(decoded.fields)
        assertEquals(2, changes.size)
        assertArrayEquals(byteArrayOf(8, 9), changes[0].env)
        assertTrue(changes[1].isDelete)
        assertEquals(2, decoded.fields.all(MlsField.ADDED).size)
        assertTrue("the reply buffer is erased once decoded", reply.all { it.toInt() == 0 })
    }

    @Test
    fun anErrorReplyCarriesItsReasonOrIndex() {
        val commit = MlsReply.decode(byteArrayOf(9, 0x34, 0, 0, 0, 1, 14))
        assertEquals(MlsCode.INVALID_COMMIT, commit.code)
        assertEquals(MlsCommitReason.RATE, commit.reason)
        val kp = MlsReply.decode(byteArrayOf(15, 0x35, 0, 0, 0, 2, 0, 3))
        assertEquals(MlsCode.INVALID_KEYPACKAGE, kp.code)
        assertEquals(3, kp.index)
        assertEquals(MlsCode.NO_FIT, MlsReply.decode(byteArrayOf(14)).code)
    }

    @Test
    fun aMalformedReplyIsStateCorruptAndAMissingOneInternal() {
        assertEquals(MlsCode.INTERNAL, MlsReply.decode(null).code)
        assertEquals(MlsCode.INTERNAL, MlsReply.decode(ByteArray(0)).code)
        assertEquals(MlsCode.STATE_CORRUPT, MlsReply.decode(byteArrayOf(0x42)).code)
        assertEquals(MlsCode.STATE_CORRUPT, MlsReply.decode(byteArrayOf(0, 0x29, 0, 0)).code)
        assertEquals(MlsCode.STATE_CORRUPT, MlsReply.decode(byteArrayOf(0, 0x7f, 0, 0, 0, 0)).code)
        assertEquals(MlsCode.STATE_CORRUPT, MlsReply.decode(byteArrayOf(0, 0x29, 0, 0, 0, 9, 1)).code)
        // A repeated scalar, a repeated list item is fine.
        assertEquals(MlsCode.STATE_CORRUPT, MlsReply.decode(byteArrayOf(0, 0x29, 0, 0, 0, 1, 0, 0x29, 0, 0, 0, 1, 1)).code)
        assertTrue(MlsReply.decode(byteArrayOf(0, 0x5f, 0, 0, 0, 1, 0, 0x5f, 0, 0, 0, 1, 1)).isOk)
        // A malformed record anywhere is the whole reply's failure.
        assertEquals(MlsCode.STATE_CORRUPT, MlsReply.decode(byteArrayOf(0, 0x03, 0, 0, 0, 2, 0x05, 0)).code)
        // An unknown reason.
        assertEquals(MlsCode.STATE_CORRUPT, MlsReply.decode(byteArrayOf(9, 0x34, 0, 0, 0, 1, 99)).code)
        // Every prefix of a valid reply decodes or is refused, and never throws.
        val reply = byteArrayOf(0) + MlsTlv().record(MlsField.MEMBER, MlsTlv().put(MlsField.PSEUDONYM, ByteArray(3)).u32(MlsField.LEAF, 2)).toByteArray()
        for (length in 1..reply.size) {
            val r = MlsReply.decode(reply.copyOf(length))
            assertTrue("prefix $length", r.code == MlsCode.STATE_CORRUPT || r.isOk)
        }
    }

    @Test
    fun theArgumentEncoderWritesTheWireAndErasesItself() {
        val t = MlsTlv().u8(MlsField.SCOPE, 1).u16(MlsField.PW_VERSION, 0x0102).u32(MlsField.DAY, 20725).u64(MlsField.EPOCH, 7)
        assertArrayEquals(
            byteArrayOf(
                0x05, 0, 0, 0, 1, 1,
                0x24, 0, 0, 0, 2, 1, 2,
                0x43, 0, 0, 0, 4, 0, 0, 0x50, 0xf5.toByte(),
                0x08, 0, 0, 0, 8, 0, 0, 0, 0, 0, 0, 0, 7,
            ),
            t.toByteArray(),
        )
        t.erase()
        assertEquals(0, t.toByteArray().size)
        val rows = MlsRow.encode(listOf(MlsRow(MlsRow.SCOPE_GROUP, byteArrayOf(1), byteArrayOf(2))))
        val decoded = MlsRecord.parse(rows, 0, rows.size)
        assertNotNull(decoded)
        assertEquals(1, decoded!!.records(MlsField.ROW).size)
    }
}
