package org.ghost.crypto.bridge

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * The one number this module restates from the crate is [DmContent.MAX_BODY_BYTES], and this test
 * is why restating it is allowed: it reads `seal.rs` and compares.
 *
 * The cap is the facade's `TOO_LARGE` (§13.2) and the engine's guard at SEND S2, which runs
 * **before** the record is built, so it cannot come out of a call. Everything else about the
 * bucket rule stays in Rust and crosses with the record: `l0Encode` returns the bucket R-B1 chose
 * from the body length (§6.6), which is what stops mutants ME-22 and ME-3 from being writable in
 * Kotlin at all.
 */
class DmBucketsTest {

    private fun crateSource(name: String): File {
        val file = File("../../client-core/dm/src/$name").canonicalFile
        assertTrue("$file must exist", file.isFile)
        return file
    }

    @Test
    fun theBodyCapIsTheOneTheCrateFreezes() {
        val source = crateSource("seal.rs").readText()
        val value = Regex("""pub const MAX_BODY_BYTES: usize = (\d[\d_]*);""")
            .find(source)
            ?.groupValues
            ?.get(1)
            ?.replace("_", "")
            ?.toInt()
            ?: error("seal.rs has no MAX_BODY_BYTES")
        assertEquals(value, DmContent.MAX_BODY_BYTES)
    }

    /**
     * The three buckets are not restated here at all; this asserts that, so a later slice cannot
     * add a fourth copy of them to Kotlin without this failing.
     */
    @Test
    fun theBucketSizesAreNotRestatedInThisModule() {
        val facadeDir = File("src/main/kotlin/org/ghost/crypto/bridge").canonicalFile
        val sources = facadeDir.listFiles { file -> file.extension == "kt" }.orEmpty()
        assertTrue(sources.isNotEmpty())
        for (source in sources) {
            val text = source.readText()
            for (literal in listOf("4096", "16384", "65536", "1664")) {
                assertTrue(
                    "${source.name} restates the bucket constant $literal; " +
                        "the bucket comes back from l0Encode (§6.6)",
                    !Regex("""(^|[^\d_])$literal([^\d_]|$)""").containsMatchIn(text),
                )
            }
        }
    }
}
