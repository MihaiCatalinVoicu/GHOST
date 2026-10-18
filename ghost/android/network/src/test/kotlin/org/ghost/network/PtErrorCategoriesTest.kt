package org.ghost.network

import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * The documented-and-tested half of the Phase 12 category discipline (design
 * `faza12-transports.md` §8.3): the four PT category constants of `:network` are exactly the
 * rows `client-core/README.md` documents, mirroring `ErrorPolicyTest`'s README parse (the Rust
 * half, `categories.rs`'s `categories_are_unique_and_documented`, pins the same table the other
 * direction). A category string is the only thing an error carries across the boundary (T58's
 * error half), so the names are pinned at both ends of the build.
 */
class PtErrorCategoriesTest {

    private fun readmeCategories(): Set<String> {
        val readme = File("../../client-core/README.md")
        assertTrue("client-core/README.md not found from ${File(".").absolutePath}", readme.isFile)
        val lines = readme.readLines(Charsets.UTF_8)
        val header = lines.indexOfFirst { it.trim().startsWith("| Categorie |") }
        assertTrue("category table header not found", header >= 0)
        val row = Regex("""^\|\s*`([a-z_]+)`\s*\|""")
        val out = HashSet<String>()
        for (line in lines.drop(header + 2)) {
            if (!line.trim().startsWith("|")) break
            out += row.find(line.trim())?.groupValues?.get(1) ?: throw AssertionError("unparsable category row: $line")
        }
        return out
    }

    @Test
    fun theFourPtCategoriesAreDocumentedInTheReadmeTable() {
        val documented = readmeCategories()
        for (category in listOf(
            PtErrorCategories.PT_HASH_MISMATCH,
            PtErrorCategories.PT_UNSUPPORTED_ABI,
            PtErrorCategories.BRIDGE_LINE_INVALID,
            PtErrorCategories.BRIDGE_LINE_UNSUPPORTED_TRANSPORT,
        )) {
            assertTrue("README does not document `$category`", category in documented)
        }
    }

    @Test
    fun theCategoriesCarryNoSecretsByShape() {
        // Lowercase snake_case, like every category of `categories.rs ALL` (its mapping test
        // pins the same shape); an index or a line can never hide in one of these names.
        for (category in listOf(
            PtErrorCategories.PT_HASH_MISMATCH,
            PtErrorCategories.PT_UNSUPPORTED_ABI,
            PtErrorCategories.BRIDGE_LINE_INVALID,
            PtErrorCategories.BRIDGE_LINE_UNSUPPORTED_TRANSPORT,
        )) {
            assertTrue(category.matches(Regex("[a-z_]+")))
        }
    }
}
