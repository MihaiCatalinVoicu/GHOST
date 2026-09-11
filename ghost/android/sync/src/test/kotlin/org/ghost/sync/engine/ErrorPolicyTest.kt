package org.ghost.sync.engine

import org.ghost.network.NetworkException
import org.ghost.sync.api.StatusFlag
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * Every error category of `client-core/README.md` has an explicit mapping (design §3.6), mirroring
 * the Rust test `categories_are_unique_and_documented`. The README is a declared Gradle test input.
 */
class ErrorPolicyTest {

    /** First-column backticked names of the README's category table ("| Categorie | Când |"). */
    private fun readmeCategories(): List<String> {
        val readme = File("../../client-core/README.md")
        assertTrue("client-core/README.md not found from ${File(".").absolutePath}", readme.isFile)
        val lines = readme.readLines(Charsets.UTF_8)
        val header = lines.indexOfFirst { it.trim().startsWith("| Categorie |") }
        assertTrue("category table header not found", header >= 0)
        val out = ArrayList<String>()
        val row = Regex("""^\|\s*`([a-z_]+)`\s*\|""")
        for (line in lines.drop(header + 2)) {
            if (!line.trim().startsWith("|")) break
            val match = row.find(line.trim()) ?: throw AssertionError("unparsable category row: $line")
            out += match.groupValues[1]
        }
        return out
    }

    @Test
    fun everyReadmeCategoryHasAnExplicitMapping() {
        val documented = readmeCategories()
        assertEquals("the README lists each category once", documented.size, documented.toSet().size)
        assertEquals("categories.rs ALL (20) plus native_missing", 21, documented.size)
        val unmapped = documented.filter { it !in ErrorPolicy.CATEGORIES }
        assertEquals("categories without an explicit mapping", emptyList<String>(), unmapped)
        val undocumented = ErrorPolicy.CATEGORIES.keys.filter { it !in documented }
        assertEquals("mapped categories the README does not list", emptyList<String>(), undocumented)
        for (category in documented) assertNotEquals(category, ErrorClass.UNKNOWN, ErrorPolicy.classify(category))
    }

    @Test
    fun theCategoryClassesFollowTheDesignTable() {
        val expected = mapOf(
            "closed" to ErrorClass.ABORT,
            "not_bootstrapped" to ErrorClass.NEEDS_BOOTSTRAP,
            "tor_bootstrap" to ErrorClass.NEW_TRANSPORT,
            "tor_bootstrap_timeout" to ErrorClass.NEW_TRANSPORT,
            "tor_setup" to ErrorClass.LOCAL_FATAL,
            "runtime" to ErrorClass.LOCAL_FATAL,
            "native_missing" to ErrorClass.LOCAL_FATAL,
            "bridge_config" to ErrorClass.CONFIG,
            "transport" to ErrorClass.RELAY_TRANSIENT,
            "timeout" to ErrorClass.RELAY_TRANSIENT_AMBIGUOUS,
            "relay_unavailable" to ErrorClass.RELAY_TRANSIENT_AMBIGUOUS,
            "internal" to ErrorClass.RELAY_TRANSIENT_AMBIGUOUS,
            "malformed_response" to ErrorClass.RELAY_HOSTILE,
            "not_stored" to ErrorClass.RELAY_ANOMALY,
            "unauthorized" to ErrorClass.NEEDS_CAPABILITY,
            "quota" to ErrorClass.QUOTA,
            "not_found" to ErrorClass.MISSING,
            "rejected" to ErrorClass.PERMANENT,
            "invalid_argument" to ErrorClass.LOCAL_BUG,
            "not_bucket_sized" to ErrorClass.LOCAL_BUG,
            "not_onion" to ErrorClass.LOCAL_BUG,
        )
        assertEquals(expected, ErrorPolicy.CATEGORIES)
        assertEquals(ErrorClass.UNKNOWN, ErrorPolicy.classify("a_category_from_the_future"))
    }

    @Test
    fun storeColumn() {
        fun row(c: ErrorClass) = ErrorPolicy.store(c).let { listOf(it.action, it.breakerWeight, it.flag, it.copyEffect) }
        assertEquals(listOf(StoreAction.STOP, 0, null, CopyEffect.POSSIBLE), row(ErrorClass.ABORT))
        for (c in listOf(ErrorClass.NEEDS_BOOTSTRAP, ErrorClass.NEW_TRANSPORT, ErrorClass.LOCAL_FATAL, ErrorClass.CONFIG)) {
            assertEquals(listOf(StoreAction.STOP, 0, null, CopyEffect.NONE), row(c))
        }
        assertEquals(listOf(StoreAction.NOT_APPLIED, 1, null, CopyEffect.NONE), row(ErrorClass.RELAY_TRANSIENT))
        assertEquals(listOf(StoreAction.AMBIGUOUS, 1, null, CopyEffect.POSSIBLE), row(ErrorClass.RELAY_TRANSIENT_AMBIGUOUS))
        assertEquals(listOf(StoreAction.AMBIGUOUS, 2, null, CopyEffect.POSSIBLE), row(ErrorClass.RELAY_HOSTILE))
        assertEquals(listOf(StoreAction.AMBIGUOUS, 2, null, CopyEffect.POSSIBLE), row(ErrorClass.RELAY_ANOMALY))
        assertEquals(listOf(StoreAction.PARK_UNAUTHORIZED, 0, null, CopyEffect.NONE), row(ErrorClass.NEEDS_CAPABILITY))
        assertEquals(listOf(StoreAction.QUOTA_CHECK, 0, null, CopyEffect.NONE), row(ErrorClass.QUOTA))
        assertEquals(listOf(StoreAction.AMBIGUOUS, 2, null, CopyEffect.POSSIBLE), row(ErrorClass.MISSING))
        assertEquals(listOf(StoreAction.FAIL, 0, StatusFlag.RELAY_REJECTS, CopyEffect.NONE), row(ErrorClass.PERMANENT))
        assertEquals(listOf(StoreAction.FAIL, 0, StatusFlag.BUG, CopyEffect.NONE), row(ErrorClass.LOCAL_BUG))
        assertEquals(listOf(StoreAction.AMBIGUOUS, 1, StatusFlag.UNKNOWN_CATEGORY, CopyEffect.POSSIBLE), row(ErrorClass.UNKNOWN))
        // Every category that may have left a copy is exactly the design's "possible copy" set.
        val possible = ErrorPolicy.CATEGORIES.filterValues { ErrorPolicy.store(it).copyEffect == CopyEffect.POSSIBLE }.keys
        assertEquals(setOf("closed", "timeout", "relay_unavailable", "internal", "malformed_response", "not_stored", "not_found"), possible)
    }

    @Test
    fun listGetAndCheckColumns() {
        fun row(c: ErrorClass, get: Boolean) = ErrorPolicy.read(c, get).let { listOf(it.action, it.breakerWeight, it.flag) }
        for (get in listOf(false, true)) {
            for (c in ErrorClass.entries.filter { it.transportLevel }) assertEquals(listOf(ReadAction.STOP, 0, null), row(c, get))
            assertEquals(listOf(ReadAction.SKIP, 1, null), row(ErrorClass.RELAY_TRANSIENT, get))
            assertEquals(listOf(ReadAction.SKIP, 1, null), row(ErrorClass.RELAY_TRANSIENT_AMBIGUOUS, get))
            assertEquals(listOf(ReadAction.HOSTILE, 2, null), row(ErrorClass.RELAY_HOSTILE, get))
            // quota and not_stored cannot answer a read: hostile.
            assertEquals(listOf(ReadAction.HOSTILE, 2, null), row(ErrorClass.QUOTA, get))
            assertEquals(listOf(ReadAction.HOSTILE, 2, null), row(ErrorClass.RELAY_ANOMALY, get))
            assertEquals(listOf(ReadAction.SUSPEND, 0, null), row(ErrorClass.NEEDS_CAPABILITY, get))
            assertEquals(listOf(ReadAction.PAUSE, 0, StatusFlag.RELAY_REJECTS), row(ErrorClass.PERMANENT, get))
            assertEquals(listOf(ReadAction.PAUSE, 0, StatusFlag.BUG), row(ErrorClass.LOCAL_BUG, get))
            assertEquals(listOf(ReadAction.SKIP, 1, StatusFlag.UNKNOWN_CATEGORY), row(ErrorClass.UNKNOWN, get))
        }
        assertEquals(listOf(ReadAction.NOT_FOUND, 0, null), row(ErrorClass.MISSING, true))
        assertEquals(listOf(ReadAction.HOSTILE, 2, null), row(ErrorClass.MISSING, false))
    }

    @Test
    fun relayCallCatchesOnlyThePortFailures() {
        val failed = relayCall<Int> { throw NetworkException("timeout") }
        assertTrue(failed is CallResult.Failed && failed.errorClass == ErrorClass.RELAY_TRANSIENT_AMBIGUOUS && failed.category == "timeout")
        val bug = relayCall<Int> { throw IllegalArgumentException("deadline out of range") }
        assertTrue(bug is CallResult.Failed && bug.errorClass == ErrorClass.LOCAL_BUG)
        assertNull((bug as CallResult.Failed).category)
        val ok = relayCall { 7 }
        assertEquals(7, (ok as CallResult.Ok).value)
        // Everything else propagates: a JVM Error (a simulated crash) and an engine bug alike.
        assertThrows(AssertionError::class.java) { relayCall<Int> { throw AssertionError("crash") } }
        assertThrows(IllegalStateException::class.java) { relayCall<Int> { throw IllegalStateException("bug") } }
    }
}
