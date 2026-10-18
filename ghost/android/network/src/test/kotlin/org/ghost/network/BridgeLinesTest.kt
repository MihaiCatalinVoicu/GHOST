package org.ghost.network

import org.ghost.storage.JdbcSqlExecutor
import org.ghost.storage.MigrationRunner
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test

/**
 * PT-U7 (Phase 12 design `faza12-transports.md` §6.2–§6.3, §8.2, §12.2): the PT-3/PT-4 round
 * trip through the **host build** of the network library (`-Dghost.net.native`, the Phase 12
 * slice-S2 host build of `ghost-client-net`): validation errors carry the failing index and
 * never a line's text, the validated set persists wrapped (the SQLCipher database on device,
 * JDBC SQLite here) in insertion order with exact dedup, and nothing beyond the validated lines
 * is ever returned or thrown. Skipped, not failed, without the host library — the repo's
 * standing native-test rule (the `android` CI job passes the property).
 */
class BridgeLinesTest {

    private val plain = "192.0.2.10:443 0123456789ABCDEF0123456789ABCDEF01234567"
    private val obfs4 = "obfs4 192.0.2.11:443 0123456789ABCDEF0123456789ABCDEF01234567 cert=AAECAw== iat-mode=1"
    private val webtunnel = "webtunnel 192.0.2.12:443 0123456789ABCDEF0123456789ABCDEF01234567 url=https://192.0.2.12/abcdefghijklmnop ver=abcdef0123"

    private fun lines(): BridgeLines {
        assumeTrue(
            "ghost-client-net host library not loaded (-Dghost.net.native)",
            System.getProperty("ghost.net.native") != null,
        )
        val db = JdbcSqlExecutor()
        MigrationRunner(db).migrate()
        // The day clock steps per inserted line, so §6.3's day-granular order is distinguishable
        // from the same-day alphabetical tie-break (pinned in TransportBridgeSchemaTest).
        var day = 100L
        return BridgeLines(db) { day++ }
    }

    @Test
    fun roundTripStoresValidatedLinesInOrder() {
        val b = lines()
        b.set(listOf(obfs4, plain, obfs4, webtunnel))
        // The duplicate collapsed; the order kept; the stored set is exactly the validated one.
        assertEquals(listOf(obfs4, plain, webtunnel), b.list())
        b.set(emptyList())
        assertEquals(emptyList<String>(), b.list())
    }

    @Test
    fun structuralFailureCarriesTheIndexNeverTheLine() {
        val b = lines()
        val bad = "obfs4 192.0.2.11:443 0123456789ABCDEF0123456789ABCDEF01234567 cert=AAECAw== iat-mode=9"
        val e = assertThrows(NetworkException::class.java) { b.set(listOf(plain, bad, webtunnel)) }
        assertEquals(PtErrorCategories.BRIDGE_LINE_INVALID, e.category)
        assertEquals("1", e.detail)
        // The message is the category alone: no line text anywhere on the exception.
        assertEquals(PtErrorCategories.BRIDGE_LINE_INVALID, e.message)
        assertFalse(e.message!!.contains("obfs4"))
        assertFalse((e.detail ?: "").contains("obfs4"))
        // A refused write stored nothing.
        assertEquals(emptyList<String>(), b.list())
    }

    @Test
    fun snowflakeAndUnknownTransportsAreDistinctlyRefused() {
        val b = lines()
        val snow = assertThrows(NetworkException::class.java) {
            b.set(listOf(plain, "snowflake 192.0.2.13:443 0123456789ABCDEF0123456789ABCDEF01234567"))
        }
        assertEquals(PtErrorCategories.BRIDGE_LINE_UNSUPPORTED_TRANSPORT, snow.category)
        assertEquals("1", snow.detail)

        val conjure = assertThrows(NetworkException::class.java) {
            b.set(listOf("conjure 192.0.2.14:443 0123456789ABCDEF0123456789ABCDEF01234567", plain))
        }
        assertEquals(PtErrorCategories.BRIDGE_LINE_UNSUPPORTED_TRANSPORT, conjure.category)
        assertEquals("0", conjure.detail)
        assertEquals(emptyList<String>(), b.list())
    }

    @Test
    fun theNineLineCapNamesTheFirstOverflowingIndex() {
        val b = lines()
        val many = (0..8).map { "192.0.2.$it:443 0123456789ABCDEF0123456789ABCDEF01234567" }
        val e = assertThrows(NetworkException::class.java) { b.set(many) }
        assertEquals(PtErrorCategories.BRIDGE_LINE_INVALID, e.category)
        assertEquals("8", e.detail)
    }

    @Test
    fun deleteRemovesOneExactLine() {
        val b = lines()
        b.set(listOf(plain, obfs4))
        assertTrue(b.delete(plain))
        assertFalse(b.delete(plain))
        assertEquals(listOf(obfs4), b.list())
    }

    @Test
    fun validatedLinesNeverAppearInErrorsEvenWhenUnique() {
        val b = lines()
        val weird = "obfs4 192.0.2.20:443 0123456789ABCDEF0123456789ABCDEF01234567 cert=AAECAw== iat-mode=2"
        b.set(listOf(weird))
        val e = assertThrows(NetworkException::class.java) { b.set(listOf("$weird trailing=1")) }
        assertNotEquals(PtErrorCategories.BRIDGE_LINE_UNSUPPORTED_TRANSPORT, e.category)
        assertFalse(e.message!!.contains("192.0.2.20"))
        // The earlier valid row survived the refused write (set is all-or-nothing).
        assertEquals(listOf(weird), b.list())
    }
}
