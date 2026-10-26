package org.ghost.sync.store

import org.ghost.network.OnionAddress
import org.ghost.storage.JdbcSqlExecutor
import org.ghost.storage.MigrationRunner
import org.ghost.sync.api.RelayEntry
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * §7.8 / D19's directory application ([ManifestDirectory]): inserts on an empty table, a fresh
 * manifest's takeover (retire what it does not list), reactivation of a retired onion, and the
 * write-once operator rule (a manifest cannot relabel a known onion).
 */
class ManifestDirectoryTest {

    private fun db(): JdbcSqlExecutor = JdbcSqlExecutor().also { MigrationRunner(it).migrate() }

    private fun entry(address: String, operator: ByteArray, source: RelayEntry.Source) =
        RelayEntry(OnionAddress.parse(address), operator, source)

    private fun op(b: Int) = ByteArray(16) { b.toByte() }

    private fun rows(db: JdbcSqlExecutor): List<Triple<String, Boolean, String>> =
        db.rows("SELECT onion_address, state, source FROM relay_directory ORDER BY relay_id") {
            Triple(it.string(0), it.string(1) == "active", it.string(2))
        }

    @Test
    fun insertsOntoAnEmptyTable() = db().use { db ->
        ManifestDirectory.apply(
            db,
            listOf(
                entry("dee5clmkkhtfagfunbjx6clhg6lw6wla2ztso7r3lkwymwkzehlqsvid.onion:443", op(1), RelayEntry.Source.CONFIG),
                entry("zlaedoy2kjoq6kybq4lidy2mvsvnnfbgfn4cgzowwqtpmg624xpni3ad.onion:443", op(2), RelayEntry.Source.CONFIG),
            ),
            now = 1_900_000_000L,
            retireOthers = false,
        )
        assertEquals(2, rows(db).size)
        assertTrue(rows(db).all { it.second && it.third == "config" })
    }

    @Test
    fun aFreshManifestTakesTheDirectoryOver() = db().use { db ->
        ManifestDirectory.apply(
            db,
            listOf(
                entry("dee5clmkkhtfagfunbjx6clhg6lw6wla2ztso7r3lkwymwkzehlqsvid.onion:443", op(1), RelayEntry.Source.CONFIG),
                entry("zlaedoy2kjoq6kybq4lidy2mvsvnnfbgfn4cgzowwqtpmg624xpni3ad.onion:443", op(2), RelayEntry.Source.CONFIG),
            ),
            now = 1_900_000_000L,
            retireOthers = false,
        )
        // The manifest lists only the first relay, from a new source: the second retires.
        ManifestDirectory.apply(
            db,
            listOf(entry("dee5clmkkhtfagfunbjx6clhg6lw6wla2ztso7r3lkwymwkzehlqsvid.onion:443", op(1), RelayEntry.Source.MANIFEST)),
            now = 1_900_000_100L,
            retireOthers = true,
        )
        val after = rows(db)
        assertEquals(2, after.size)
        assertEquals(
            Triple("dee5clmkkhtfagfunbjx6clhg6lw6wla2ztso7r3lkwymwkzehlqsvid.onion:443", true, "manifest"),
            after[0],
        )
        assertEquals("zlaedoy2kjoq6kybq4lidy2mvsvnnfbgfn4cgzowwqtpmg624xpni3ad.onion:443", after[1].first)
        assertTrue(!after[1].second)
    }

    @Test
    fun aRetiredOnionReListedReactivatesWithRefreshedSource() = db().use { db ->
        ManifestDirectory.apply(
            db,
            listOf(entry("dee5clmkkhtfagfunbjx6clhg6lw6wla2ztso7r3lkwymwkzehlqsvid.onion:443", op(1), RelayEntry.Source.CONFIG)),
            now = 1_900_000_000L,
            retireOthers = true,
        )
        ManifestDirectory.apply(db, emptyList(), now = 1_900_000_100L, retireOthers = true)
        assertTrue(rows(db).single().let { !it.second })
        ManifestDirectory.apply(
            db,
            listOf(entry("dee5clmkkhtfagfunbjx6clhg6lw6wla2ztso7r3lkwymwkzehlqsvid.onion:443", op(1), RelayEntry.Source.MANIFEST)),
            now = 1_900_000_200L,
            retireOthers = false,
        )
        assertEquals(
            Triple("dee5clmkkhtfagfunbjx6clhg6lw6wla2ztso7r3lkwymwkzehlqsvid.onion:443", true, "manifest"),
            rows(db).single(),
        )
    }

    @Test
    fun operatorIdsAreWriteOncePerOnion() = db().use { db ->
        ManifestDirectory.apply(
            db,
            listOf(
                entry("dee5clmkkhtfagfunbjx6clhg6lw6wla2ztso7r3lkwymwkzehlqsvid.onion:443", op(1), RelayEntry.Source.CONFIG),
                entry("zlaedoy2kjoq6kybq4lidy2mvsvnnfbgfn4cgzowwqtpmg624xpni3ad.onion:443", op(2), RelayEntry.Source.CONFIG),
            ),
            now = 1_900_000_000L,
            retireOthers = false,
        )
        // A manifest relabels the first relay and drops the second: the relabel is refused (the
        // row keeps operator 1), the relabeled onion still counts as present, the second retires.
        ManifestDirectory.apply(
            db,
            listOf(entry("dee5clmkkhtfagfunbjx6clhg6lw6wla2ztso7r3lkwymwkzehlqsvid.onion:443", op(9), RelayEntry.Source.MANIFEST)),
            now = 1_900_000_100L,
            retireOthers = true,
        )
        val opOfFirst = db.single(
            "SELECT operator_id FROM relay_directory WHERE onion_address = ?1",
            listOf("dee5clmkkhtfagfunbjx6clhg6lw6wla2ztso7r3lkwymwkzehlqsvid.onion:443"),
        ) { it.blob(0) }!!
        assertTrue(opOfFirst.contentEquals(op(1)))
        val after = rows(db)
        assertTrue(after[0].second) // still active (present in the manifest list)
        assertTrue(!after[1].second) // dropped by the takeover
    }
}
