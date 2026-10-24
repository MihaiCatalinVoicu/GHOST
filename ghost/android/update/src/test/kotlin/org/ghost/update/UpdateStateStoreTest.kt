package org.ghost.update

import org.ghost.storage.JdbcSqlExecutor
import org.ghost.storage.MigrationRunner
import org.ghost.storage.queryLong
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayOutputStream

/**
 * The `:update` store over schema U (Phase 14 design §9.6.1): START's fresh row, the blob ↔
 * columns round trip, ACCEPT's one transaction with its directory hook and its crash rule,
 * RUN-END's counter, and the staged row's lifecycle. The codec's byte layout is pinned by a
 * hand-built golden so Kotlin and `ghost-client-update`'s `codec.rs` cannot drift silently.
 */
class UpdateStateStoreTest {

    private fun db(): JdbcSqlExecutor = JdbcSqlExecutor().also { MigrationRunner(it).migrate() }

    private fun facts(
        epochTag: Int = 0xE1,
        epochVersionCode: Int = 1,
        rootVersion: Int = 1,
        manifestSeq: Long = 0,
        manifestRoot: Int = 0,
        withManifest: Boolean = false,
        floorVersionCode: Int = 0,
        floorRoot: Int = 0,
        conflict: Boolean = false,
        rootConflict: Boolean = false,
    ): UpdateCodec.Facts {
        val chain = ByteArray(128) { 0xC1.toByte() }
        return UpdateCodec.Facts(
            network = 2,
            epoch = ByteArray(32) { epochTag.toByte() },
            epochVersionCode = epochVersionCode,
            chain = chain,
            rootVersion = rootVersion,
            manifestRoot = manifestRoot,
            manifestSeq = manifestSeq,
            manifestSha256 = if (withManifest) ByteArray(32) { 0xA1.toByte() } else null,
            manifestFile = if (withManifest) ByteArray(16) { 1 } else null,
            proofFile = if (withManifest) ByteArray(8) { 2 } else null,
            floorVersionCode = floorVersionCode,
            floorRoot = floorRoot,
            conflict = conflict,
            rootConflict = rootConflict,
        )
    }

    private fun u32(out: ByteArrayOutputStream, n: Int) {
        out.write((n ushr 24) and 0xff)
        out.write((n ushr 16) and 0xff)
        out.write((n ushr 8) and 0xff)
        out.write(n and 0xff)
    }

    @Test
    fun theCodecMatchesTheHandBuiltGolden() {
        val f = facts(withManifest = true, manifestSeq = 7, manifestRoot = 3, floorVersionCode = 9, floorRoot = 3, conflict = true, rootConflict = true)
        // The layout of `codec.rs`, built again by hand: version ‖ epoch(32) ‖ epoch_vc ‖
        // lp32(chain) ‖ root_version ‖ pair.root ‖ pair.seq ‖ 1 ‖ lp32(manifest) ‖ hash(32) ‖
        // lp32(proof) ‖ floor_vc ‖ floor_root ‖ conflict ‖ root_conflict.
        val golden = ByteArrayOutputStream()
        golden.write(1)
        golden.write(ByteArray(32) { 0xE1.toByte() })
        u32(golden, 1) // epoch_version_code
        u32(golden, 128)
        golden.write(ByteArray(128) { 0xC1.toByte() })
        u32(golden, 1) // root_version
        u32(golden, 3) // pair.root
        u32(golden, 0) // pair.seq (high word)
        u32(golden, 7) // pair.seq (low word)
        golden.write(1)
        u32(golden, 16)
        golden.write(ByteArray(16) { 1 })
        golden.write(ByteArray(32) { 0xA1.toByte() })
        u32(golden, 8)
        golden.write(ByteArray(8) { 2 })
        u32(golden, 9) // floor_vc
        u32(golden, 3) // floor_root
        golden.write(1) // conflict
        golden.write(1) // root_conflict
        assertArrayEquals(golden.toByteArray(), UpdateCodec.encode(f))
        val back = UpdateCodec.decode(golden.toByteArray(), 2)
        assertEquals(2, back.network)
        assertEquals(7L, back.manifestSeq)
        assertEquals(3, back.manifestRoot)
        assertTrue(back.conflict)
        assertTrue(back.rootConflict)
    }

    @Test
    fun theCodecRefusesTamperedAndTruncatedBlobs() {
        val blob = UpdateCodec.encode(facts(withManifest = true))
        val flipped = blob.copyOf()
        flipped[0] = 2
        assertThrowsMalformed { UpdateCodec.decode(flipped, 2) }
        assertThrowsMalformed { UpdateCodec.decode(blob.copyOfRange(0, blob.size - 1), 2) }
        assertThrowsMalformed { UpdateCodec.decode(blob + byteArrayOf(0), 2) }
    }

    private fun rejects(db: org.ghost.storage.SqlExecutor, fragment: String, sql: String, vararg args: Any?) {
        try {
            db.exec(sql, args.toList())
        } catch (e: java.sql.SQLException) {
            org.junit.Assert.assertTrue("expected '$fragment', got: ${e.message}", e.message.orEmpty().contains(fragment))
            return
        }
        throw AssertionError("expected an abort for [$sql]")
    }

    private fun assertThrowsMalformed(block: () -> Unit) {
        try {
            block()
        } catch (e: org.ghost.network.NetworkException) {
            assertEquals("malformed_response", e.category)
            return
        }
        throw AssertionError("expected malformed_response")
    }

    @Test
    fun startInsertsTheFreshRowAndLoadRoundTrips() = db().use { db ->
        val store = UpdateStateStore(db)
        assertTrue(store.isEmpty())
        val rollout = ByteArray(32) { 0x31 }
        store.insertFirst(facts(), rollout)
        assertFalse(store.isEmpty())
        val loaded = store.load()!!
        assertEquals(2, loaded.network)
        assertNull(loaded.conflictRoot)
        assertEquals(0, loaded.failedRuns)
        assertArrayEquals(rollout, loaded.rolloutKey)
        assertArrayEquals(UpdateCodec.encode(facts()), loaded.blob)
        // And the columns hold what the row CHECKs require.
        assertEquals(1L, db.queryLong("SELECT root_version FROM upd_state WHERE id = 1"))
        assertEquals(0L, db.queryLong("SELECT manifest_seq FROM upd_state WHERE id = 1"))
    }

    @Test
    fun acceptRunsTheDirectoryHookInTheSameTransactionAndRollsBack() = db().use { db ->
        val store = UpdateStateStore(db)
        store.insertFirst(facts(), ByteArray(32) { 0x31 })
        var hooked = 0
        store.accept(facts(withManifest = true, manifestSeq = 1, manifestRoot = 1)) { hooked++ }
        assertEquals(1, hooked)
        val loaded = store.load()!!
        assertEquals(1L, loaded.facts.manifestSeq)
        assertEquals(16, loaded.facts.manifestFile!!.size)

        // The crash rule: a failing hook leaves the previous facts, transaction rolled back.
        try {
            store.accept(facts(withManifest = true, manifestSeq = 2, manifestRoot = 1)) {
                throw IllegalStateException("injected crash mid-ACCEPT")
            }
        } catch (e: IllegalStateException) {
            assertEquals("injected crash mid-ACCEPT", e.message)
        }
        assertFalse(db.inTransaction)
        assertEquals(1L, store.load()!!.facts.manifestSeq)
    }

    @Test
    fun runEndCountsOnlyUnansweredRuns() = db().use { db ->
        val store = UpdateStateStore(db)
        store.insertFirst(facts(), ByteArray(32) { 0x31 })
        store.runEnd(anyMirrorAnswered = false)
        store.runEnd(anyMirrorAnswered = false)
        assertEquals(2, store.load()!!.failedRuns)
        store.runEnd(anyMirrorAnswered = true)
        assertEquals(0, store.load()!!.failedRuns)
    }

    @Test
    fun theStagedRowLivesPartialVerifiedCommittedAndClears() = db().use { db ->
        val store = UpdateStateStore(db)
        store.insertFirst(facts(), ByteArray(32) { 0x31 })
        val sha = ByteArray(32) { 0x51 }
        store.stageBegin(sha, versionCode = 2, apkLength = 1000)
        assertEquals("partial", store.staged(sha)!!.state)
        store.stageAdvance(sha, 500)
        assertEquals(500L, store.staged(sha)!!.received)
        store.stageVerified(sha)
        assertEquals("verified", store.staged(sha)!!.state)
        assertEquals(1000L, store.staged(sha)!!.received)
        store.stageCommitted(sha)
        assertEquals("committed", store.staged(sha)!!.state)
        store.stageClear(sha)
        assertNull(store.staged(sha))
    }

    @Test
    fun theMonotonicTriggersGuardTheColumnsTheEngineWrites() = db().use { db ->
        val store = UpdateStateStore(db)
        store.insertFirst(facts(), ByteArray(32) { 0x31 })
        // A second START is refused by the singleton's key.
        try {
            store.insertFirst(facts(), ByteArray(32) { 0x32 })
            throw AssertionError("a second START must be refused")
        } catch (e: java.sql.SQLException) {
            assertTrue(e.message.orEmpty().contains("UNIQUE constraint failed"))
        }
        // ACCEPT writing a lower pair is refused by the trigger, not by the engine.
        store.accept(facts(withManifest = true, manifestSeq = 5, manifestRoot = 1))
        try {
            store.accept(facts(withManifest = true, manifestSeq = 2, manifestRoot = 1))
            throw AssertionError("the pair must never decrease")
        } catch (e: java.sql.SQLException) {
            assertTrue(e.message.orEmpty().contains("the pair never decreases"))
        }
    }
}
