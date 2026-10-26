package org.ghost.update

import org.ghost.network.NetworkException
import org.ghost.network.UpdateNative
import org.ghost.storage.JdbcSqlExecutor
import org.ghost.storage.MigrationRunner
import org.ghost.sync.api.MirrorAccess
import org.ghost.sync.api.UpdateSession
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

/**
 * The [UpdateEngine] as the one [org.ghost.sync.api.UpdateParticipant] (Phase 14 design §7.3,
 * §9.4, §9.5): START at the first run, the two-mirror fetch and the sequential acceptance, the
 * offer recomputed against the accepted facts, the resumable chunk download and STAGE-VERIFY,
 * and RUN-END's counter. The native side and the transport are fakes: the engine's job is the
 * orchestration and the rows, and that is what these tests pin.
 */
class UpdateEngineTest {

    @get:Rule
    val temp = TemporaryFolder()

    private fun db(): JdbcSqlExecutor = JdbcSqlExecutor().also { MigrationRunner(it).migrate() }

    /** The fake native: scripted answers, and a recording of everything the engine asked. */
    private class FakeNative(
        val blob: ByteArray,
        var acceptCode: Int = UpdateNative.OK,
        var offers: MutableList<UpdateNative.Offer> = mutableListOf(UpdateNative.Offer.None(UpdateNative.UP_TO_DATE)),
        var finishCode: Int = UpdateNative.OK,
    ) : UpdateNativeBridge {
        var starts = 0
        var accepts = 0
        var acceptBundles = mutableListOf<ByteArray>()
        var offerCalls = 0
        var mirrorSets = mutableListOf<Boolean>() // noChannel flags
        var closed = 0
        var begin: Long? = null
        var finish = 0
        var streamed = mutableListOf<Pair<Long, Int>>() // (offset, chunk length), in order
        var footer: ByteArray? = null
        var tail: ByteArray? = null

        override fun embeddedChain(): ByteArray = byteArrayOf(
            'G'.code.toByte(), 'H'.code.toByte(), 'R'.code.toByte(), 'C'.code.toByte(), 1, 0, 2, 0,
        ) + ByteArray(121)

        override fun start(stored: ByteArray, embeddedChain: ByteArray, installed: Int): ByteArray {
            starts++
            return blob
        }

        override fun accept(stored: ByteArray, bundle: ByteArray, dayTrusted: Boolean, day: Int, nowUnix: Long): Pair<Int, ByteArray> {
            accepts++
            acceptBundles += bundle
            return acceptCode to blob
        }

        override fun offer(stored: ByteArray, installed: Int, sdk: Int, rolloutKey: ByteArray, dayTrusted: Boolean, day: Int): UpdateNative.Offer {
            offerCalls++
            return offers[(offerCalls - 1).coerceAtMost(offers.size - 1)]
        }

        override fun mirrorSet(
            stored: ByteArray, embeddedChain: ByteArray, noChannel: Boolean, dayTrusted: Boolean, day: Int,
            draw: ByteArray, hasOffer: Boolean, offerSha256: ByteArray, offerLength: Long,
        ): Long {
            mirrorSets += noChannel
            return 1L
        }

        override fun mirrorSetClose(handle: Long) {
            closed++
        }

        override fun apkBegin(stored: ByteArray, releaseIndex: Int, sdk: Int, length: Long, tail: ByteArray): Long {
            begin = length
            this.tail = tail
            return 7L
        }

        override fun apkFooter(handle: Long, footer: ByteArray): Int {
            this.footer = footer
            return UpdateNative.OK
        }

        override fun apkUpdate(handle: Long, offset: Long, chunk: ByteArray): Int {
            streamed += offset to chunk.size
            return UpdateNative.OK
        }

        override fun apkFinish(handle: Long): Int {
            finish++
            return finishCode
        }

        override fun apkAbort(handle: Long) = Unit
        override fun bootstrapRelays(): List<UpdateNative.NativeRelay> = emptyList()
        override fun manifestRelays(manifest: ByteArray): List<UpdateNative.NativeRelay> = emptyList()
    }

    /** The fake session: canned bundles and chunks, a closed flag, a recording of fetches. */
    private class FakeSession(
        val bundles: MutableList<ByteArray> = mutableListOf(ByteArray(10) { 9 }, ByteArray(10) { 8 }),
        val chunks: MutableMap<Long, ByteArray> = mutableMapOf(),
        var failSecondBundle: Boolean = false,
        var failFirstBundle: Boolean = false,
    ) : UpdateSession {
        var fetchedBundles = 0
        var fetchedChunks = 0
        override var closed: Boolean = false
        override val userInitiated: Boolean = false

        override fun updateDraw(): ByteArray = ByteArray(32) { 0xD7.toByte() }

        override fun clockTrusted(): Boolean = true

        override val deadlineMonotonicMillis: Long = Long.MAX_VALUE

        override val mirror: MirrorAccess = object : MirrorAccess {
            override fun fetchBundle(mirrorSet: Long, slot: Int, deadlineMillis: Int): ByteArray {
                if (slot == 0 && failFirstBundle) throw NetworkException("transport")
                if (slot == 1 && failSecondBundle) throw NetworkException("deadline")
                fetchedBundles++
                return bundles[slot]
            }

            override fun fetchApkChunk(mirrorSet: Long, slot: Int, chunkIndex: Long, deadlineMillis: Int): ByteArray {
                fetchedChunks++
                return chunks[chunkIndex] ?: throw NetworkException("transport")
            }
        }
    }

    private fun blob(): ByteArray = UpdateCodec.encode(
        UpdateCodec.Facts(
            network = 2,
            epoch = ByteArray(32) { 0xE1.toByte() },
            epochVersionCode = 1,
            chain = ByteArray(128) { 0xC1.toByte() },
            rootVersion = 1,
            manifestRoot = 0,
            manifestSeq = 0,
            manifestSha256 = null,
            manifestFile = null,
            proofFile = null,
            floorVersionCode = 0,
            floorRoot = 0,
            conflict = false,
            rootConflict = false,
        ),
    )

    private fun engine(db: JdbcSqlExecutor, native: FakeNative) = UpdateEngine(
        db = { db },
        files = temp.newFolder("update"),
        native = native,
        installedVersionCode = { 1 },
        sdk = 29,
        dayNow = { 20_990 to 1_900_000_000L },
    )

    @Test
    fun theFirstRunStartsTheEpochFetchesBothMirrorsAcceptsAndCountsTheRun() {
        val db = db()
        val native = FakeNative(blob())
        val session = FakeSession()
        engine(db, native).onUpdateRun(session)

        assertEquals(1, native.starts)
        assertEquals(2, session.fetchedBundles)
        assertEquals(2, native.accepts)
        assertArrayEquals(ByteArray(10) { 9 }, native.acceptBundles[0])
        assertArrayEquals(ByteArray(10) { 8 }, native.acceptBundles[1])
        assertEquals(1, native.mirrorSets.size)
        assertFalse(native.mirrorSets[0])
        assertEquals(1, native.closed)
        // RUN-END with an answer: the counter stays at zero.
        assertEquals(0, UpdateStateStore(db).load()!!.failedRuns)
    }

    @Test
    fun aRunWhoseFirstMirrorFailsCountsAndRethrows() {
        val db = db()
        val native = FakeNative(blob())
        val session = FakeSession(failFirstBundle = true)
        try {
            engine(db, native).onUpdateRun(session)
            throw AssertionError("the first mirror's failure must propagate")
        } catch (e: NetworkException) {
            assertEquals("transport", e.category)
        }
        assertEquals(1, UpdateStateStore(db).load()!!.failedRuns)
        assertEquals(0, native.accepts)
    }

    @Test
    fun aRunWhoseSecondMirrorFailsStillAcceptsTheFirst() {
        val db = db()
        val native = FakeNative(blob())
        val session = FakeSession(failSecondBundle = true)
        engine(db, native).onUpdateRun(session)
        assertEquals(1, native.accepts)
        // The first mirror answered: the counter resets.
        assertEquals(0, UpdateStateStore(db).load()!!.failedRuns)
    }

    @Test
    fun twelveUnansweredRunsPutTheNextMirrorSetOnNoChannel() {
        val db = db()
        val store = UpdateStateStore(db)
        val facts = UpdateCodec.decode(blob(), 2)
        store.insertFirst(facts, ByteArray(32) { 0x31 })
        for (i in 1..12) store.runEnd(anyMirrorAnswered = false)
        assertEquals(12, store.load()!!.failedRuns)
        val native = FakeNative(blob())
        engine(db, native).onUpdateRun(FakeSession())
        assertTrue(native.mirrorSets[0])
    }

    @Test
    fun anOfferDownloadsChunksVerifiesAndStagesTheApk() {
        val db = db()
        // The content: 100 bytes; cd_offset (bytes 94..97, little-endian) = 40, so the footer
        // the engine must name is bytes 16..39.
        val content = ByteArray(100) { it.toByte() }
        content[94] = 40
        content[95] = 0
        content[96] = 0
        content[97] = 0
        val sha = ByteArray(32) { 0x5A }
        val native = FakeNative(
            blob(),
            offers = mutableListOf(
                UpdateNative.Offer.Update(2, "0.9.0-stg2", 0, sha, content.size.toLong()),
                UpdateNative.Offer.Update(2, "0.9.0-stg2", 0, sha, content.size.toLong()),
            ),
        )
        val session = FakeSession(chunks = mutableMapOf(0L to content))
        engine(db, native).onUpdateRun(session)

        assertEquals(1, native.finish)
        assertEquals(content.size.toLong(), native.begin)
        assertArrayEquals(content.copyOfRange(78, 100), native.tail)
        // Streamed in order, covering exactly the body (all but the 22-byte end record).
        val streamedTotal = native.streamed.sumOf { it.second }
        assertEquals(78, streamedTotal)
        assertEquals(0L, native.streamed.first().first)
        assertTrue(native.streamed.zipWithNext().all { (a, b) -> a.first + a.second == b.first })
        assertArrayEquals(content.copyOfRange(16, 40), native.footer)
        val staged = UpdateStateStore(db).staged(sha)!!
        assertEquals("verified", staged.state)
        assertEquals(content.size.toLong(), staged.received)
        assertTrue(java.io.File(temp.root, "update/${sha.toHexTest()}.apk").exists())
    }

    @Test
    fun aRefusedApkClearsTheRowAndThePartFile() {
        val db = db()
        val content = ByteArray(100) { it.toByte() }
        content[94] = 40
        content[95] = 0
        content[96] = 0
        content[97] = 0
        val sha = ByteArray(32) { 0x5A }
        val native = FakeNative(
            blob(),
            finishCode = UpdateNative.APK_SIGNER,
            offers = mutableListOf(
                UpdateNative.Offer.Update(2, "0.9.0-stg2", 0, sha, content.size.toLong()),
                UpdateNative.Offer.Update(2, "0.9.0-stg2", 0, sha, content.size.toLong()),
            ),
        )
        engine(db, native).onUpdateRun(FakeSession(chunks = mutableMapOf(0L to content)))
        assertNull(UpdateStateStore(db).staged(sha))
        assertFalse(java.io.File(temp.root, "update/${sha.toHexTest()}.part").exists())
    }

    private fun ByteArray.toHexTest(): String {
        val alphabet = "0123456789abcdef"
        return joinToString("") { b -> "${alphabet[(b.toInt() shr 4) and 15]}${alphabet[b.toInt() and 15]}" }
    }
}
