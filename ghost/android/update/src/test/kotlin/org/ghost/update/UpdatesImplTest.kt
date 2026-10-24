package org.ghost.update

import org.ghost.network.NetworkException
import org.ghost.network.UpdateNative
import org.ghost.storage.JdbcSqlExecutor
import org.ghost.storage.MigrationRunner
import org.ghost.sync.api.UpdateParticipant
import org.ghost.sync.api.UpdateSession
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

/**
 * The [UpdatesImpl] facade (Phase 14 design §9.5): every status derived from the stored facts,
 * the channel flags' precedence, and `manifestIssuedDay` read from the manifest document at
 * §4.5's fixed offsets. The native side is a fake that answers what each scenario scripts.
 */
class UpdatesImplTest {

    @get:Rule
    val temp = TemporaryFolder()

    private fun db(): JdbcSqlExecutor = JdbcSqlExecutor().also { MigrationRunner(it).migrate() }

    /** A GHRM-shaped manifest document with the fields the facade reads at §4.5's offsets. */
    private fun manifest(issued: Int = 20_960, notAfter: Int = 20_990, name: String = "0.9.0-stg2"): ByteArray {
        val out = ByteArray(100)
        out[0] = 'G'.code.toByte()
        out[1] = 'H'.code.toByte()
        out[2] = 'R'.code.toByte()
        out[3] = 'M'.code.toByte()
        out[4] = 1
        out[6] = 2
        fun put32(at: Int, n: Int) {
            out[at] = (n ushr 24).toByte()
            out[at + 1] = (n ushr 16).toByte()
            out[at + 2] = (n ushr 8).toByte()
            out[at + 3] = n.toByte()
        }
        put32(50, issued)
        put32(54, notAfter)
        put32(58, 2) // version_code
        out[62] = 0
        out[63] = name.length.toByte()
        name.toByteArray(Charsets.US_ASCII).copyInto(out, 64)
        return out
    }

    private class FakeNative(var answer: UpdateNative.Offer) : UpdateNativeBridge {
        var offerCalls = 0
        override fun embeddedChain(): ByteArray = ByteArray(128)
        override fun start(stored: ByteArray, embeddedChain: ByteArray, installed: Int): ByteArray = stored
        override fun accept(stored: ByteArray, bundle: ByteArray, dayTrusted: Boolean, day: Int, nowUnix: Long): Pair<Int, ByteArray> =
            UpdateNative.OK to stored
        override fun offer(stored: ByteArray, installed: Int, sdk: Int, rolloutKey: ByteArray, dayTrusted: Boolean, day: Int): UpdateNative.Offer {
            offerCalls++
            return answer
        }
        override fun mirrorSet(stored: ByteArray, embeddedChain: ByteArray, noChannel: Boolean, dayTrusted: Boolean, day: Int, draw: ByteArray, hasOffer: Boolean, offerSha256: ByteArray, offerLength: Long): Long = 1
        override fun mirrorSetClose(handle: Long) = Unit
        override fun apkBegin(stored: ByteArray, releaseIndex: Int, sdk: Int, length: Long, tail: ByteArray): Long = 1
        override fun apkFooter(handle: Long, footer: ByteArray): Int = UpdateNative.OK
        override fun apkUpdate(handle: Long, offset: Long, chunk: ByteArray): Int = UpdateNative.OK
        override fun apkFinish(handle: Long): Int = UpdateNative.OK
        override fun apkAbort(handle: Long) = Unit
    }

    private fun facts(manifest: ByteArray? = null, conflict: Boolean = false, rootConflict: Boolean = false): UpdateCodec.Facts =
        UpdateCodec.Facts(
            network = 2,
            epoch = ByteArray(32) { 0xE1.toByte() },
            epochVersionCode = 1,
            chain = ByteArray(128) { 0xC1.toByte() },
            rootVersion = 1,
            manifestRoot = if (manifest != null) 1 else 0,
            manifestSeq = if (manifest != null) 1 else 0,
            manifestSha256 = if (manifest != null) ByteArray(32) { 0xA1.toByte() } else null,
            manifestFile = manifest,
            proofFile = if (manifest != null) ByteArray(8) { 2 } else null,
            floorVersionCode = 0,
            floorRoot = 0,
            conflict = conflict,
            rootConflict = rootConflict,
        )

    private fun facade(
        db: JdbcSqlExecutor,
        native: FakeNative,
        day: Int = 20_970,
        userCall: ((UpdateSession) -> Unit) -> Unit = { it(FakeSession()) },
    ): UpdatesImpl {
        val engine = UpdateEngine(
            db = { db },
            files = temp.newFolder("upd-${System.nanoTime()}"),
            native = native,
            installedVersionCode = { 1 },
            sdk = 29,
            dayNow = { day to 1_900_000_000L },
        )
        return UpdatesImpl(
            db = { db },
            native = native,
            engine = engine,
            installedVersionCode = { 1 },
            sdk = 29,
            clockTrusted = { true },
            dayNow = { day to 1_900_000_000L },
            userCall = userCall,
        )
    }

    private class FakeSession : UpdateSession {
        override fun updateDraw(): ByteArray = ByteArray(32)
        override fun clockTrusted(): Boolean = true
        override val deadlineMonotonicMillis: Long = Long.MAX_VALUE
        override val closed: Boolean = false
        override val userInitiated: Boolean = false
        override val mirror: org.ghost.sync.api.MirrorAccess = object : org.ghost.sync.api.MirrorAccess {
            override fun fetchBundle(mirrorSet: Long, slot: Int, deadlineMillis: Int): ByteArray = ByteArray(10) { slot.toByte() }
            override fun fetchApkChunk(mirrorSet: Long, slot: Int, chunkIndex: Long, deadlineMillis: Int): ByteArray =
                throw NetworkException("transport")
        }
    }

    private fun seed(db: JdbcSqlExecutor, f: UpdateCodec.Facts) {
        val store = UpdateStateStore(db)
        store.insertFirst(facts(), ByteArray(32) { 0x31 })
        if (f.manifestFile != null || f.conflict || f.rootConflict) store.accept(f)
    }

    @Test
    fun noRowMeansNoManifest() {
        assertEquals(UpdateStatus.NoManifest, facade(db(), FakeNative(UpdateNative.Offer.None(UpdateNative.UP_TO_DATE))).status)
    }

    @Test
    fun upToDateAndAvailableComeFromTheOffer() {
        val db = db()
        seed(db, facts(manifest()))
        val upToDate = facade(db, FakeNative(UpdateNative.Offer.None(UpdateNative.UP_TO_DATE)))
        assertEquals(UpdateStatus.UpToDate, upToDate.status)
        val available = facade(db, FakeNative(UpdateNative.Offer.Update(2, "0.9.0-stg2", 0, ByteArray(32) { 5 }, 1000)))
        assertEquals(UpdateStatus.Available("0.9.0-stg2", 2), available.status)
    }

    @Test
    fun flagsAndStaleOutrankTheOffer() {
        val db = db()
        seed(db, facts(manifest(), conflict = true))
        assertEquals(UpdateStatus.Conflict, facade(db, FakeNative(UpdateNative.Offer.Update(2, "x", 0, ByteArray(32), 1))).status)

        val db2 = db()
        seed(db2, facts(manifest(issued = 20_960, notAfter = 20_965), rootConflict = true))
        assertEquals(UpdateStatus.RootConflict, facade(db2, FakeNative(UpdateNative.Offer.None(UpdateNative.UP_TO_DATE))).status)

        val db3 = db()
        seed(db3, facts(manifest(issued = 20_900, notAfter = 20_910)))
        assertEquals(UpdateStatus.Stale(20_900), facade(db3, FakeNative(UpdateNative.Offer.Update(2, "x", 0, ByteArray(32), 1)), day = 20_950).status)
    }

    @Test
    fun twelveUnansweredRunsMeanNoChannel() {
        val db = db()
        seed(db, facts(manifest()))
        val store = UpdateStateStore(db)
        for (i in 1..12) store.runEnd(anyMirrorAnswered = false)
        assertEquals(UpdateStatus.NoChannel, facade(db, FakeNative(UpdateNative.Offer.Update(2, "x", 0, ByteArray(32), 1))).status)
    }

    @Test
    fun aStagedRowMeansDownloadingOrReady() {
        val db = db()
        seed(db, facts(manifest()))
        val store = UpdateStateStore(db)
        val sha = ByteArray(32) { 0x5A }
        store.stageBegin(sha, 2, 1000)
        store.stageAdvance(sha, 400)
        assertEquals(UpdateStatus.Downloading(400, 1000), facade(db, FakeNative(UpdateNative.Offer.None(UpdateNative.UP_TO_DATE))).status)
        store.stageVerified(sha)
        assertEquals(UpdateStatus.Ready("0.9.0-stg2", 2), facade(db, FakeNative(UpdateNative.Offer.None(UpdateNative.UP_TO_DATE))).status)
    }

    @Test
    fun manifestIssuedDayComesFromTheDocument() {
        val db = db()
        seed(db, facts(manifest(issued = 20_944)))
        assertEquals(20_944, facade(db, FakeNative(UpdateNative.Offer.None(UpdateNative.UP_TO_DATE))).manifestIssuedDay)
    }

    @Test
    fun userCallsRunTheEngineOnAUserSession() {
        val db = db()
        seed(db, facts(manifest()))
        val native = FakeNative(UpdateNative.Offer.None(UpdateNative.UP_TO_DATE))
        var sessions = 0
        val updates = facade(db, native) { block ->
            sessions++
            block(FakeSession())
        }
        assertTrue(updates.requestCheck() is Updates.CheckOutcome.Ok)
        assertEquals(1, sessions)
        // No offer: the download finds nothing to start.
        assertEquals(Updates.DownloadOutcome.NothingToDownload, updates.requestDownload())
        assertEquals(2, sessions)
    }
}
