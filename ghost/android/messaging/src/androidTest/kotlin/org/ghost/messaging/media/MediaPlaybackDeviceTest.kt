package org.ghost.messaging.media

import android.app.Activity
import android.os.Build
import android.os.Bundle
import android.view.SurfaceHolder
import android.view.SurfaceView
import android.view.WindowManager
import androidx.media3.common.PlaybackException
import androidx.media3.common.Player
import androidx.media3.exoplayer.ExoPlayer
import org.ghost.crypto.bridge.MediaCrypto
import org.ghost.device.DeviceRunner
import org.ghost.media.play.GhostPlayer
import org.ghost.media.play.MediaPlayException
import org.ghost.media.play.MediaPlayable
import org.ghost.media.store.CiphertextFiles
import org.ghost.media.store.MediaLimits
import org.ghost.media.store.NameSource
import org.ghost.media.store.NioCiphertextFileSystem
import org.ghost.media.store.WriteResult
import org.ghost.messaging.device.DeviceWorld
import org.ghost.messaging.port.DmContext
import org.ghost.messaging.port.MediaReaders
import org.ghost.messaging.port.NativeMediaReaders
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File
import java.security.SecureRandom
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference

/**
 * §15.8 item 3's device half (Phase 11 slice S7): the real media stack plays a real sealed
 * object — the golden canonical fMP4 sealed with the real Rust sealer over the device's DM
 * context, read back through the real reader into [GhostMediaDataSource] and [GhostPlayer] —
 * in a FLAG_SECURE window. Seeks land, the stream ends, and a byte flipped on one fragment
 * file ends the playback with the typed corrupt error, never a crash. Content-identified
 * seeks (the corpus's luma-block frame indices) are the emulator job's harness over the
 * committed corpus; this local run proves the configuration end to end on the real crypto.
 * Recorded as local slice evidence, not gate evidence (D23).
 */
class MediaPlaybackDeviceTest {

    /** How the test reaches the activity it started (the test APK's own component). */
    object MediaPlaybackRegistry {
        @Volatile
        var current: MediaPlaybackActivity? = null
    }

    /** The media window of §10.3: FLAG_SECURE, and the recents screenshot off on API 33+. */
    class MediaPlaybackActivity : Activity() {
        @Volatile
        private var holderRef: SurfaceHolder? = null

        val holder: SurfaceHolder? get() = holderRef

        override fun onCreate(savedInstanceState: Bundle?) {
            super.onCreate(savedInstanceState)
            window.setFlags(
                WindowManager.LayoutParams.FLAG_SECURE,
                WindowManager.LayoutParams.FLAG_SECURE,
            )
            if (Build.VERSION.SDK_INT >= 33) {
                setRecentsScreenshotEnabled(false)
            }
            val view = SurfaceView(this)
            view.holder.addCallback(object : SurfaceHolder.Callback {
                override fun surfaceCreated(h: SurfaceHolder) {
                    holderRef = h
                }

                override fun surfaceChanged(h: SurfaceHolder, f: Int, w: Int, ht: Int) = Unit

                override fun surfaceDestroyed(h: SurfaceHolder) {
                    if (holderRef === h) holderRef = null
                }
            })
            setContentView(view)
            MediaPlaybackRegistry.current = this
        }

        override fun onDestroy() {
            MediaPlaybackRegistry.current = null
            super.onDestroy()
        }
    }

    /** One sealed object in a throwaway store: the real sealer, the real reader, real files. */
    private class Sealed(
        val content: ByteArray,
        val manifestBlob: ByteArray,
        val manifestHash: ByteArray,
        val keyEnv: ByteArray,
        val objectId: ByteArray,
        val classCode: Int,
        val files: CiphertextFiles,
        val fragmentFiles: List<ByteArray>,
        val durationMs: Long,
    )

    private fun context() = DeviceRunner.current.targetContext

    private fun seal(context: android.content.Context, world: DeviceWorld): Sealed {
        // F-S7-9's corrected reading (the review of S7): the in-tree goldens ARE canonical —
        // recorded with `tfdt` in every `traf` and `mfra` included, each checked by the S0
        // spike's profile checker (Mp4TfdtTest's two properties hold over every golden). The
        // old input was broken twice: `insertTfdt` on the full golden wrote a SECOND `tfdt`
        // after every `tfhd` (exactly what the walker refuses), and the golden's trailing
        // `mfra` would be followed by the one the Rust sealer appends. The one adjustment the
        // send input needs is dropping the golden's own `mfra` — host-proven: withoutMfra of
        // the golden seals fine.
        val asset = context.assets.open("quad_land.fmp4").use { it.readBytes() }
        val golden = withoutMfra(asset)
        val handle = world.alice.keys.handleOrNull() ?: error("the DM context is open after unlock")
        val destId = ByteArray(16) { 0x42 }
        val begun = MediaCrypto.begin(handle, destId, MediaCrypto.Kind.VIDEO, viewOnce = false, maxClass = 10)
        assertTrue("sealBegin: $begun", begun is MediaCrypto.Begun.Ok)
        val sealer = (begun as MediaCrypto.Begun.Ok).sealer
        val appended = MediaCrypto.append(handle, sealer.id, golden)
        assertTrue("sealAppend: $appended", appended is MediaCrypto.Appended.Ok)
        val finished = MediaCrypto.finish(handle, sealer.id, ByteArray(0))
        assertTrue("sealFinish: $finished", finished is MediaCrypto.FinishedResult.Ok)
        val done = (finished as MediaCrypto.FinishedResult.Ok).finished

        val dir = File(context.filesDir, "playback-test").apply { deleteRecursively(); mkdirs() }
        val files = CiphertextFiles(File(dir, "m"), NioCiphertextFileSystem(), TestNames()).also { it.open() }
        val names = mutableListOf<ByteArray>()
        for (frag in done.chunks.flatMap { it.fragments }) {
            val name = files.newName()
            val written = files.write(name, frag, enforceFloor = false)
            assertTrue("fragment written: $written", written is WriteResult.Written)
            names += (written as WriteResult.Written).fileName
        }
        return Sealed(
            content = golden,
            manifestBlob = done.manifestBlob,
            manifestHash = done.manifestHash,
            keyEnv = done.keyEnv,
            objectId = sealer.objectId,
            classCode = done.classCode,
            files = files,
            fragmentFiles = names,
            durationMs = done.durationMs,
        )
    }

    /** The golden minus its trailing `mfra`: the send input carries none because the Rust
     * sealer appends the box itself (built from the `tfdt`s). Refuses a stream whose box walk
     * does not close on an `mfra` — the asset is a checked-in canonical golden, so a surprise
     * here fails loudly rather than sealing a half-known stream. */
    private fun withoutMfra(stream: ByteArray): ByteArray {
        var at = 0
        var lastStart = -1
        while (at + 8 <= stream.size) {
            val size = u32be(stream, at)
            require(size >= 8 && at + size <= stream.size) { "box of $size B at $at overruns the stream" }
            lastStart = at
            at += size
        }
        require(at == stream.size) { "the box walk stops at $at of ${stream.size} B" }
        require(lastStart >= 0 && stream[lastStart + 4] == 'm'.code.toByte() &&
            stream[lastStart + 5] == 'f'.code.toByte() && stream[lastStart + 6] == 'r'.code.toByte() &&
            stream[lastStart + 7] == 'a'.code.toByte()) { "the golden does not end in mfra" }
        return stream.copyOfRange(0, lastStart)
    }

    private fun u32be(bytes: ByteArray, at: Int): Int =
        (bytes[at].toInt() and 0xff shl 24) or (bytes[at + 1].toInt() and 0xff shl 16) or
            (bytes[at + 2].toInt() and 0xff shl 8) or (bytes[at + 3].toInt() and 0xff)

    /** The playable over the real reader: fetch four fragments, read the chunk, erase the assembly. */
    private fun playable(sealed: Sealed, keys: DmContext, corrupt: Boolean): MediaPlayable {
        val readers = NativeMediaReaders(keys)
        val opened = readers.open(
            MediaReaders.OpenSpec(
                keyEnv = sealed.keyEnv,
                role = MediaCrypto.Role.OUT,
                destId = ByteArray(16) { 0x42 },
                objectId = sealed.objectId,
                manifestHash = sealed.manifestHash,
                manifestBlob = sealed.manifestBlob,
                kind = MediaCrypto.Kind.VIDEO,
                viewOnce = false,
                classCode = sealed.classCode,
                readable = true,
            ),
        )
        assertTrue("readerOpen: $opened", opened is MediaReaders.Opened.Ok)
        val ok = opened as MediaReaders.Opened.Ok
        val fragmentCount = ok.hashes.size
        return object : MediaPlayable {
            override val contentLength: Long = ok.contentLen

            override fun readChunk(index: Int): ByteArray {
                val assembled = ByteArray(4 * MediaLimits.FRAGMENT_BYTES)
                try {
                    for (k in 0 until 4) {
                        val ordinal = index * 4 + k
                        if (ordinal >= fragmentCount) {
                            throw MediaPlayException.Defect("fragment $ordinal missing")
                        }
                        val bytes = sealed.files.read(sealed.fragmentFiles[ordinal])
                        if (corrupt && index == 0 && k == 1) {
                            bytes[1000] = (bytes[1000].toInt() xor 1).toByte()
                        }
                        System.arraycopy(bytes, 0, assembled, k * MediaLimits.FRAGMENT_BYTES, MediaLimits.FRAGMENT_BYTES)
                    }
                    return when (val chunked = readers.chunk(ok.reader, index, assembled, validate = false)) {
                        is MediaReaders.Chunked.Ok -> chunked.content
                        MediaReaders.Chunked.HashMismatch,
                        MediaReaders.Chunked.NotOpen,
                        MediaReaders.Chunked.NonCanonical,
                        -> throw MediaPlayException.Corrupt()
                        MediaReaders.Chunked.Sequence,
                        MediaReaders.Chunked.IndexRange,
                        -> throw MediaPlayException.Defect("reader refused chunk $index")
                        MediaReaders.Chunked.Unavailable -> throw MediaPlayException.Closed()
                    }
                } finally {
                    assembled.fill(0)
                }
            }

            override fun close() = readers.close(ok.reader)
        }
    }

    private class TestNames : NameSource {
        private val random = SecureRandom()
        override fun next16(): ByteArray = ByteArray(16).also { random.nextBytes(it) }
    }

    @Test
    fun theRealStackPlaysSeeksAndSurvivesCorruption() {
        System.loadLibrary("ghost_client_net")
        val context = context()
        val world = DeviceWorld(context, "playback")
        try {
            world.alice.unlock()
            val sealed = seal(context, world)

            // The manifest's duration drives the seeks (§10.2: the fMP4 carries none).
            assertTrue("the golden has a duration", sealed.durationMs > 0)
            DeviceRunner.report(
                "media-playback: sealed ${sealed.content.size} B, ${sealed.durationMs} ms, " +
                    "${sealed.fragmentFiles.size} fragments, class ${sealed.classCode}",
            )

            // The FLAG_SECURE window the player renders into.
            DeviceRunner.current.runOnMainSync {
                val intent = android.content.Intent(context, MediaPlaybackActivity::class.java)
                    .addFlags(android.content.Intent.FLAG_ACTIVITY_NEW_TASK)
                context.startActivity(intent)
            }
            val activity = waitForActivity()
            val holder = activity.holder
            assertNotNull("the surface is up", holder)

            val main = android.os.Handler(android.os.Looper.getMainLooper())
            val errorRef = AtomicReference<PlaybackException?>()

            // Play the object: prepare, reach READY, run the seek sweep, reach ENDED. The player
            // lives on the main looper (GhostPlayer's builder), so every touch — the listener
            // registration and the polled state reads included — runs there; Media3 refuses a
            // cross-thread access with the typed "Player is accessed on the wrong thread"
            // failure (F-S7's re-run found this: the earlier runs never got past sealAppend,
            // so the harness's polling had never executed on the device).
            val uri = GhostPlayer.uriOf(sealed.objectId)
            // The playables outlive the players' data sources (the sources close and re-open
            // around Media3's own seeks without tearing down the reader — ChunkCursor's
            // releaseBuffer), so the test closes them explicitly after each release.
            val goodPlayable = playable(sealed, world.alice.keys, corrupt = false)
            val player = onMain(main) { GhostPlayer.create(context, goodPlayable, uri) }
            post(main) { player.addListener(errorCapture(errorRef)) }
            post(main) {
                player.setVideoSurface(holder!!.surface)
                player.prepare()
                player.playWhenReady = true
            }
            val becameReady = waitForState(player, main, Player.STATE_READY, 30_000)
            if (!becameReady) {
                val chain = generateSequence(errorRef.get() as Throwable?) { it.cause }
                    .joinToString(" <- ") { "${it.javaClass.simpleName}: ${it.message}" }
                DeviceRunner.report("media-playback: never READY; state=${onMain(main) { player.playbackState }} chain=$chain")
            }
            assertTrue("the player becomes ready", becameReady)
            assertTrue("the duration is the manifest's", onMain(main) { player.duration } > 0)

            val random = java.util.Random(20261016)
            val targets = (0 until 20).map { random.nextInt(sealed.durationMs.toInt()).toLong() }.sorted()
            var landed = 0
            for (target in targets) {
                post(main) { player.seekTo(target) }
                if (waitForPosition(player, main, target, 10_000)) landed++
            }
            DeviceRunner.report("media-playback: seeks $landed/${targets.size} land within 2 s of the target")
            assertTrue("at least 17 of 20 seeks land", landed >= 17)
            assertTrue("the stream ends", waitForState(player, main, Player.STATE_ENDED, 60_000))
            assertTrue("no playback error", errorRef.get() == null)
            post(main) { player.release() }
            goodPlayable.close()

            // Corruption: one flipped byte on disk, a fresh reader — typed error, no crash.
            val badPlayable = playable(sealed, world.alice.keys, corrupt = true)
            val bad = onMain(main) { GhostPlayer.create(context, badPlayable, uri) }
            val badError = AtomicReference<PlaybackException?>()
            val badLatch = CountDownLatch(1)
            post(main) {
                bad.addListener(object : Player.Listener {
                    override fun onPlayerError(error: PlaybackException) {
                        badError.set(error)
                        badLatch.countDown()
                    }
                })
            }
            post(main) {
                bad.setVideoSurface(holder!!.surface)
                bad.prepare()
                bad.playWhenReady = true
            }
            assertTrue("the corrupt object ends with a typed error", badLatch.await(30, TimeUnit.SECONDS))
            val cause = badError.get()?.cause
            assertTrue(
                "the error is the corrupt reader failure, not a crash: $cause",
                cause is MediaPlayException.Corrupt,
            )
            DeviceRunner.report("media-playback: corruption ends typed ($cause)")
            post(main) { bad.release() }
            badPlayable.close()

            assertTrue(
                "FLAG_SECURE held",
                (activity.window.attributes.flags and WindowManager.LayoutParams.FLAG_SECURE) != 0,
            )
            DeviceRunner.report("media-playback: FLAG_SECURE on the media window")
        } finally {
            world.close()
        }
    }

    private fun errorCapture(ref: AtomicReference<PlaybackException?>): Player.Listener =
        object : Player.Listener {
            override fun onPlayerError(error: PlaybackException) {
                ref.set(error)
            }
        }

    private fun post(main: android.os.Handler, body: () -> Unit) {
        val done = CountDownLatch(1)
        main.post { body(); done.countDown() }
        assertTrue("posted", done.await(30, TimeUnit.SECONDS))
    }

    private fun waitForActivity(): MediaPlaybackActivity {
        var activity = MediaPlaybackRegistry.current
        var waited = 0
        while (activity == null && waited < 30_000) {
            Thread.sleep(200)
            waited += 200
            activity = MediaPlaybackRegistry.current
        }
        val a = activity ?: error("the media activity did not start")
        var waited2 = 0
        while (a.holder == null && waited2 < 30_000) {
            Thread.sleep(200)
            waited2 += 200
        }
        return a
    }

    /** Runs [body] on the main looper and answers its value (the player's thread). */
    private fun <T> onMain(main: android.os.Handler, body: () -> T): T {
        val ref = AtomicReference<T?>()
        val done = CountDownLatch(1)
        main.post { ref.set(body()); done.countDown() }
        assertTrue("posted to the main looper", done.await(30, TimeUnit.SECONDS))
        @Suppress("UNCHECKED_CAST")
        return ref.get() as T
    }

    private fun waitForState(player: ExoPlayer, main: android.os.Handler, state: Int, timeoutMs: Long): Boolean {
        val deadline = System.currentTimeMillis() + timeoutMs
        while (System.currentTimeMillis() < deadline) {
            val snap = onMain(main) { player.playbackState to player.playerError }
            if (snap.first == state) return true
            if (snap.second != null) return false
            Thread.sleep(100)
        }
        return onMain(main) { player.playbackState } == state
    }

    private fun waitForPosition(player: ExoPlayer, main: android.os.Handler, target: Long, timeoutMs: Long): Boolean {
        val deadline = System.currentTimeMillis() + timeoutMs
        while (System.currentTimeMillis() < deadline) {
            val snap = onMain(main) { player.playerError to player.currentPosition }
            if (snap.first != null) return false
            if (snap.second >= target && snap.second - target <= 2_000) return true
            Thread.sleep(100)
        }
        return false
    }
}
