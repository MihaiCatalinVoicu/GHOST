package org.ghost.app.media

import android.content.Context
import org.ghost.media.sandbox.MediaSandbox
import org.ghost.media.send.GhostTranscoder
import org.ghost.media.send.GhostVideoExport
import org.ghost.media.send.SandboxDecoder
import org.ghost.media.send.SandboxStripper
import org.ghost.media.store.CiphertextFiles
import org.ghost.media.send.MediaSendLimits
import org.ghost.media.store.NameSource
import org.ghost.media.store.NioCiphertextFileSystem
import org.ghost.media.store.PreparingFiles
import org.ghost.messaging.engine.MediaPipelinePorts
import java.io.File
import java.security.SecureRandom

/**
 * The sender pipeline's device wiring (Phase 11 design §13.7; slice S5): the one place the
 * `MediaPipelinePorts` are built — the ciphertext store under the app's `noBackupFilesDir/m`
 * (§10.4; random 16-byte names from the OS CSPRNG, the free-space floor of §6.6), the sandbox
 * client (one fresh isolated process per request, §9.2) and `GhostTranscoder` with the bundled
 * calibration clip (§8.3 point 5(d)) and the no-images loader ([NoBitmapsLoader], whose
 * interface names the content-handle package G-DM1 bans from `:media`, F-S5-3).
 *
 * The sealer factory and the JPEG canonicaliser are built inside `:messaging`
 * ([org.ghost.messaging.engine.MediaEngineSupport]), so the DM context's handle never reaches
 * `:app`. Where the calibration asset is absent the transcoder still constructs; `calibrate()`
 * then answers `COLOUR_UNVERIFIED` and video sending stays off (F-S5-6(b)) — images are
 * unaffected.
 */
object MediaWiring {

    /** The pipeline ports, or null when the store directory cannot be prepared. */
    fun pipelinePorts(context: Context, noBackupDir: File, readers: org.ghost.messaging.port.MediaReaders): MediaPipelinePorts? {
        val store = File(noBackupDir, "m")
        val files = try {
            // The store's write floor is §7.5's MEDIA_FREE_FLOOR (256 MiB, the default): ingest
            // below it consumes without writing. The send-side refusal uses the smaller
            // 3 × F × 64 KiB pre-check over freeSpace() and is not this constant (F-S6-2).
            CiphertextFiles(
                store,
                NioCiphertextFileSystem(),
                SecureNames,
            ).also { it.open() }
        } catch (e: RuntimeException) {
            return null
        }
        val calibration = try {
            context.assets.open("media/calibration.mp4").use { it.readBytes() }
        } catch (e: java.io.IOException) {
            null
        }
        val transcoder = GhostTranscoder(context, calibration, NoBitmapsLoader)
        val sandbox = MediaSandbox(context)
        return MediaPipelinePorts(
            files = files,
            preparing = PreparingFiles(),
            stripper = SandboxStripper(sandbox),
            video = GhostVideoExport(context, transcoder),
            readers = readers,
            decoder = SandboxDecoder(sandbox),
        )
    }

    /** The store's name source: 16 random bytes from the OS CSPRNG ([SecureRandom]). */
    private object SecureNames : NameSource {
        private val random = SecureRandom()
        override fun next16(): ByteArray = random.generateSeed(16).also {
            // generateSeed draws from the OS; fall back to nextBytes if a provider disagrees.
            if (it.size != 16) random.nextBytes(it)
        }
    }
}
