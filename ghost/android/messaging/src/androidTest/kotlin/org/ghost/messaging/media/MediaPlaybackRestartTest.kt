package org.ghost.messaging.media

import android.content.Context
import org.ghost.crypto.bridge.MediaCrypto
import org.ghost.device.DeviceRunner
import org.ghost.media.store.CiphertextFiles
import org.ghost.media.store.MediaLimits
import org.ghost.media.store.NameSource
import org.ghost.media.store.NioCiphertextFileSystem
import org.ghost.messaging.device.DeviceWorld
import org.ghost.messaging.port.MediaReaders
import org.ghost.messaging.port.NativeMediaReaders
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File
import java.security.SecureRandom

/**
 * §15.8 item 3's host-driven restart run (Phase 11 design; slice S7), the playback half: part
 * one seals the golden, opens a reader, plays to a recorded position and writes the state to
 * the test app's files directory; the host script then kills the process
 * (`adb shell am force-stop`); part two — a second instrumentation run, a new process — reads
 * the state, reopens the object from its persisted `key_env` and fragment files and reads the
 * chunk at the recorded position. Instrumentation dies with the process, which is why the run
 * is host-driven (F9 §22.17 item 10's deferral; the JVM crash enumeration stays the upload
 * half's resume evidence).
 *
 * What this proves of FR-7.4's "resumes after a process restart": the readable state (the
 * wrapped `key_env`, the content-addressed ciphertext files) survives the kill untouched and
 * a fresh process serves the same bytes at the recorded position. The full two-device upload
 * half (the feeder resuming without re-storing an acknowledged blob) is the JVM SCN-MA/MB
 * crash enumerations' territory.
 */
class MediaPlaybackRestartTest {

    private class TestNames : NameSource {
        private val random = SecureRandom()
        override fun next16(): ByteArray = ByteArray(16).also { random.nextBytes(it) }
    }

    private fun context(): Context = DeviceRunner.current.targetContext

    private fun stateFile(context: Context): File = File(context.filesDir, "restart-state.bin")

    /** Seals the golden if the state file is absent; answers the parsed state either way. */
    private class State(
        val objectId: ByteArray,
        val keyEnv: ByteArray,
        val manifestBlob: ByteArray,
        val manifestHash: ByteArray,
        val classCode: Int,
        val contentLen: Long,
        val position: Int,
        val chunkIndex: Int,
        val chunkPrefix: ByteArray,
        val filesDirPath: String,
    )

    private fun ensureSealed(context: Context): State {
        val existing = stateFile(context)
        if (existing.exists()) return readState(existing)

        val world = DeviceWorld(context, "restart")
        try {
            world.alice.unlock()
            val handle = world.alice.keys.handleOrNull() ?: error("the DM context is open after unlock")
            // An image object: the restart run's subject is the reader's resume, and the kind
            // is incidental to it (F-S7-9's corrected reading — the video goldens are canonical
            // too, minus their `mfra`; the playback device test is their subject).
            val sandbox = org.ghost.media.sandbox.MediaSandbox(context)
            val source = context.assets.open("strip_orient1.jpg").use { it.readBytes() }
            val stripped = sandbox.stripImage(
                source, preview = false,
                maxBytes = org.ghost.media.send.MediaSendLimits.IMAGE_MAX_CONTENT,
            )
            assertTrue("strip: $stripped", stripped is org.ghost.media.sandbox.MediaSandbox.Result.Ok)
            val image = (stripped as org.ghost.media.sandbox.MediaSandbox.Result.Ok).bytes
            // The stripper's fixed point, checked cheaply before the seal: the sandbox's strip
            // of an already-canonical golden must answer bytes a JPEG decoder accepts (F-S7-9's
            // corrected reading — the strip output has never before been fed to a real check;
            // the walker's own verdict is the sealAppend below). The decoder here is the
            // test's probe on a GHOST-generated golden, not a recipient path (G-M3 scans
            // production sources only).
            val probe = android.graphics.BitmapFactory.decodeByteArray(image, 0, image.size)
            assertNotNull("the stripped golden is a decodable JPEG (the stripper's fixed point)", probe)
            DeviceRunner.report("media-restart: the stripped golden decodes (${probe!!.width}x${probe.height})")
            val strippedPreview = sandbox.stripImage(source, preview = true, maxBytes = 100_000)
            assertTrue("strip preview: $strippedPreview", strippedPreview is org.ghost.media.sandbox.MediaSandbox.Result.Ok)
            val preview = (strippedPreview as org.ghost.media.sandbox.MediaSandbox.Result.Ok).bytes
            val destId = ByteArray(16) { 0x43 }
            val begun = MediaCrypto.begin(handle, destId, MediaCrypto.Kind.IMAGE, viewOnce = false, maxClass = 10)
            assertTrue("sealBegin: $begun", begun is MediaCrypto.Begun.Ok)
            val sealer = (begun as MediaCrypto.Begun.Ok).sealer
            val appended = MediaCrypto.append(handle, sealer.id, image)
            assertTrue("sealAppend: $appended", appended is MediaCrypto.Appended.Ok)
            val finished = MediaCrypto.finish(handle, sealer.id, preview)
            assertTrue("sealFinish: $finished", finished is MediaCrypto.FinishedResult.Ok)
            val done = (finished as MediaCrypto.FinishedResult.Ok).finished

            val dir = File(context.filesDir, "restart-store").apply { deleteRecursively(); mkdirs() }
            val files = CiphertextFiles(File(dir, "m"), NioCiphertextFileSystem(), TestNames()).also { it.open() }
            val names = mutableListOf<ByteArray>()
            for (frag in done.chunks.flatMap { it.fragments }) {
                val written = files.write(files.newName(), frag, enforceFloor = false)
                assertTrue("fragment written: $written", written is org.ghost.media.store.WriteResult.Written)
                names += (written as org.ghost.media.store.WriteResult.Written).fileName
            }

            // Read chunk 0 in this process and record where "playback" stopped: mid-chunk.
            val readers = NativeMediaReaders(world.alice.keys)
            val opened = readers.open(
                MediaReaders.OpenSpec(
                    keyEnv = done.keyEnv,
                    role = MediaCrypto.Role.OUT,
                    destId = destId,
                    objectId = sealer.objectId,
                    manifestHash = done.manifestHash,
                    manifestBlob = done.manifestBlob,
                    kind = MediaCrypto.Kind.VIDEO,
                    viewOnce = false,
                    classCode = done.classCode,
                    readable = true,
                ),
            )
            assertTrue("readerOpen: $opened", opened is MediaReaders.Opened.Ok)
            val ok = opened as MediaReaders.Opened.Ok
            val assembled = ByteArray(4 * MediaLimits.FRAGMENT_BYTES)
            for (k in 0 until 4) {
                if (k >= done.chunks[0].fragments.size) break
                System.arraycopy(done.chunks[0].fragments[k], 0, assembled, k * MediaLimits.FRAGMENT_BYTES, MediaLimits.FRAGMENT_BYTES)
            }
            val chunked = readers.chunk(ok.reader, 0, assembled, validate = false)
            assertTrue("chunk 0 reads: $chunked", chunked is MediaReaders.Chunked.Ok)
            val plaintext = (chunked as MediaReaders.Chunked.Ok).content
            val position = plaintext.size / 2
            readers.close(ok.reader)

            val state = State(
                objectId = sealer.objectId,
                keyEnv = done.keyEnv,
                manifestBlob = done.manifestBlob,
                manifestHash = done.manifestHash,
                classCode = done.classCode,
                contentLen = ok.contentLen,
                position = position,
                chunkIndex = 0,
                // The bytes at the recorded position, for part two's comparison.
                chunkPrefix = plaintext.copyOfRange(position, minOf(position + 64, plaintext.size)),
                filesDirPath = dir.absolutePath,
            )
            writeState(existing, state, names)
            DeviceRunner.report("media-restart: part one sealed and recorded position ${state.position} of chunk 0")
            return state
        } finally {
            world.close()
        }
    }

    private fun writeState(file: File, state: State, fragmentNames: List<ByteArray>) {
        val out = java.io.DataOutputStream(java.io.BufferedOutputStream(file.outputStream()))
        out.use {
            it.writeInt(state.objectId.size)
            it.write(state.objectId)
            it.writeInt(state.keyEnv.size)
            it.write(state.keyEnv)
            it.writeInt(state.manifestBlob.size)
            it.write(state.manifestBlob)
            it.writeInt(state.manifestHash.size)
            it.write(state.manifestHash)
            it.writeInt(state.classCode)
            it.writeLong(state.contentLen)
            it.writeInt(state.position)
            it.writeInt(state.chunkIndex)
            it.writeInt(state.chunkPrefix.size)
            it.write(state.chunkPrefix)
            it.writeUTF(state.filesDirPath)
            it.writeInt(fragmentNames.size)
            for (name in fragmentNames) {
                it.writeInt(name.size)
                it.write(name)
            }
        }
    }

    private fun readState(file: File): State {
        val input = java.io.DataInputStream(java.io.BufferedInputStream(file.inputStream()))
        input.use {
            fun bytes(): ByteArray {
                val n = it.readInt()
                return ByteArray(n).also { b -> it.readFully(b) }
            }
            val objectId = bytes()
            val keyEnv = bytes()
            val manifestBlob = bytes()
            val manifestHash = bytes()
            val classCode = it.readInt()
            val contentLen = it.readLong()
            val position = it.readInt()
            val chunkIndex = it.readInt()
            val prefix = bytes()
            val dirPath = it.readUTF()
            val count = it.readInt()
            val names = (0 until count).map { bytes() }
            lastFragmentNames = names
            return State(objectId, keyEnv, manifestBlob, manifestHash, classCode, contentLen, position, chunkIndex, prefix, dirPath)
        }
    }

    private var lastFragmentNames: List<ByteArray> = emptyList()

    @Test
    fun partOneRecordsState() {
        System.loadLibrary("ghost_client_net")
        val state = ensureSealed(context())
        assertTrue(state.position > 0)
        DeviceRunner.report("media-restart: part one done; the host may kill the process now")
    }

    @Test
    fun partTwoResumesFromTheRecordedPosition() {
        System.loadLibrary("ghost_client_net")
        val context = context()
        val state = ensureSealed(context)
        val names = lastFragmentNames
        assertTrue("part one ran before the kill", names.isNotEmpty())

        // A fresh process: the DM context is rebuilt from the world's identity, and the reader
        // reopens from the persisted key_env — the shape §10.4's store promises.
        val world = DeviceWorld(context, "restart")
        try {
            world.alice.unlock()
            val readers = NativeMediaReaders(world.alice.keys)
            val opened = readers.open(
                MediaReaders.OpenSpec(
                    keyEnv = state.keyEnv,
                    role = MediaCrypto.Role.OUT,
                    destId = ByteArray(16) { 0x43 },
                    objectId = state.objectId,
                    manifestHash = state.manifestHash,
                    manifestBlob = state.manifestBlob,
                    kind = MediaCrypto.Kind.IMAGE,
                    viewOnce = false,
                    classCode = state.classCode,
                    readable = true,
                ),
            )
            assertTrue("readerOpen after the kill: $opened", opened is MediaReaders.Opened.Ok)
            val ok = opened as MediaReaders.Opened.Ok
            assertEquals("the content length is the manifest's", state.contentLen, ok.contentLen)

            val files = CiphertextFiles(File(state.filesDirPath, "m"), NioCiphertextFileSystem(), TestNames()).also { it.open() }
            val assembled = ByteArray(4 * MediaLimits.FRAGMENT_BYTES)
            for (k in 0 until 4) {
                if (k >= names.size) break
                val frag = files.read(names[k])
                System.arraycopy(frag, 0, assembled, k * MediaLimits.FRAGMENT_BYTES, MediaLimits.FRAGMENT_BYTES)
            }
            val chunked = readers.chunk(ok.reader, state.chunkIndex, assembled, validate = false)
            assertTrue("chunk ${state.chunkIndex} reads after the kill: $chunked", chunked is MediaReaders.Chunked.Ok)
            val plaintext = (chunked as MediaReaders.Chunked.Ok).content
            assertTrue("playback resumes at the recorded position", state.position < plaintext.size)
            val resumed = plaintext.copyOfRange(state.position, minOf(state.position + state.chunkPrefix.size, plaintext.size))
            assertTrue(
                "the bytes at the recorded position are the ones part one read",
                resumed.copyOf(state.chunkPrefix.size).contentEquals(state.chunkPrefix),
            )
            readers.close(ok.reader)
            DeviceRunner.report("media-restart: part two resumed at position ${state.position} after the kill")
        } finally {
            world.close()
        }
    }
}
