package org.ghost.media.send

import org.ghost.media.store.MediaLimits
import org.ghost.media.store.MediaWorld
import org.ghost.media.store.PreparingFiles
import org.ghost.media.store.WriteResult
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import java.io.ByteArrayOutputStream
import java.io.File
import java.nio.ByteBuffer

/**
 * `SealingChannel` over the real `CiphertextFiles` on a temporary directory, with a fake sealer
 * that honours the M2/M3 contract (append completes chunks; finish seals the buffered tail as the
 * padding chunk and returns the manifest). The properties:
 *
 *  1. the plaintext the sealer receives is exactly the `tfdt`-inserted stream (the golden — so
 *     the bytes sealed are the bytes the S0 goldens record, chunk by 262 128);
 *  2. every fragment and the manifest land as whole 64 KiB files under reserved names, in order;
 *  3. failures (a walker refusal, a truncated stream, a full disk) surface as the typed
 *     [SealException] and abort the sealer.
 */
class SealingChannelTest {

    private val goldens = File("../../protocol/test-vectors/media-goldens/media3-1.11.1").canonicalFile

    /** The fake sealer: accepts arbitrary pieces, completes one group per full chunk, tails in finish. */
    private class FakeSealer(
        private val refuseAfterGroups: Int = -1,
        private val failDiskAt: Int = -1,
    ) : StreamSealer {
        val received = ByteArrayOutputStream()
        var finished = false
        var aborted = false
        var next = 0
        private var consumed = 0L

        override fun append(plaintext: ByteArray): List<SealedFragmentGroup> {
            received.write(plaintext)
            consumed += plaintext.size
            val completed = (consumed / MediaLimits.CHUNK_PLAINTEXT).toInt()
            val out = ArrayList<SealedFragmentGroup>()
            while (next < completed) {
                if (next == refuseAfterGroups) throw SealException.NonCanonical()
                out += group(next++)
            }
            return out
        }

        override fun finish(preview: ByteArray): SealedObject {
            finished = true
            val hasTail = consumed % MediaLimits.CHUNK_PLAINTEXT != 0L
            if (next == refuseAfterGroups) throw SealException.NonCanonical()
            val finishGroups = if (hasTail) listOf(group(next++)) else emptyList()
            val manifest = ByteArray(MediaLimits.FRAGMENT_BYTES) { 0x4D }
            return SealedObject(
                classCode = 0,
                contentLen = next * MediaLimits.CHUNK_PLAINTEXT.toLong() - 7,
                width = 1_280,
                height = 720,
                durationMs = 1_000,
                keyEnv = ByteArray(60) { 0x4B },
                manifestBlob = manifest,
                manifestHash = ByteArray(32) { 0x48 },
                preview = preview,
                finishGroups = finishGroups,
            )
        }

        override fun abort() {
            aborted = true
        }

        private fun group(index: Int) = SealedFragmentGroup(
            index = index,
            fragments = List(4) { k -> ByteArray(MediaLimits.FRAGMENT_BYTES) { ((it + k * 13 + index) and 0xFF).toByte() } },
            hashes = List(4) { k -> ByteArray(32) { ((it + k + index) and 0xFF).toByte() } },
        )
    }

    /** Feeds [bytes] through the channel in [cut] byte pieces; returns the channel after close. */
    private fun feed(channel: SealingChannel, bytes: ByteArray, cut: Int) {
        var at = 0
        while (at < bytes.size) {
            val end = minOf(bytes.size, at + cut)
            channel.write(ByteBuffer.wrap(bytes, at, end - at))
            at = end
        }
        channel.close()
    }

    @Test
    fun theGoldenStreamSealsIntoOrderedWholeFiles() {
        val golden = File(goldens, "api35-emulator/quad_land.fmp4").readBytes()
        val stripped = stripTfdt(golden)
        MediaWorld().use { world ->
            val sealer = FakeSealer()
            val channel = SealingChannel.of(sealer, world.files, world.preparing)
            feed(channel, stripped, cut = 64 * 1024)
            val result = channel.finish(preview = ByteArray(0))

            // The sealer saw exactly the tfdt-inserted stream = the golden, in 262 128-byte
            // pieces (the last piece is the short tail; the Rust sealer pads it internally).
            assertArrayEquals(golden, sealer.received.toByteArray())
            assertTrue(sealer.finished)

            // F fragments + the manifest, every file whole and named; F is the chunk count the
            // sealed stream implies.
            val chunks = (sealer.received.size() + MediaLimits.CHUNK_PLAINTEXT - 1) / MediaLimits.CHUNK_PLAINTEXT
            assertEquals(chunks * 4, result.fragmentHashes.size)
            assertEquals(result.fragmentFiles.size, result.fragmentHashes.size)
            for (file in result.fragmentFiles + result.manifestFile) {
                val bytes = world.files.read(file)
                assertEquals(MediaLimits.FRAGMENT_BYTES, bytes.size)
            }
            assertEquals(MediaLimits.FRAGMENT_BYTES, result.manifestBlob.size)

            // The names were reserved before the writes and are still held for the reconcile.
            val snapshot = world.preparing.snapshot()
            for (file in result.fragmentFiles + result.manifestFile) {
                assertTrue(snapshot.contains(org.ghost.media.store.hex(file)))
            }
            channel.releaseNames()
            assertTrue(world.preparing.isEmpty)
        }
    }

    @Test
    fun byteByByteFeedsGiveTheSameFiles() {
        val golden = File(goldens, "api29-emulator/quad_land.fmp4").readBytes()
        val stripped = stripTfdt(golden)
        val hashes = mutableListOf<ByteArray>()
        MediaWorld().use { world ->
            val sealer = FakeSealer()
            val channel = SealingChannel.of(sealer, world.files, world.preparing)
            feed(channel, stripped, cut = 1)
            val result = channel.finish(ByteArray(0))
            hashes += result.fragmentHashes
            channel.releaseNames()
        }
        MediaWorld().use { world ->
            val sealer = FakeSealer()
            val channel = SealingChannel.of(sealer, world.files, world.preparing)
            feed(channel, stripped, cut = 999_983)
            val result = channel.finish(ByteArray(0))
            assertEquals(hashes.size, result.fragmentHashes.size)
            for (i in hashes.indices) assertArrayEquals(hashes[i], result.fragmentHashes[i])
            channel.releaseNames()
        }
    }

    @Test
    fun aSealerRefusalAbortsWithTheTypedError() {
        val golden = File(goldens, "api35-emulator/land1080p60.fmp4").readBytes()
        val stripped = stripTfdt(golden)
        MediaWorld().use { world ->
            val sealer = FakeSealer(refuseAfterGroups = 1)
            val channel = SealingChannel.of(sealer, world.files, world.preparing)
            try {
                feed(channel, stripped, cut = 512 * 1024)
                fail("the refusal surfaced")
            } catch (e: SealException.NonCanonical) {
                // the typed failure
            }
            channel.abort()
            assertTrue(sealer.aborted)
            channel.releaseNames()
            assertTrue(world.preparing.isEmpty)
        }
    }

    @Test
    fun aTruncatedStreamRefusesAtClose() {
        MediaWorld().use { world ->
            val sealer = FakeSealer()
            val channel = SealingChannel.of(sealer, world.files, world.preparing)
            channel.write(ByteBuffer.wrap(byteArrayOf(0, 0, 0, 24, 'f'.code.toByte(), 't'.code.toByte(), 'y'.code.toByte(), 'p'.code.toByte(), 1, 2)))
            try {
                channel.close()
                fail("a truncated stream refused")
            } catch (e: SealException.NonCanonical) {
                // the typed failure
            }
            channel.abort()
            channel.releaseNames()
            assertTrue(world.preparing.isEmpty)
        }
    }

    @Test
    fun aFullDiskIsTheStorageFailure() {
        MediaWorld(freeFloorBytes = Long.MAX_VALUE).use { world ->
            // Simulate the disk failure with a store whose write throws DISK_FULL; the golden's
            // first bytes carry at least one whole chunk past the box graph, so a write happens.
            val golden = File(goldens, "api35-emulator/land1080p60.fmp4").readBytes()
            val sealer = FakeSealer()
            val failing = object : org.ghost.media.store.CiphertextFileSystem by world.disk {
                override fun writeNew(file: File, bytes: ByteArray) {
                    throw org.ghost.media.store.CiphertextFilesException(
                        org.ghost.media.store.CiphertextFilesError.DISK_FULL, "test", null,
                    )
                }
            }
            val files = org.ghost.media.store.CiphertextFiles(File(world.dir, "m2"), failing, world.names, 0L).also { it.open() }
            val channel = SealingChannel.of(sealer, files, world.preparing)
            try {
                feed(channel, stripTfdt(golden), cut = 512 * 1024)
                fail("the disk failure surfaced")
            } catch (e: SealException.Storage) {
                // the typed failure
            }
            channel.abort()
            channel.releaseNames()
            assertTrue(world.preparing.isEmpty)
        }
    }

    // ---------------------------------------------------------------- the test stripper

    private class Box(val type: String, val offset: Int, val size: Int)

    private fun topBoxes(bytes: ByteArray): List<Box> {
        val out = ArrayList<Box>()
        var at = 0
        while (at + 8 <= bytes.size) {
            val size = u32(bytes, at)
            out += Box(String(bytes, at + 4, 4, Charsets.ISO_8859_1), at, size)
            at += size
        }
        return out
    }

    private fun children(bytes: ByteArray, parent: Box): List<Box> {
        val out = ArrayList<Box>()
        var at = parent.offset + 8
        val end = parent.offset + parent.size
        while (at + 8 <= end) {
            val size = u32(bytes, at)
            out += Box(String(bytes, at + 4, 4, Charsets.ISO_8859_1), at, size)
            at += size
        }
        return out
    }

    private fun stripTfdt(stream: ByteArray): ByteArray {
        val out = ByteArrayOutputStream()
        for (top in topBoxes(stream)) {
            if (top.type != "moof") {
                out.write(stream, top.offset, top.size)
                continue
            }
            val kids = children(stream, top)
            val trafCount = kids.count { it.type == "traf" }
            val body = ByteArrayOutputStream()
            for (kid in kids) {
                if (kid.type != "traf") {
                    body.write(stream, kid.offset, kid.size)
                    continue
                }
                val tb = ByteArrayOutputStream()
                for (part in children(stream, kid)) {
                    if (part.type == "tfdt") continue
                    val bytes = stream.copyOfRange(part.offset, part.offset + part.size)
                    if (part.type == "trun") {
                        put32(bytes, 16, u32(bytes, 16) - 20 * trafCount)
                    }
                    tb.write(bytes)
                }
                body.write(box("traf", tb.toByteArray()))
            }
            out.write(box("moof", body.toByteArray()))
        }
        return out.toByteArray()
    }

    private fun box(type: String, body: ByteArray): ByteArray =
        ByteBuffer.allocate(8 + body.size).putInt(8 + body.size)
            .put(type.toByteArray(Charsets.ISO_8859_1)).put(body).array()

    private fun u32(bytes: ByteArray, at: Int): Int =
        (bytes[at].toInt() and 0xff shl 24) or (bytes[at + 1].toInt() and 0xff shl 16) or
            (bytes[at + 2].toInt() and 0xff shl 8) or (bytes[at + 3].toInt() and 0xff)

    private fun put32(bytes: ByteArray, at: Int, value: Int) {
        bytes[at] = (value ushr 24).toByte()
        bytes[at + 1] = (value ushr 16).toByte()
        bytes[at + 2] = (value ushr 8).toByte()
        bytes[at + 3] = value.toByte()
    }
}
