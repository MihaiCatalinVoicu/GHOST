package org.ghost.media.send

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import java.io.ByteArrayOutputStream
import java.io.File

/**
 * The `tfdt` insertion against the S0 goldens (§8.3: every golden was recorded with `tfdt` and
 * `mfra` included, each checked by the S0 spike's profile checker). Two properties per golden, both
 * on both API levels' files:
 *
 *  1. the golden's own `tfdt`s are exactly the running sums of their tracks' `trun` durations —
 *     so the value this layer writes is the value the recorded stream carries;
 *  2. stripping every `tfdt` (shrinking `moof`/`traf` sizes and shifting `trun` data offsets back)
 *     and re-inserting reproduces the golden **byte for byte** — so this Kotlin layer is the exact
 *     inverse of what the S0 spike did to build the goldens, over every fragment count and both
 *     track layouts the emulators produced.
 */
class Mp4TfdtTest {

    private val goldens = File("../../protocol/test-vectors/media-goldens/media3-1.11.1").canonicalFile

    private val fmp4s = listOf(
        "api35-emulator/quad_land.fmp4",
        "api35-emulator/quad_port.fmp4",
        "api35-emulator/quad_rot90.fmp4",
        "api35-emulator/quad_rot180.fmp4",
        "api35-emulator/quad_rot270.fmp4",
        "api35-emulator/quad_noaudio.fmp4",
        "api35-emulator/land1080p60.fmp4",
        "api29-emulator/quad_land.fmp4",
        "api29-emulator/quad_port.fmp4",
        "api29-emulator/quad_noaudio.fmp4",
        "api29-emulator/land1080p60.fmp4",
    )

    @Test
    fun goldensTfdtValuesAreTheRunningSums() {
        for (name in fmp4s) {
            val stream = File(goldens, name).readBytes()
            val running = HashMap<Int, Long>()
            for (moof in topBoxes(stream).filter { it.type == "moof" }) {
                for (traf in children(stream, moof).filter { it.type == "traf" }) {
                    val parts = children(stream, traf)
                    val tfhd = parts.first { it.type == "tfhd" }
                    val track = u32(stream, tfhd.offset + 12)
                    val tfdt = parts.first { it.type == "tfdt" }
                    assertEquals(20, tfdt.size)
                    assertEquals(1 shl 24, u32(stream, tfdt.offset + 8))
                    assertEquals(
                        "$name track $track tfdt is the running sum",
                        running[track] ?: 0L,
                        u64(stream, tfdt.offset + 12),
                    )
                    var sum = 0L
                    for (trun in parts.filter { it.type == "trun" }) {
                        val flags = u24(stream, trun.offset + 9)
                        val count = u32(stream, trun.offset + 12)
                        var at = trun.offset + 16
                        if (flags and 0x1 != 0) at += 4
                        if (flags and 0x4 != 0) at += 4
                        for (i in 0 until count) {
                            if (flags and 0x100 != 0) {
                                sum += u32(stream, at).toLong() and 0xffff_ffffL
                                at += 4
                            }
                            if (flags and 0x200 != 0) at += 4
                            if (flags and 0x400 != 0) at += 4
                            if (flags and 0x800 != 0) at += 4
                        }
                    }
                    running[track] = (running[track] ?: 0L) + sum
                }
            }
            assertTrue("$name walked at least one moof", running.isNotEmpty())
        }
    }

    @Test
    fun stripThenReinsertReproducesTheGoldenByteForByte() {
        for (name in fmp4s) {
            val golden = File(goldens, name).readBytes()
            val stripped = stripTfdt(golden)
            val rebuilt = try {
                Mp4Tfdt.insertTfdt(stripped)
            } catch (e: Mp4Tfdt.MalformedStream) {
                fail("$name: $e")
                ByteArray(0)
            }
            assertArrayEquals("$name: reinserted stream equals the golden", golden, rebuilt)
        }
    }

    @Test
    fun feedsSplitAcrossArbitraryBoundariesGiveTheSameStream() {
        val golden = File(goldens, "api35-emulator/land1080p60.fmp4").readBytes()
        val stripped = stripTfdt(golden)
        val whole = Mp4Tfdt.insertTfdt(stripped)
        val piecewise = ByteArrayOutputStream()
        val stream = Mp4Tfdt.Mp4Stream { bytes -> piecewise.write(bytes) }
        var at = 0
        // Odd sizes on purpose: 7, then 13, then 1 024 097-byte steps cut the box graph anywhere.
        val cuts = listOf(7, 13) + generateSequence(0) { it + 1_024_097 }.takeWhile { it < stripped.size }.toList()
        for (cut in cuts) {
            val end = minOf(stripped.size, cut)
            if (end <= at) continue
            stream.offer(stripped, at, end - at)
            at = end
        }
        if (at < stripped.size) stream.offer(stripped, at, stripped.size - at)
        stream.finish()
        assertEquals(whole.size.toLong(), stream.sealedBytes)
        assertArrayEquals(whole, piecewise.toByteArray())
    }

    @Test
    fun aTruncatedTailRefuses() {
        val golden = File(goldens, "api35-emulator/quad_land.fmp4").readBytes()
        val cut = golden.size - 10
        try {
            Mp4Tfdt.insertTfdt(golden.copyOfRange(0, cut))
            fail("a truncated stream refused")
        } catch (e: Mp4Tfdt.MalformedStream) {
            assertTrue(e.reason.contains("truncated"))
        }
    }

    // ---------------------------------------------------------------- test box graph

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

    /** Removes every `tfdt`, shrinking `moof`/`traf` and shifting every `trun` data offset back. */
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
            var removed = 0
            for (kid in kids) {
                when (kid.type) {
                    "traf" -> {
                        val parts = children(stream, kid)
                        val tb = ByteArrayOutputStream()
                        for (part in parts) {
                            if (part.type == "tfdt") {
                                removed++
                                continue
                            }
                            val bytes = stream.copyOfRange(part.offset, part.offset + part.size)
                            if (part.type == "trun") {
                                // Every trun's data offset grew by all of this moof's tfdts: the
                                // mdat moved by 20·trafCount while the moof start did not move.
                                val flags = u24(bytes, 9)
                                if (flags and 0x1 != 0) put32(bytes, 16, u32(bytes, 16) - 20 * trafCount)
                            }
                            tb.write(bytes)
                        }
                        body.write(box("traf", tb.toByteArray()))
                    }
                    else -> body.write(stream, kid.offset, kid.size)
                }
            }
            assertEquals("one tfdt per traf removed", trafCount, removed)
            out.write(box("moof", body.toByteArray()))
        }
        return out.toByteArray()
    }

    private fun box(type: String, body: ByteArray): ByteArray =
        java.nio.ByteBuffer.allocate(8 + body.size)
            .putInt(8 + body.size)
            .put(type.toByteArray(Charsets.ISO_8859_1))
            .put(body)
            .array()

    private fun u24(bytes: ByteArray, at: Int): Int =
        (bytes[at].toInt() and 0xff shl 16) or (bytes[at + 1].toInt() and 0xff shl 8) or (bytes[at + 2].toInt() and 0xff)

    private fun u32(bytes: ByteArray, at: Int): Int =
        (bytes[at].toInt() and 0xff shl 24) or (bytes[at + 1].toInt() and 0xff shl 16) or
            (bytes[at + 2].toInt() and 0xff shl 8) or (bytes[at + 3].toInt() and 0xff)

    private fun u64(bytes: ByteArray, at: Int): Long {
        var v = 0L
        for (i in 0 until 8) v = (v shl 8) or (bytes[at + i].toLong() and 0xff)
        return v
    }

    private fun put32(bytes: ByteArray, at: Int, value: Int) {
        bytes[at] = (value ushr 24).toByte()
        bytes[at + 1] = (value ushr 16).toByte()
        bytes[at + 2] = (value ushr 8).toByte()
        bytes[at + 3] = value.toByte()
    }
}
