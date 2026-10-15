package org.ghost.media.send

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * The ladder of D29, pinned by S1: `protocol/test-vectors/media_object.txt` `[ladder]` holds the
 * 18 sizes the Rust `geometry::image_target`/`preview_target` produce (§22.2 row 7a: S1 rounds
 * half up, in integers, and "the Kotlin `STRIP_IMAGE` of S5, which runs in the isolated process
 * without the native library, must produce exactly these sizes"). This test parses that file, so
 * the two implementations cannot drift apart.
 */
class MediaGeometryTest {

    private val ladder: File = File("../../protocol/test-vectors/media_object.txt").canonicalFile

    @Test
    fun thePinnedLadderReplaysExactly() {
        val lines = ladder.readLines()
        val start = lines.indexOfFirst { it.trim() == "[ladder]" }
        assertTrue("the vector file has a [ladder] section", start >= 0)
        var checked = 0
        for (line in lines.drop(start + 1)) {
            if (line.isBlank() || line.trimStart().startsWith("[")) break
            val match = Regex("""(image|preview)\[(\d+)x(\d+)\] = (\d+)x(\d+)""").matchEntire(line.trim())
            assertTrue("ladder line is a pinned size: $line", match != null)
            val kind = match!!.groupValues[1]
            val sw = match.groupValues[2].toInt()
            val sh = match.groupValues[3].toInt()
            val tw = match.groupValues[4].toInt()
            val th = match.groupValues[5].toInt()
            val got = if (kind == "image") {
                MediaGeometry.imageTarget(sw, sh)
            } else {
                MediaGeometry.previewTarget(sw, sh)
            }
            assertEquals("$line: width", tw, got.first)
            assertEquals("$line: height", th, got.second)
            checked++
        }
        assertEquals("the file's ladder entries all replayed", 18, checked)
    }

    @Test
    fun longEdgeIsTheLargestLadderStepNotAboveTheSource() {
        assertEquals(2_048, MediaGeometry.imageTarget(4_032, 3_024).first)
        assertEquals(2_048, MediaGeometry.imageTarget(2_048, 2_048).first)
        assertEquals(1_024, MediaGeometry.imageTarget(1_024, 1_024).first)
        assertEquals(1_024, MediaGeometry.imageTarget(2_047, 1_151).first)
        assertEquals(512, MediaGeometry.imageTarget(1_000, 1_001).first)
        assertEquals(512, MediaGeometry.imageTarget(100, 50).first)
    }

    @Test
    fun shortEdgeIsAMultipleOf16NeverAboveTheLongEdge() {
        val cases = listOf(
            Pair(4_032, 3_024) to Pair(2_048, 1_536),
            Pair(2_400, 1_080) to Pair(2_048, 928),
            Pair(513, 300) to Pair(512, 304),
            Pair(5_000, 10) to Pair(2_048, 16),
            Pair(10, 5_000) to Pair(16, 2_048),
        )
        for ((source, want) in cases) {
            val got = MediaGeometry.imageTarget(source.first, source.second)
            assertEquals(want, got)
            assertEquals(0, got.second % 16)
            assertTrue(got.second >= 16)
            assertTrue(maxOf(got.first, got.second) <= maxOf(want.first, want.second))
        }
    }

    @Test
    fun portraitSourcesStayPortrait() {
        assertEquals(Pair(1_536, 2_048), MediaGeometry.imageTarget(3_024, 4_032))
        assertEquals(Pair(176, 320), MediaGeometry.previewTarget(720, 1_280))
        assertEquals(Pair(320, 176), MediaGeometry.previewTarget(1_280, 720))
    }

    @Test
    fun aRemainderOfExactlyHalfRoundsUp() {
        // 512 · 43 / (16 · 64) = 21.5: half up gives 22 (352), half to even or down would give 21
        // (336) — S1 pinned half up (§22.2 row 7a).
        assertEquals(Pair(512, 352), MediaGeometry.imageTarget(64, 43))
    }
}
