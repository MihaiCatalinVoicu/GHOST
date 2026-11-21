package org.ghost.media.send

import org.junit.Assert.assertFalse
import org.junit.Assert.assertArrayEquals
import org.junit.Test

class SpsColourNormalizerTest {
    @Test
    fun theCapturedSpsColourIsRewrittenOnce() {
        val original = hex("0164001fffe100116764001facb402802dd35050605078b17501000468ee0d8b")
        val normalized = SpsColourNormalizer.normalize(original, Triple(5, 1, 6))
        assertFalse(normalized.contentEquals(original))
        assertArrayEquals(normalized, SpsColourNormalizer.normalize(normalized, Triple(5, 1, 6)))
    }

    @Test
    fun theAnnexBCsdZeroUsedByMedia3IsRewrittenWithoutChangingItsShape() {
        val original = hex("000000016764001facb402802dd35050605078b1750100")
        val expected = hex("000000016764001facb402802dd35050106078b1750100")
        val normalized = SpsColourNormalizer.normalize(original, Triple(5, 1, 6))
        assertArrayEquals(expected, normalized)
        assertArrayEquals(normalized, SpsColourNormalizer.normalize(normalized, Triple(5, 1, 6)))
    }

    @Test
    fun formatBuilderCarriesTheNormalizedAvcC() {
        val original = hex("0164001fffe100116764001facb402802dd35050605078b17501000468ee0d8b")
        val normalized = SpsColourNormalizer.normalize(original, Triple(5, 1, 6))
        val format = androidx.media3.common.Format.Builder()
            .setSampleMimeType(androidx.media3.common.MimeTypes.VIDEO_H264)
            .setInitializationData(listOf(original))
            .build()
        val carried = format.buildUpon().setInitializationData(listOf(normalized)).build()
        assertArrayEquals(normalized, carried.initializationData.single())
    }

    @Test
    fun aTruncatedAvcCIsLeftForTheNativeGateWithoutCrashing() {
        val truncated = hex("0164001fffe1ffff67")
        assertArrayEquals(truncated, SpsColourNormalizer.normalize(truncated, Triple(5, 1, 6)))
    }

    private fun hex(value: String): ByteArray = ByteArray(value.length / 2) {
        value.substring(it * 2, it * 2 + 2).toInt(16).toByte()
    }
}
