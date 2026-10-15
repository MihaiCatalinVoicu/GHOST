package org.ghost.media.send

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The SEI filter of §8.3 point 3: payload types 0, 1, 6 survive, 4, 5 and anything else are
 * dropped; a NAL unit with mixed payloads is dropped when **any** payload is outside the set;
 * emulation prevention and the 0xFF extension byte are handled (§22.2 row A4's cases).
 */
class AvcTest {

    /** One SEI NAL unit (type 6) with [types] as payloads, rbsp trailing bits appended. */
    private fun sei(vararg types: Int): ByteArray {
        val body = java.io.ByteArrayOutputStream()
        for (t in types) {
            var rest = t
            while (rest >= 255) {
                body.write(255)
                rest -= 255
            }
            body.write(rest) // payloadType
            body.write(0) // payloadSize = 0
        }
        body.write(0x80)
        val payload = body.toByteArray()
        return byteArrayOf(0x06) + payload
    }

    /** One non-SEI NAL unit of [type] with a few payload bytes. */
    private fun nal(type: Int, vararg payload: Int): ByteArray =
        byteArrayOf(type.toByte()) + payload.map { it.toByte() }.toByteArray()

    @Test
    fun nonSeiNalUnitsAreAlwaysKept() {
        assertTrue(Avc.keepSei(nal(1, 0x88, 0x99)))
        assertTrue(Avc.keepSei(nal(5, 0x11)))
        assertTrue(Avc.keepSei(nal(7, 0x42, 0x00, 0x1f)))
    }

    @Test
    fun allowedSeiPayloadsSurvive() {
        assertTrue(Avc.keepSei(sei(0)))
        assertTrue(Avc.keepSei(sei(1)))
        assertTrue(Avc.keepSei(sei(6)))
        assertTrue(Avc.keepSei(sei(0, 1, 6)))
    }

    @Test
    fun userDataAndOtherPayloadsAreDropped() {
        assertFalse(Avc.keepSei(sei(4)))
        assertFalse(Avc.keepSei(sei(5)))
        assertFalse(Avc.keepSei(sei(0, 4)))
        assertFalse(Avc.keepSei(sei(137)))
        assertFalse(Avc.keepSei(ByteArray(0)))
        assertFalse(Avc.keepSei(byteArrayOf(0x06))) // no payload at all: not parseable
    }

    @Test
    fun payloadTypesAt255UseTheExtensionByte() {
        // type 260 = 255 + 5: parses as one payload of 260, outside the allowed set.
        assertFalse(Avc.keepSei(sei(260)))
        // 255 alone = 255 + 0: also outside.
        assertFalse(Avc.keepSei(sei(255)))
    }

    @Test
    fun emulationPreventionBytesAreRemovedBeforeThePayloadWalk() {
        // payload type 1, then 00 00 03 00 (emulation prevention inside), size 0, trailing 0x80.
        val nal = byteArrayOf(0x06, 0x01, 0x00, 0x00, 0x03, 0x00, 0x00, 0x80.toByte())
        assertTrue(Avc.keepSei(nal))
        // The same shape with payload type 4: dropped.
        val bad = byteArrayOf(0x06, 0x04, 0x00, 0x00, 0x03, 0x00, 0x00, 0x80.toByte())
        assertFalse(Avc.keepSei(bad))
    }

    @Test
    fun filterSampleDropsSeiAndKeepsFraming() {
        val avccSample = avcc(nal(7, 0x42), sei(5), nal(1, 0xAA.toInt()))
        val filtered = Avc.filterSample(avccSample)
        assertEquals(listOf(7, 1), Avc.split(filtered, annexB = false).map { it[0].toInt() and 0x1f })
        // The framing is preserved: 4-byte lengths, recomputable.
        assertEquals((4 + 2) + (4 + 2), filtered.size)

        val annexB = annexB(nal(6, 0x04, 0x00, 0x80.toInt()), nal(1, 0x55))
        val kept = Avc.filterSample(annexB)
        assertArrayEquals(byteArrayOf(0, 0, 0, 1, 0x01, 0x55), kept)
    }

    private fun avcc(vararg nals: ByteArray): ByteArray {
        val out = java.io.ByteArrayOutputStream()
        for (nal in nals) {
            out.write(byteArrayOf(
                (nal.size ushr 24).toByte(), (nal.size ushr 16).toByte(),
                (nal.size ushr 8).toByte(), nal.size.toByte(),
            ))
            out.write(nal)
        }
        return out.toByteArray()
    }

    private fun annexB(vararg nals: ByteArray): ByteArray {
        val out = java.io.ByteArrayOutputStream()
        for (nal in nals) {
            out.write(byteArrayOf(0, 0, 0, 1))
            out.write(nal)
        }
        return out.toByteArray()
    }
}
