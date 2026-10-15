package org.ghost.media.send

import java.io.ByteArrayOutputStream

/**
 * The H.264 sample handling of Phase 11 design §8.3 point 3: each video sample (one access unit)
 * is split into NAL units, and an SEI NAL unit survives only if **every** payload type it carries
 * is a buffering period (0), picture timing (1) or recovery point (6) — the payloads a decoder
 * needs to schedule; user-data SEI (4, 5 — where encoders write version strings) and every other
 * payload are dropped before the sample reaches the muxer. V-M12 measured what real encoders emit
 * (the emulators' software encoders emit no SEI at all; the filter dropped all 360 user-data SEI
 * of a transmuxed source).
 *
 * Pure functions, no allocation beyond the output (the spike this productionizes is
 * `ghost/spikes/media-s0` `GhostMuxer.filterAvc`/`seiPayloadTypes`, measured on the emulators).
 * [GhostMuxer] calls [filterSample] per video sample; the unit tests cover both annex-B and
 * AVCC-length-prefixed inputs and the emulation-prevention discipline.
 */
object Avc {

    /**
     * Splits [sample] into NAL units and drops SEI with payloads outside {0, 1, 6}. The output
     * keeps the input's framing (annex-B start codes or 4-byte AVCC lengths) so the muxer sees a
     * well-formed sample of the same shape; a sample that parses into no NAL unit is returned
     * unchanged-empty (the walker would refuse it, and a zero-length sample must not be written).
     */
    fun filterSample(sample: ByteArray): ByteArray {
        val annexB = isAnnexB(sample)
        val nals = split(sample, annexB)
        if (nals.isEmpty()) return ByteArray(0)
        val out = ByteArrayOutputStream(sample.size)
        for (nal in nals) {
            if (!keepSei(nal)) continue
            if (annexB) out.write(byteArrayOf(0, 0, 0, 1)) else {
                out.write(byteArrayOf(
                    (nal.size ushr 24).toByte(), (nal.size ushr 16).toByte(),
                    (nal.size ushr 8).toByte(), nal.size.toByte(),
                ))
            }
            out.write(nal)
        }
        return out.toByteArray()
    }

    /**
     * The SEI decision for one NAL unit: true unless it is an SEI (type 6) whose payload types
     * include anything but 0, 1 or 6. A non-SEI NAL unit is always kept; an SEI whose payload
     * types cannot be parsed is dropped (fail closed).
     */
    fun keepSei(nal: ByteArray): Boolean {
        if (nal.isEmpty()) return false
        if ((nal[0].toInt() and 0x1f) != 6) return true
        val payloads = try {
            seiPayloadTypes(nal)
        } catch (e: IllegalArgumentException) {
            return false
        }
        return payloads.isNotEmpty() && payloads.all { it in ALLOWED_SEI }
    }

    /** The SEI payload types that survive the filter (§8.3 point 3). */
    private val ALLOWED_SEI: Set<Int> = setOf(0, 1, 6)

    /** True when [sample] starts with an annex-B start code (00 00 01 or 00 00 00 01). */
    internal fun isAnnexB(sample: ByteArray): Boolean =
        sample.size >= 4 &&
            sample[0] == 0.toByte() && sample[1] == 0.toByte() &&
            (sample[2] == 1.toByte() || (sample[2] == 0.toByte() && sample[3] == 1.toByte()))

    /** The NAL units of [sample], framed annex-B when [annexB], else 4-byte length-prefixed. */
    internal fun split(sample: ByteArray, annexB: Boolean): List<ByteArray> {
        if (annexB) {
            val starts = ArrayList<Pair<Int, Int>>() // (start code offset, NAL offset)
            var i = 0
            while (i + 3 <= sample.size) {
                if (sample[i] == 0.toByte() && sample[i + 1] == 0.toByte() && sample[i + 2] == 1.toByte()) {
                    val codeStart = if (i > 0 && sample[i - 1] == 0.toByte()) i - 1 else i
                    starts += Pair(codeStart, i + 3)
                    i += 3
                } else i++
            }
            return starts.mapIndexed { k, s ->
                val end = if (k + 1 < starts.size) starts[k + 1].first else sample.size
                sample.copyOfRange(s.second, end)
            }.filter { it.isNotEmpty() }
        }
        val out = ArrayList<ByteArray>()
        var at = 0
        while (at + 4 <= sample.size) {
            val len = ((sample[at].toInt() and 0xff) shl 24) or ((sample[at + 1].toInt() and 0xff) shl 16) or
                ((sample[at + 2].toInt() and 0xff) shl 8) or (sample[at + 3].toInt() and 0xff)
            at += 4
            if (len < 0 || at + len > sample.size) break
            out += sample.copyOfRange(at, at + len)
            at += len
        }
        return out.filter { it.isNotEmpty() }
    }

    /**
     * The payload types of one SEI NAL unit (type 6): emulation prevention bytes removed first,
     * then the payloadType/payloadSize byte-pair walk of H.264 §7.3.2.3.1. The trailing
     * `rbsp_trailing_bits` (0x80) ends the walk. Throws [IllegalArgumentException] when the walk
     * overruns — the caller drops such a NAL unit.
     */
    internal fun seiPayloadTypes(nal: ByteArray): List<Int> {
        val rbsp = ByteArrayOutputStream()
        var zeros = 0
        for (i in 1 until nal.size) {
            val x = nal[i].toInt() and 0xff
            if (zeros >= 2 && x == 3) {
                zeros = 0
                continue
            }
            rbsp.write(x)
            zeros = if (x == 0) zeros + 1 else 0
        }
        val p = rbsp.toByteArray()
        val out = ArrayList<Int>()
        var at = 0
        while (at < p.size) {
            if (p.size - at == 1 && (p[at].toInt() and 0xff) == 0x80) break
            var type = 0
            while (at < p.size && (p[at].toInt() and 0xff) == 0xff) {
                type += 255
                at++
            }
            if (at >= p.size) break
            type += p[at].toInt() and 0xff
            at++
            var size = 0
            while (at < p.size && (p[at].toInt() and 0xff) == 0xff) {
                size += 255
                at++
            }
            if (at >= p.size) break
            size += p[at].toInt() and 0xff
            at++
            out += type
            at += size
        }
        if (out.isEmpty()) throw IllegalArgumentException("no SEI payload")
        return out
    }
}
