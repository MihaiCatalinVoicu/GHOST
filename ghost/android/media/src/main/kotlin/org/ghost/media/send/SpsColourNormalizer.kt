package org.ghost.media.send

/**
 * Rewrites only the VUI colour description in avcC or Annex-B SPS NALs, in place and without
 * changing their length. This is a normalization step, not acceptance: the native fMP4 walker
 * validates the resulting stream and rejects any malformed SPS exactly as before.
 */
internal object SpsColourNormalizer {
    fun normalize(csd: ByteArray, colour: Triple<Int, Int, Int>): ByteArray {
        require(colour.first in 0..255 && colour.second in 0..255 && colour.third in 0..255)
        if (csd.isEmpty()) return csd.copyOf()
        val out = csd.copyOf()
        try {
            if (csd[0] == 1.toByte() && csd.size >= 8) {
                normalizeAvcC(out, colour)
            } else {
                normalizeAnnexB(out, colour)
            }
        } catch (e: RuntimeException) {
            // Not a CSD/SPS shape this normalizer understands; the native walker remains the gate.
            return csd.copyOf()
        }
        return out
    }

    private fun normalizeAvcC(out: ByteArray, colour: Triple<Int, Int, Int>) {
        var at = 5 // avcC's fixed prefix; numOfSPS is the low five bits of byte 5.
        val spsCount = out[at++].toInt() and 0x1f
        repeat(spsCount) {
            val size = readU16(out, at)
            at += 2
            val end = at + size
            require(end <= out.size) { "an SPS beyond avcC" }
            normalizeNal(out, at, end, colour)
            at = end
        }
    }

    /** Media3's avcC writer receives separate Annex-B csd-0/csd-1 buffers, not an avcC record. */
    private fun normalizeAnnexB(out: ByteArray, colour: Triple<Int, Int, Int>) {
        var at = 0
        var foundNal = false
        while (at < out.size) {
            val prefix = annexBPrefix(out, at) ?: throw IllegalArgumentException("CSD is not Annex-B")
            val start = at + prefix
            require(start < out.size) { "an empty Annex-B NAL" }
            val next = findAnnexBPrefix(out, start + 1) ?: out.size
            if (out[start].toInt() and 0x1f == 7) normalizeNal(out, start, next, colour)
            foundNal = true
            at = next
        }
        require(foundNal) { "an empty CSD" }
    }

    private fun findAnnexBPrefix(bytes: ByteArray, from: Int): Int? {
        for (at in from until bytes.size - 2) {
            if (annexBPrefix(bytes, at) != null) return at
        }
        return null
    }

    private fun annexBPrefix(bytes: ByteArray, at: Int): Int? = when {
        at + 3 < bytes.size && bytes[at] == 0.toByte() && bytes[at + 1] == 0.toByte() &&
            bytes[at + 2] == 0.toByte() && bytes[at + 3] == 1.toByte() -> 4
        at + 2 < bytes.size && bytes[at] == 0.toByte() && bytes[at + 1] == 0.toByte() &&
            bytes[at + 2] == 1.toByte() -> 3
        else -> null
    }

    private fun normalizeNal(out: ByteArray, start: Int, end: Int, colour: Triple<Int, Int, Int>) {
        val rbsp = Rbsp(out, start + 1, end)
        val bits = Bits(rbsp)
        bits.u(8) // profile_idc
        bits.u(8) // constraint flags + reserved bits
        bits.u(8) // level_idc
        bits.ue() // seq_parameter_set_id
        val profile = out[start + 1].toInt() and 0xff
        // profile_idc is the first RBSP byte, after the NAL header.
        if (profile == 100) {
            bits.ue() // chroma_format_idc
            bits.ue() // bit_depth_luma_minus8
            bits.ue() // bit_depth_chroma_minus8
            bits.u1() // qpprime_y_zero_transform_bypass
            if (bits.u1() == 1) {
                for (i in 0 until 8) if (bits.u1() == 1) scalingList(bits, if (i < 6) 16 else 64)
            }
        }
        bits.ue() // log2_max_frame_num_minus4
        when (bits.ue()) {
            0 -> bits.ue()
            1 -> {
                bits.u1()
                bits.se()
                bits.se()
                val cycle = bits.ue()
                repeat(cycle) { bits.se() }
            }
        }
        bits.ue() // max_num_ref_frames
        bits.u1() // gaps_in_frame_num_value_allowed_flag
        bits.ue() // pic_width_in_mbs_minus1
        bits.ue() // pic_height_in_map_units_minus1
        bits.u1() // frame_mbs_only_flag
        bits.u1() // direct_8x8_inference_flag
        bits.u1() // frame_cropping_flag
        if (bits.u1() == 0) return // no VUI, therefore no colour description to rewrite
        vui(bits, colour)
    }

    private fun vui(bits: Bits, colour: Triple<Int, Int, Int>) {
        if (bits.u1() == 1) {
            val aspect = bits.u(8)
            if (aspect == 255) {
                bits.u(16)
                bits.u(16)
            }
        }
        if (bits.u1() == 1) bits.u1() // overscan_appropriate_flag
        if (bits.u1() == 0) return // no video_signal_type, therefore no colour description
        bits.u(3) // video_format
        bits.u1() // video_full_range_flag
        if (bits.u1() == 0) return // no colour_description
        val positions = intArrayOf(bits.position, bits.position + 8, bits.position + 16)
        bits.u(8)
        bits.u(8)
        bits.u(8)
        bits.rbsp.write(positions[0], colour.first)
        bits.rbsp.write(positions[1], colour.second)
        bits.rbsp.write(positions[2], colour.third)
    }

    private fun scalingList(bits: Bits, size: Int) {
        var last = 8
        var next = 8
        repeat(size) {
            if (next != 0) {
                next = (last + bits.se() + 256) % 256
            }
            if (next != 0) last = next
        }
    }

    private fun readU16(bytes: ByteArray, at: Int): Int =
        ((bytes[at].toInt() and 0xff) shl 8) or (bytes[at + 1].toInt() and 0xff)

    /** The RBSP plus each byte's original NAL index, with emulation-prevention bytes removed. */
    private class Rbsp(val source: ByteArray, start: Int, end: Int) {
        val bytes: ByteArray
        private val original: IntArray

        init {
            require(start in 0 until end && end <= source.size) { "an invalid SPS range" }
            val data = ArrayList<Byte>()
            val indexes = ArrayList<Int>()
            var zeros = 0
            for (i in start until end) {
                val value = source[i].toInt() and 0xff
                if (zeros >= 2) {
                    if (value == 3) {
                        zeros = 0
                        continue
                    }
                    require(value > 2) { "a start-code prefix inside SPS" }
                }
                zeros = if (value == 0) zeros + 1 else 0
                data += value.toByte()
                indexes += i
            }
            bytes = ByteArray(data.size) { data[it] }
            original = IntArray(indexes.size) { indexes[it] }
        }

        fun write(bit: Int, value: Int) {
            for (i in 0 until 8) {
                val rbspBit = bit + i
                val byte = rbspBit / 8
                require(byte < original.size) { "a VUI colour description beyond SPS" }
                val shift = 7 - rbspBit % 8
                val mask = 1 shl shift
                val originalIndex = original[byte]
                source[originalIndex] = if (value and (1 shl (7 - i)) != 0) {
                    (source[originalIndex].toInt() or mask).toByte()
                } else {
                    (source[originalIndex].toInt() and mask.inv()).toByte()
                }
            }
        }
    }

    private class Bits(val rbsp: Rbsp) {
        var position = 0
            private set

        fun u1(): Int {
            val byte = rbsp.bytes.getOrNull(position / 8) ?: throw IllegalArgumentException("SPS ends early")
            val value = (byte.toInt() shr (7 - position % 8)) and 1
            position++
            return value
        }

        fun u(count: Int): Int {
            var value = 0
            repeat(count) { value = (value shl 1) or u1() }
            return value
        }

        fun ue(): Int {
            var zeros = 0
            while (u1() == 0) {
                zeros++
                require(zeros <= 31) { "an overlong Exp-Golomb code" }
            }
            val rest = u(zeros)
            return ((1L shl zeros) - 1L + rest).toInt()
        }

        fun se(): Int {
            val value = ue()
            return if (value % 2 == 1) (value + 1) / 2 else -(value / 2)
        }
    }
}
