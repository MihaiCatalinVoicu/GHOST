package org.ghost.media.send

import java.io.ByteArrayOutputStream
import java.nio.ByteBuffer

/**
 * The `tfdt` insertion of Phase 11 design §8.3: `FragmentedMp4Muxer` 1.11.1 writes no `tfdt`
 * (corrected by S0, V-M2/S0-2), and without one the `mfra` the Rust sealer appends would have 0
 * entries and a seek would stamp samples with stale decode times. So, **before any byte reaches
 * `sealAppend`**, this layer rewrites the muxer's stream: after the `tfhd` of every `traf` it
 * inserts a version-1 `tfdt` whose value is the running sum of that track's `trun` sample durations
 * (in the track's `mdhd` timescale — which is also the `tfdt` timescale), adds 20 B per inserted
 * box to the `moof` and `traf` sizes and to every `trun` `data_offset` of that `moof`, and rewrites
 * each `tfhd` `base_data_offset` (absolute, flag 0x1) by the bytes inserted before it. It buffers
 * one `moof` at a time (the profile bounds a `moof` to 256 KiB) and passes `mdat` through.
 *
 * The spike this productionizes is `ghost/spikes/media-s0` `Mp4Mini.insertTfdt` (measured against
 * the emulators' encoders, S0 V-M2); the difference is strictness: a box the canonical profile
 * refuses (a `largesize` header, a truncated box) fails the export here, at the sender, instead of
 * sealing a stream the recipient's walker would refuse.
 *
 * Nothing here allocates per sample: a `moof` is one byte array (≤ 256 KiB by the profile bound,
 * which [GhostMuxer] enforces on the samples before the writer buffers them), and the `mdat` body
 * streams through [Mp4Stream]. No logging, no clock (§13.1).
 */
object Mp4Tfdt {

    /** A refusal of the box stream: the export fails with the typed [reason]. */
    class MalformedStream(val reason: String) : IllegalStateException(reason)

    /** One ISO-BMFF box of the parsed stream. */
    private class Box(val type: String, val offset: Int, val size: Int, val header: Int)

    /**
     * The incremental transformer: feed [offer] the bytes `GhostMuxer`'s writer emits and it calls
     * [sink] with the rewritten stream, one piece at a time. [sealedBytes] counts everything
     * emitted — the caller (the sealer) needs the exact stream length.
     */
    class Mp4Stream(private val sink: (ByteArray) -> Unit) {
        /** Everything not yet recognised as a complete box. */
        private var pending = ByteArray(0)

        /** Bytes emitted so far: the file offset the next top-level box starts at. */
        var sealedBytes: Long = 0
            private set

        /** Running decode time per track id (the sum of that track's `trun` durations so far). */
        private val decodeTime = HashMap<Int, Long>()

        /** Feeds [data]; may call [sink] zero or more times. Throws [MalformedStream]. */
        fun offer(data: ByteArray, offset: Int = 0, length: Int = data.size) {
            pending = pending + data.copyOfRange(offset, offset + length)
            var rest = pending
            while (true) {
                val box = firstBox(rest) ?: break
                if (box.size == rest.size || box.size < rest.size) {
                    emit(rest, box)
                    rest = rest.copyOfRange(box.size, rest.size)
                } else break
            }
            pending = rest
        }

        /**
         * The end of the export: any leftover is a truncated box (the writer never ends mid-box),
         * which refuses the stream.
         */
        fun finish() {
            if (pending.isNotEmpty()) throw MalformedStream("truncated box of ${pending.size} B at $sealedBytes")
        }

        private fun emit(stream: ByteArray, box: Box) {
            if (box.type == "moof") {
                emit(box("moof", rewriteMoof(stream, box)))
            } else {
                emit(stream.copyOfRange(box.offset, box.offset + box.size))
            }
        }

        private fun emit(bytes: ByteArray) {
            sealedBytes += bytes.size
            sink(bytes)
        }

        /**
         * Rewrites one `moof`: grows it by `20 · trafCount`, shifts its `trun` data offsets and
         * its `tfhd` base offsets to the new absolute position, and appends the `tfdt`s.
         */
        private fun rewriteMoof(stream: ByteArray, moof: Box): ByteArray {
            val kids = boxes(stream, moof.offset + moof.header, moof.offset + moof.size)
            val trafCount = kids.count { it.type == "traf" }
            if (trafCount == 0) throw MalformedStream("moof without traf")
            val newMoofOffset = sealedBytes
            val body = ByteArrayOutputStream()
            for (kid in kids) {
                if (kid.type != "traf") {
                    body.write(stream, kid.offset, kid.size)
                    continue
                }
                body.write(box("traf", rewriteTraf(stream, kid, trafCount, newMoofOffset)))
            }
            return body.toByteArray()
        }

        private fun rewriteTraf(stream: ByteArray, traf: Box, trafCount: Int, newMoofOffset: Long): ByteArray {
            val parts = boxes(stream, traf.offset + traf.header, traf.offset + traf.size)
            if (parts.firstOrNull()?.type != "tfhd") throw MalformedStream("traf without leading tfhd")
            val out = ByteArrayOutputStream()
            var trackId = 0
            var durationSum = 0L
            for (part in parts) {
                val bytes = stream.copyOfRange(part.offset, part.offset + part.size)
                when (part.type) {
                    "tfhd" -> {
                        trackId = u32(bytes, 12)
                        val flags = u24(bytes, 9)
                        if (flags and 0x1 != 0) {
                            // base_data_offset: absolute; the moof moves by the bytes the tfdts
                            // before it add. Flag 0x1 is the writer's shape (1.11.1 writes flags
                            // 0x000001, nothing else); another shape is not the stream this layer
                            // rewrites.
                            put64(bytes, 16, newMoofOffset)
                        } else {
                            throw MalformedStream("tfhd without base_data_offset")
                        }
                        out.write(bytes)
                        out.write(tfdt(decodeTime[trackId] ?: 0L))
                    }
                    "trun" -> {
                        durationSum += rewriteTrun(bytes, 20 * trafCount)
                        out.write(bytes)
                    }
                    else -> out.write(bytes)
                }
            }
            decodeTime[trackId] = (decodeTime[trackId] ?: 0L) + durationSum
            return out.toByteArray()
        }

        /** Shifts the `trun` data offset by [shift]; returns the summed sample durations. */
        private fun rewriteTrun(bytes: ByteArray, shift: Int): Long {
            val flags = u24(bytes, 9)
            val count = u32(bytes, 12)
            var at = 16
            if (flags and 0x1 != 0) {
                put32(bytes, at, u32(bytes, at) + shift)
                at += 4
            } else throw MalformedStream("trun without data offset")
            if (flags and 0x4 != 0) at += 4
            var sum = 0L
            for (i in 0 until count) {
                if (flags and 0x100 != 0) {
                    sum += u32(bytes, at).toLong() and 0xffff_ffffL
                    at += 4
                } else throw MalformedStream("trun without per-sample duration")
                if (flags and 0x200 != 0) at += 4
                if (flags and 0x400 != 0) at += 4
                if (flags and 0x800 != 0) at += 4
            }
            if (at != bytes.size) throw MalformedStream("trun fields overrun the box")
            return sum
        }
    }

    /** The whole-stream form, for tests and callers that hold the bytes (the emulator suites). */
    fun insertTfdt(stream: ByteArray): ByteArray {
        val out = ByteArrayOutputStream()
        val mp4 = Mp4Stream { bytes -> out.write(bytes) }
        mp4.offer(stream)
        mp4.finish()
        return out.toByteArray()
    }

    /** The box the writer never writes: version 1, flags 0, one u64 decode time. */
    internal fun tfdt(decodeTime: Long): ByteArray =
        ByteBuffer.allocate(20)
            .putInt(20)
            .put("tfdt".toByteArray(Charsets.ISO_8859_1))
            .putInt(1 shl 24)
            .putLong(decodeTime)
            .array()

    internal fun box(type: String, body: ByteArray): ByteArray =
        ByteBuffer.allocate(8 + body.size)
            .putInt(8 + body.size)
            .put(type.toByteArray(Charsets.ISO_8859_1))
            .put(body)
            .array()

    /**
     * The first complete box of [bytes], or null when fewer than a header's worth is buffered or
     * the declared size exceeds what is buffered. A `largesize` header or a size past the stream
     * refuses the stream — the canonical profile admits neither (§22.2 row 9(g)).
     */
    private fun firstBox(bytes: ByteArray): Box? {
        if (bytes.size < 8) return null
        val size = u32(bytes, 0).toLong() and 0xffff_ffffL
        val type = String(bytes, 4, 4, Charsets.ISO_8859_1)
        if (size == 1L) throw MalformedStream("largesize box $type refused")
        if (size == 0L) throw MalformedStream("to-end box $type refused")
        if (size < 8 || size > Int.MAX_VALUE) throw MalformedStream("box $type of $size B")
        if (bytes.size < size) return null
        return Box(type, 0, size.toInt(), 8)
    }

    private fun boxes(bytes: ByteArray, start: Int, end: Int): List<Box> {
        val out = ArrayList<Box>()
        var at = start
        while (at + 8 <= end) {
            val size = u32(bytes, at).toLong() and 0xffff_ffffL
            if (size == 1L || size == 0L || size < 8 || size > Int.MAX_VALUE) {
                throw MalformedStream("malformed child box at $at")
            }
            val type = String(bytes, at + 4, 4, Charsets.ISO_8859_1)
            if (at + size > end) throw MalformedStream("child box $type overruns its parent")
            out += Box(type, at, size.toInt(), 8)
            at += size.toInt()
        }
        if (at != end) throw MalformedStream("box tail of ${end - at} B")
        return out
    }

    private fun u24(bytes: ByteArray, at: Int): Int =
        (bytes[at].toInt() and 0xff shl 16) or (bytes[at + 1].toInt() and 0xff shl 8) or (bytes[at + 2].toInt() and 0xff)

    private fun u32(bytes: ByteArray, at: Int): Int =
        (bytes[at].toInt() and 0xff shl 24) or (bytes[at + 1].toInt() and 0xff shl 16) or
            (bytes[at + 2].toInt() and 0xff shl 8) or (bytes[at + 3].toInt() and 0xff)

    private fun put32(bytes: ByteArray, at: Int, value: Int) {
        bytes[at] = (value ushr 24).toByte()
        bytes[at + 1] = (value ushr 16).toByte()
        bytes[at + 2] = (value ushr 8).toByte()
        bytes[at + 3] = value.toByte()
    }

    private fun put64(bytes: ByteArray, at: Int, value: Long) {
        for (i in 0 until 8) bytes[at + i] = (value ushr (56 - 8 * i)).toByte()
    }
}
