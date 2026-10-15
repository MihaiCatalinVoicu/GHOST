package org.ghost.media.send

import android.media.MediaCodec
import android.media.MediaFormat
import java.nio.ByteBuffer

/**
 * The decode-half of "the preview comes from the output" (§6.2, S0-19) and of the colour
 * calibration (§8.3 point 5(d)): an H.264 access unit (with the stream's `avcC`) decoded by a
 * `MediaCodec` decoder **into buffers, never a surface**, converted to RGBA with [Yuv420] and the
 * matrix the calibration chose. Runs on the media worker thread (§13.7); nothing here logs.
 */
object FrameProbe {

    /**
     * Decodes the first access unit of an H.264 stream whose parameter sets are [avcC] (the
     * `avcC` box's bytes, as carried in the format's csd) **into the raw YUV planes** — the
     * colour-matrix conversion is the caller's (the preview uses the output's label; the
     * calibration compares both). Returns null on any decoder failure — the caller then sends
     * without a preview (§6.2: `preview_len = 0`).
     */
    fun decodeSample(avcC: ByteArray, sample: ByteArray): Yuv420.Frame? {
        val format = MediaFormat.createVideoFormat(MediaFormat.MIMETYPE_VIDEO_AVC, 1_280, 720)
        format.setByteBuffer("csd-0", ByteBuffer.wrap(avcC))
        val decoder = try {
            MediaCodec.createDecoderByType(MediaFormat.MIMETYPE_VIDEO_AVC)
        } catch (e: java.io.IOException) {
            // No H.264 decoder on the device: no preview, never a failed send (§6.2).
            return null
        }
        return try {
            decoder.configure(format, null, null, 0)
            decoder.start()
            val inputId = decoder.dequeueInputBuffer(10_000)
            if (inputId < 0) return null
            decoder.getInputBuffer(inputId)!!.apply {
                clear()
                put(sample)
            }
            decoder.queueInputBuffer(inputId, 0, sample.size, 0, 0)
            val info = MediaCodec.BufferInfo()
            val outputId = decoder.dequeueOutputBuffer(info, 100_000)
            if (outputId < 0) return null
            val image = decoder.getOutputImage(outputId) ?: return null
            val frame = try {
                val width = image.width
                val height = image.height
                val y = image.planes[0]
                val u = image.planes[1]
                val v = image.planes[2]
                Yuv420.Frame(
                    width = width,
                    height = height,
                    yPlane = y.buffer.duplicate().let { buf ->
                        val b = ByteArray(y.rowStride * height)
                        buf.get(b, 0, minOf(b.size, buf.remaining()))
                        b
                    },
                    yStride = y.rowStride,
                    uPlane = u.buffer.duplicate().let { buf ->
                        val b = ByteArray(u.rowStride * ((height + 1) / 2))
                        buf.get(b, 0, minOf(b.size, buf.remaining()))
                        b
                    },
                    uStride = u.rowStride,
                    vPlane = v.buffer.duplicate().let { buf ->
                        val b = ByteArray(v.rowStride * ((height + 1) / 2))
                        buf.get(b, 0, minOf(b.size, buf.remaining()))
                        b
                    },
                    vStride = v.rowStride,
                )
            } finally {
                image.close()
                decoder.releaseOutputBuffer(outputId, false)
            }
            decoder.stop()
            frame
        } catch (e: java.lang.IllegalStateException) {
            // configure/start/stop out of order, or a codec failure surfacing as a state error:
            // the preview is optional, the send is not (§6.2).
            null
        } finally {
            try {
                decoder.release()
            } catch (e: IllegalStateException) {
                // Already released: nothing left to do.
            }
        }
    }

    /**
     * The first video access unit and the `avcC` of a `FragmentedMp4Muxer` output (the
     * calibration export): a small strict reader over the box graph, for this one shape only —
     * `moov` → `trak`(`vide`) → `stsd` → `avc1` → `avcC`, and the first `moof`'s first video
     * `trun` pointing into its `mdat`. Returns null when the shape is not there.
     */
    internal fun firstVideoSample(stream: ByteArray): Pair<ByteArray, ByteArray>? {
        val top = boxes(stream, 0, stream.size)
        val moov = top.firstOrNull { it.type == "moov" } ?: return null
        val avcC = videoAvcC(stream, moov) ?: return null
        val moof = top.firstOrNull { it.type == "moof" } ?: return null
        val mdat = top.firstOrNull { it.type == "mdat" && it.offset > moof.offset } ?: return null
        val sample = firstVideoTrunSample(stream, moof) ?: return null
        if (sample.offset < mdat.offset + 8 || sample.offset + sample.size > mdat.offset + mdat.size) {
            return null
        }
        return Pair(avcC, stream.copyOfRange(sample.offset, sample.offset + sample.size))
    }

    private class Box(val type: String, val offset: Int, val size: Int) {
        val body: Int get() = offset + 8
    }

    private fun u32(b: ByteArray, at: Int): Int =
        (b[at].toInt() and 0xff shl 24) or (b[at + 1].toInt() and 0xff shl 16) or
            (b[at + 2].toInt() and 0xff shl 8) or (b[at + 3].toInt() and 0xff)

    private fun u64(b: ByteArray, at: Int): Long {
        var v = 0L
        for (i in 0 until 8) v = (v shl 8) or (b[at + i].toLong() and 0xff)
        return v
    }

    private fun boxes(b: ByteArray, start: Int, end: Int): List<Box> {
        val out = ArrayList<Box>()
        var at = start
        while (at + 8 <= end) {
            val size = u32(b, at)
            if (size < 8 || at + size > end) return out
            out += Box(String(b, at + 4, 4, Charsets.ISO_8859_1), at, size)
            at += size
        }
        return out
    }

    private fun videoAvcC(b: ByteArray, moov: Box): ByteArray? {
        for (trak in boxes(b, moov.body, moov.offset + moov.size).filter { it.type == "trak" }) {
            val mdia = boxes(b, trak.body, trak.offset + trak.size).firstOrNull { it.type == "mdia" }
                ?: continue
            val hdlr = boxes(b, mdia.body, mdia.offset + mdia.size).firstOrNull { it.type == "hdlr" }
                ?: continue
            if (String(b, hdlr.body + 8, 4, Charsets.ISO_8859_1) != "vide") continue
            val minf = boxes(b, mdia.body, mdia.offset + mdia.size).firstOrNull { it.type == "minf" }
                ?: continue
            val stbl = boxes(b, minf.body, minf.offset + minf.size).firstOrNull { it.type == "stbl" }
                ?: continue
            val stsd = boxes(b, stbl.body, stbl.offset + stbl.size).firstOrNull { it.type == "stsd" }
                ?: continue
            for (entry in boxes(b, stsd.body + 8, stsd.offset + stsd.size)) {
                val avcC = boxes(b, entry.body, entry.offset + entry.size).firstOrNull { it.type == "avcC" }
                    ?: continue
                return b.copyOfRange(avcC.body, avcC.offset + avcC.size)
            }
        }
        return null
    }

    private class SampleRef(val offset: Int, val size: Int)

    private fun firstVideoTrunSample(b: ByteArray, moof: Box): SampleRef? {
        for (traf in boxes(b, moof.body, moof.offset + moof.size).filter { it.type == "traf" }) {
            val parts = boxes(b, traf.body, traf.offset + traf.size)
            val tfhd = parts.firstOrNull { it.type == "tfhd" } ?: continue
            // The first video traf is the one whose trun has key-frame first-sample flags; the
            // calibration clip's first fragment starts with a sync sample either way, so the
            // first traf with a trun that has sizes is taken.
            val trun = parts.firstOrNull { it.type == "trun" } ?: continue
            val flags = ((b[tfhd.body + 1].toInt() and 0xff) shl 16) or
                ((b[tfhd.body + 2].toInt() and 0xff) shl 8) or (b[tfhd.body + 3].toInt() and 0xff)
            if (flags and 0x1 == 0) continue
            val moofStart = u64(b, tfhd.body + 8)
            val trunFlags = ((b[trun.body + 1].toInt() and 0xff) shl 16) or
                ((b[trun.body + 2].toInt() and 0xff) shl 8) or (b[trun.body + 3].toInt() and 0xff)
            val count = u32(b, trun.body + 4)
            if (count < 1) continue
            var at = trun.body + 8
            var dataOffset = 0L
            if (trunFlags and 0x1 != 0) {
                dataOffset = u32(b, at).toLong() and 0xffff_ffffL
                at += 4
            }
            if (trunFlags and 0x4 != 0) at += 4
            if (trunFlags and 0x100 != 0) at += 4 // duration
            if (trunFlags and 0x200 == 0) continue // no per-sample size
            val size = u32(b, at)
            return SampleRef((moofStart + dataOffset).toInt(), size)
        }
        return null
    }
}
