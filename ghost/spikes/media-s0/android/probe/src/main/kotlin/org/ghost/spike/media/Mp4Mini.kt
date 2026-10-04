package org.ghost.spike.media

import java.io.ByteArrayOutputStream
import java.nio.ByteBuffer

/**
 * The GHOST `mfra` of design §8.3 built on the device over a `FragmentedMp4Muxer` output: one
 * `tfra` (version 1) for the video track, one entry per `moof` (time = that `moof`'s `tfdt` for the
 * track, offset = the `moof`'s file offset, traf/trun/sample numbers 1), then `mfro`. The Rust twin
 * is `mp4::build_mfra` (host checks).
 */
object Mp4Mini {
    class Box(val type: String, val offset: Int, val size: Int, val header: Int)

    fun boxes(b: ByteArray, start: Int, end: Int): List<Box> {
        val out = ArrayList<Box>()
        var p = start
        while (p + 8 <= end) {
            var size = ByteBuffer.wrap(b, p, 4).int.toLong() and 0xffffffffL
            val type = String(b, p + 4, 4, Charsets.ISO_8859_1)
            var header = 8
            if (size == 1L) {
                size = ByteBuffer.wrap(b, p + 8, 8).long
                header = 16
            } else if (size == 0L) {
                size = (end - p).toLong()
            }
            if (size < header || p + size > end) break
            out += Box(type, p, size.toInt(), header)
            p += size.toInt()
        }
        return out
    }

    fun child(b: ByteArray, parent: Box, type: String): Box? = boxes(b, parent.offset + parent.header, parent.offset + parent.size).firstOrNull { it.type == type }

    fun videoTrackId(b: ByteArray): Int {
        val moov = boxes(b, 0, b.size).first { it.type == "moov" }
        for (trak in boxes(b, moov.offset + 8, moov.offset + moov.size).filter { it.type == "trak" }) {
            val tkhd = child(b, trak, "tkhd")!!
            val v = b[tkhd.offset + 8].toInt()
            val id = ByteBuffer.wrap(b, tkhd.offset + 8 + if (v == 1) 20 else 12, 4).int
            val mdia = child(b, trak, "mdia")!!
            val hdlr = child(b, mdia, "hdlr")!!
            if (String(b, hdlr.offset + 8 + 8, 4, Charsets.ISO_8859_1) == "vide") return id
        }
        throw IllegalStateException("no video track")
    }

    /** `(moof offset, tfdt of the track)` for every `moof`. */
    fun fragmentTimes(b: ByteArray, track: Int): List<Pair<Long, Long>> {
        val out = ArrayList<Pair<Long, Long>>()
        for (moof in boxes(b, 0, b.size).filter { it.type == "moof" }) {
            for (traf in boxes(b, moof.offset + 8, moof.offset + moof.size).filter { it.type == "traf" }) {
                val tfhd = child(b, traf, "tfhd") ?: continue
                if (ByteBuffer.wrap(b, tfhd.offset + 12, 4).int != track) continue
                val tfdt = child(b, traf, "tfdt") ?: continue
                val v = b[tfdt.offset + 8].toInt()
                val t = if (v == 1) ByteBuffer.wrap(b, tfdt.offset + 12, 8).long else (ByteBuffer.wrap(b, tfdt.offset + 12, 4).int.toLong() and 0xffffffffL)
                out += Pair(moof.offset.toLong(), t)
            }
        }
        return out
    }

    /**
     * `(moof offset, decode time)` from the running sum of the track's `trun` sample durations:
     * FragmentedMp4Muxer 1.11.1 writes no `tfdt` (traf = tfhd + trun only, `Boxes.traf`), so this
     * is the only source of a fragment's decode time.
     */
    fun fragmentTimesFromDurations(b: ByteArray, track: Int): List<Pair<Long, Long>> {
        val out = ArrayList<Pair<Long, Long>>()
        var running = 0L
        for (moof in boxes(b, 0, b.size).filter { it.type == "moof" }) {
            for (traf in boxes(b, moof.offset + 8, moof.offset + moof.size).filter { it.type == "traf" }) {
                val tfhd = child(b, traf, "tfhd") ?: continue
                if (ByteBuffer.wrap(b, tfhd.offset + 12, 4).int != track) continue
                val tfhdFlags = ByteBuffer.wrap(b, tfhd.offset + 8, 4).int and 0xffffff
                var o = tfhd.offset + 16
                if (tfhdFlags and 0x1 != 0) o += 8
                if (tfhdFlags and 0x2 != 0) o += 4
                val defaultDuration = if (tfhdFlags and 0x8 != 0) ByteBuffer.wrap(b, o, 4).int.toLong() else 0L
                out += Pair(moof.offset.toLong(), running)
                for (trun in boxes(b, traf.offset + 8, traf.offset + traf.size).filter { it.type == "trun" }) {
                    val flags = ByteBuffer.wrap(b, trun.offset + 8, 4).int and 0xffffff
                    val count = ByteBuffer.wrap(b, trun.offset + 12, 4).int
                    var p = trun.offset + 16
                    if (flags and 0x1 != 0) p += 4
                    if (flags and 0x4 != 0) p += 4
                    for (i in 0 until count) {
                        if (flags and 0x100 != 0) { running += ByteBuffer.wrap(b, p, 4).int.toLong() and 0xffffffffL; p += 4 } else running += defaultDuration
                        if (flags and 0x200 != 0) p += 4
                        if (flags and 0x400 != 0) p += 4
                        if (flags and 0x800 != 0) p += 4
                    }
                }
            }
        }
        return out
    }

    /** [useTfdt] = the design text as written (entries from `tfdt`); false = the corrected rule. */
    fun buildMfra(b: ByteArray, useTfdt: Boolean = true): ByteArray {
        val track = videoTrackId(b)
        val entries = if (useTfdt) fragmentTimes(b, track) else fragmentTimesFromDurations(b, track)
        val tfra = ByteArrayOutputStream()
        fun u32(o: ByteArrayOutputStream, v: Int) = o.write(ByteBuffer.allocate(4).putInt(v).array())
        fun u64(o: ByteArrayOutputStream, v: Long) = o.write(ByteBuffer.allocate(8).putLong(v).array())
        u32(tfra, 1 shl 24) // version 1, flags 0
        u32(tfra, track)
        u32(tfra, 0) // 1-byte traf, trun, sample numbers
        u32(tfra, entries.size)
        for ((off, time) in entries) {
            u64(tfra, time)
            u64(tfra, off)
            tfra.write(byteArrayOf(1, 1, 1))
        }
        val tfraBox = box("tfra", tfra.toByteArray())
        val mfraSize = 8 + tfraBox.size + 16
        val mfro = ByteArrayOutputStream()
        u32(mfro, 0)
        u32(mfro, mfraSize)
        return box("mfra", tfraBox + box("mfro", mfro.toByteArray()))
    }

    /**
     * The fix under test for V-M2: inserts a version-1 `tfdt` (the running decode time) after the
     * `tfhd` of every `traf`, growing `traf` and `moof` and moving every `trun` data offset by the
     * bytes added to the `moof` (the offsets are relative to the `moof` start, tfhd flag 0x1 with
     * base_data_offset = moof start, which is also rewritten).
     */
    fun insertTfdt(b: ByteArray): ByteArray {
        val out = java.io.ByteArrayOutputStream(b.size + 4096)
        val tracks = HashMap<Int, Long>() // running decode time per track
        for (top in boxes(b, 0, b.size)) {
            if (top.type != "moof") {
                out.write(b, top.offset, top.size)
                continue
            }
            val kids = boxes(b, top.offset + 8, top.offset + top.size)
            val trafs = kids.count { it.type == "traf" }
            val grow = 20 * trafs
            val newMoofStart = out.size().toLong()
            val body = java.io.ByteArrayOutputStream()
            for (k in kids) {
                if (k.type != "traf") {
                    body.write(b, k.offset, k.size)
                    continue
                }
                val tk = boxes(b, k.offset + 8, k.offset + k.size)
                val tb = java.io.ByteArrayOutputStream()
                var trackId = 0
                var sum = 0L
                for (x in tk) {
                    val bytes = b.copyOfRange(x.offset, x.offset + x.size)
                    when (x.type) {
                        "tfhd" -> {
                            trackId = ByteBuffer.wrap(bytes, 12, 4).int
                            val flags = ByteBuffer.wrap(bytes, 8, 4).int and 0xffffff
                            if (flags and 0x1 != 0) ByteBuffer.wrap(bytes, 16, 8).putLong(newMoofStart)
                            tb.write(bytes)
                            val tfdt = ByteBuffer.allocate(20).putInt(20).put("tfdt".toByteArray()).putInt(1 shl 24).putLong(tracks[trackId] ?: 0L).array()
                            tb.write(tfdt)
                        }
                        "trun" -> {
                            val flags = ByteBuffer.wrap(bytes, 8, 4).int and 0xffffff
                            val count = ByteBuffer.wrap(bytes, 12, 4).int
                            var p = 16
                            if (flags and 0x1 != 0) {
                                val bb = ByteBuffer.wrap(bytes, p, 4)
                                val v = bb.int
                                ByteBuffer.wrap(bytes, p, 4).putInt(v + grow)
                                p += 4
                            }
                            if (flags and 0x4 != 0) p += 4
                            for (i in 0 until count) {
                                if (flags and 0x100 != 0) { sum += ByteBuffer.wrap(bytes, p, 4).int.toLong() and 0xffffffffL; p += 4 }
                                if (flags and 0x200 != 0) p += 4
                                if (flags and 0x400 != 0) p += 4
                                if (flags and 0x800 != 0) p += 4
                            }
                            tb.write(bytes)
                        }
                        else -> tb.write(bytes)
                    }
                }
                tracks[trackId] = (tracks[trackId] ?: 0L) + sum
                val tbody = tb.toByteArray()
                body.write(box("traf", tbody))
            }
            out.write(box("moof", body.toByteArray()))
        }
        return out.toByteArray()
    }

    fun box(type: String, body: ByteArray): ByteArray =
        ByteBuffer.allocate(8 + body.size).putInt(8 + body.size).put(type.toByteArray(Charsets.ISO_8859_1)).put(body).array()
}
