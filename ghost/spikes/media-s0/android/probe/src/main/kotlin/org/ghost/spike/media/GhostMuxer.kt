package org.ghost.spike.media

import androidx.media3.common.C
import androidx.media3.common.Format
import androidx.media3.common.Metadata
import androidx.media3.common.MimeTypes
import androidx.media3.container.Mp4OrientationData
import androidx.media3.container.Mp4TimestampData
import androidx.media3.muxer.BufferInfo
import androidx.media3.muxer.FragmentedMp4Muxer
import androidx.media3.muxer.Muxer
import androidx.media3.muxer.MuxerException
import com.google.common.collect.ImmutableList
import java.io.ByteArrayOutputStream
import java.nio.ByteBuffer
import java.nio.channels.WritableByteChannel
import java.util.TreeMap

/** What one GhostMuxer saw: V-M1 (the path), V-M3 (metadata), V-M12 (NAL and SEI types). */
class MuxRecord {
    var pathOffered: String? = null
    val offered = ArrayList<String>()
    val forwarded = ArrayList<String>()
    val tracks = ArrayList<String>()
    val nalTypes = TreeMap<Int, Int>()
    val seiTypesSeen = TreeMap<Int, Int>()
    var seiNalsDropped = 0
    var seiNalsKept = 0
    var videoSamples = 0
    var audioSamples = 0
    var annexB = 0
    var avcc = 0
    var channelWrites = 0
    var channelBytes = 0L
    var largestWrite = 0
}

/** An in-memory, strictly sequential channel: a seek is impossible by construction (design §8.3). */
class MemoryChannel(private val rec: MuxRecord, private val keep: Boolean = true) : WritableByteChannel {
    val out = ByteArrayOutputStream()
    /** With keep = false (the V-M22 runs) the stream is only counted and hashed, like a sealer. */
    val digest: java.security.MessageDigest = java.security.MessageDigest.getInstance("SHA-256")
    private var open = true
    override fun write(src: ByteBuffer): Int {
        val n = src.remaining()
        val b = ByteArray(n)
        src.get(b)
        if (keep) out.write(b) else digest.update(b)
        rec.channelWrites++
        rec.channelBytes += n
        if (n > rec.largestWrite) rec.largestWrite = n
        return n
    }
    override fun isOpen() = open
    override fun close() {
        open = false
    }
}

/**
 * `GhostMuxer` of design §8.3: `FragmentedMp4Muxer.Builder(WritableByteChannel)`, no metadata but a
 * constant `Mp4TimestampData` and a 0/90/180/270 `Mp4OrientationData`, only an AVC and an AAC
 * track, the SEI filter (payload types 0, 1, 6 kept), 2-second fragments.
 */
class GhostMuxer(
    private val channel: MemoryChannel,
    private val rec: MuxRecord,
    applySeiFilter: Boolean,
    /** V-M24 fix under test: turn the video Format's rotationDegrees into Mp4OrientationData, as
     *  Media3's own InAppFragmentedMp4Muxer.addTrack does; off = the design text as written. */
    private val orientationFromFormat: Boolean = false,
) : Muxer {
    private val inner: FragmentedMp4Muxer = FragmentedMp4Muxer.Builder(channel).build()
    private val mime = HashMap<Int, String>()
    private val filter = applySeiFilter

    init {
        inner.addMetadataEntry(Mp4TimestampData(0, 0))
        rec.forwarded += "Mp4TimestampData(0,0) [GhostMuxer's own constant]"
    }

    override fun addTrack(format: Format): Int {
        val m = format.sampleMimeType ?: ""
        rec.tracks += "$format rotationDegrees=${format.rotationDegrees} colorInfo=${format.colorInfo}"
        if (m != MimeTypes.VIDEO_H264 && m != MimeTypes.AUDIO_AAC) throw MuxerException("GhostMuxer refuses track $m", IllegalArgumentException(m))
        val id = inner.addTrack(format)
        if (orientationFromFormat && m == MimeTypes.VIDEO_H264 && format.rotationDegrees in listOf(0, 90, 180, 270)) {
            inner.addMetadataEntry(Mp4OrientationData(format.rotationDegrees))
            rec.forwarded += "Mp4OrientationData(${format.rotationDegrees}) [from Format.rotationDegrees]"
        }
        mime[id] = m
        return id
    }

    override fun writeSampleData(trackId: Int, data: ByteBuffer, info: BufferInfo) {
        if (mime[trackId] == MimeTypes.VIDEO_H264) {
            rec.videoSamples++
            val filtered = filterAvc(data)
            inner.writeSampleData(trackId, filtered, BufferInfo(info.presentationTimeUs, filtered.remaining(), info.flags))
        } else {
            rec.audioSamples++
            inner.writeSampleData(trackId, data, info)
        }
    }

    override fun addMetadataEntry(entry: Metadata.Entry) {
        rec.offered += "${entry.javaClass.simpleName}: $entry"
        if (entry is Mp4OrientationData && entry.orientation in listOf(0, 90, 180, 270)) {
            inner.addMetadataEntry(entry)
            rec.forwarded += "Mp4OrientationData(${entry.orientation})"
        }
    }

    override fun close() {
        inner.close()
    }

    /** Splits an access unit into NAL units (Annex-B or 4-byte AVCC), records and filters SEI. */
    private fun filterAvc(data: ByteBuffer): ByteBuffer {
        val b = ByteArray(data.remaining())
        data.get(b)
        val annexB = b.size >= 4 && b[0] == 0.toByte() && b[1] == 0.toByte() && (b[2] == 1.toByte() || (b[2] == 0.toByte() && b[3] == 1.toByte()))
        val nals = ArrayList<ByteArray>()
        if (annexB) {
            rec.annexB++
            val starts = ArrayList<Pair<Int, Int>>() // (start of start code, start of NAL)
            var i = 0
            while (i + 3 <= b.size) {
                if (b[i] == 0.toByte() && b[i + 1] == 0.toByte() && b[i + 2] == 1.toByte()) {
                    val scStart = if (i > 0 && b[i - 1] == 0.toByte()) i - 1 else i
                    starts += Pair(scStart, i + 3)
                    i += 3
                } else i++
            }
            for ((k, s) in starts.withIndex()) {
                val end = if (k + 1 < starts.size) starts[k + 1].first else b.size
                nals += b.copyOfRange(s.second, end)
            }
        } else {
            rec.avcc++
            var o = 0
            while (o + 4 <= b.size) {
                val l = ((b[o].toInt() and 0xff) shl 24) or ((b[o + 1].toInt() and 0xff) shl 16) or ((b[o + 2].toInt() and 0xff) shl 8) or (b[o + 3].toInt() and 0xff)
                o += 4
                if (l < 0 || o + l > b.size) break
                nals += b.copyOfRange(o, o + l)
                o += l
            }
        }
        val out = ByteArrayOutputStream()
        for (n in nals) {
            if (n.isEmpty()) continue
            val t = n[0].toInt() and 0x1f
            rec.nalTypes[t] = (rec.nalTypes[t] ?: 0) + 1
            if (t == 6) {
                val types = seiPayloadTypes(n)
                for (ty in types) rec.seiTypesSeen[ty] = (rec.seiTypesSeen[ty] ?: 0) + 1
                if (filter && types.any { it !in setOf(0, 1, 6) }) {
                    rec.seiNalsDropped++
                    continue
                }
                rec.seiNalsKept++
            }
            if (annexB) out.write(byteArrayOf(0, 0, 0, 1)) else out.write(byteArrayOf((n.size ushr 24).toByte(), (n.size ushr 16).toByte(), (n.size ushr 8).toByte(), n.size.toByte()))
            out.write(n)
        }
        return ByteBuffer.wrap(out.toByteArray())
    }

    companion object {
        fun seiPayloadTypes(nal: ByteArray): List<Int> {
            // Remove emulation prevention bytes.
            val r = ByteArrayOutputStream()
            var zeros = 0
            for (i in 1 until nal.size) {
                val x = nal[i].toInt() and 0xff
                if (zeros >= 2 && x == 3) {
                    zeros = 0; continue
                }
                r.write(x)
                zeros = if (x == 0) zeros + 1 else 0
            }
            val p = r.toByteArray()
            val out = ArrayList<Int>()
            var o = 0
            while (o < p.size) {
                if (p.size - o == 1 && (p[o].toInt() and 0xff) == 0x80) break
                var t = 0
                while (o < p.size && (p[o].toInt() and 0xff) == 0xff) { t += 255; o++ }
                if (o >= p.size) break
                t += p[o].toInt() and 0xff; o++
                var s = 0
                while (o < p.size && (p[o].toInt() and 0xff) == 0xff) { s += 255; o++ }
                if (o >= p.size) break
                s += p[o].toInt() and 0xff; o++
                out += t
                o += s
            }
            return out
        }
    }
}

class GhostMuxerFactory(
    private val rec: MuxRecord,
    private val seiFilter: Boolean = true,
    private val orientationFromFormat: Boolean = false,
    private val keepBytes: Boolean = true,
) : Muxer.Factory {
    lateinit var channel: MemoryChannel
    override fun create(path: String): Muxer {
        rec.pathOffered = path
        channel = MemoryChannel(rec, keepBytes)
        return GhostMuxer(channel, rec, seiFilter, orientationFromFormat)
    }

    override fun getSupportedSampleMimeTypes(trackType: Int): ImmutableList<String> = when (trackType) {
        C.TRACK_TYPE_VIDEO -> ImmutableList.of(MimeTypes.VIDEO_H264)
        C.TRACK_TYPE_AUDIO -> ImmutableList.of(MimeTypes.AUDIO_AAC)
        else -> ImmutableList.of()
    }
}
