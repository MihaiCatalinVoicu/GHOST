package org.ghost.spike.media

import android.graphics.Bitmap
import android.graphics.Canvas
import android.graphics.Color
import android.graphics.ColorSpace
import android.graphics.Gainmap
import android.graphics.Matrix
import android.graphics.Paint
import android.media.MediaCodec
import android.media.MediaCodecInfo
import android.media.MediaFormat
import android.media.MediaMuxer
import android.os.Build
import androidx.exifinterface.media.ExifInterface
import androidx.heifwriter.AvifWriter
import androidx.heifwriter.HeifWriter
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.FileOutputStream
import java.nio.ByteBuffer
import kotlin.math.PI
import kotlin.math.sin

/**
 * Builds the S0 inputs on the device (the "generated half" of the §15.7 corpus that the V-M checks
 * need): H.264 + AAC MP4 sources with planted metadata written by the platform's own MediaMuxer
 * (MPEG4Writer), an H.264 SEI user-data canary in every access unit and an AAC data-stream element
 * (DSE) canary in every audio frame; an 8-orientation EXIF corpus; PNG/WebP/HEIC/AVIF sources; a
 * 100-megapixel JPEG; Ultra HDR and Display P3 JPEGs.
 */
object SourceMaker {
    const val CANARY = "GHOSTCANARYS0"
    // A random-looking UUID without zero bytes (no emulation prevention needed).
    private val SEI_UUID = byteArrayOf(0x47, 0x48, 0x4f, 0x53, 0x54, 0x2d, 0x53, 0x30, 0x2d, 0x53, 0x45, 0x49, 0x2d, 0x55, 0x55, 0x49)
    const val LAT = 46.771234
    const val LON = 23.623456

    class VideoSpec(
        val name: String,
        val w: Int,
        val h: Int,
        val fps: Int,
        val seconds: Double,
        val bitrate: Int,
        val audioRate: Int,
        val audioChannels: Int,
        val rotation: Int = 0,
        val content: String = "mixed",
        val canaries: Boolean = true,
        val location: Boolean = true,
        val profile: Int = MediaCodecInfo.CodecProfileLevel.AVCProfileBaseline,
        val bt601Full: Boolean = true,
    )

    val videoSpecs = listOf(
        // The matching-source row of §15.7 (H.264 + AAC-LC, <= 720p30, SDR, square pixels, below
        // the 2.128 Mbit/s budget), with distinctive VUI (BT.601, full range) and Baseline profile.
        VideoSpec("match720p30.mp4", 1280, 720, 30, 12.0, 1_800_000, 48_000, 2),
        // Stream-parameter rows (D29): 1080p60 with 44.1 kHz mono; portrait 24 fps with 5.1;
        // landscape frames with a 90-degree rotation (how phones store portrait video); VGA.
        VideoSpec("land1080p60.mp4", 1920, 1080, 60, 6.0, 8_000_000, 44_100, 1),
        VideoSpec("port720x1280p24.mp4", 720, 1280, 24, 6.0, 3_000_000, 48_000, 6),
        VideoSpec("rot90_1280x720p30.mp4", 1280, 720, 30, 6.0, 3_000_000, 48_000, 2, rotation = 90),
        VideoSpec("vga640x480p30.mp4", 640, 480, 30, 6.0, 1_000_000, 22_050, 2),
        // Colour control for V-M17: the matching row without the BT.601 full-range request.
        VideoSpec("match720p30_709.mp4", 1280, 720, 30, 12.0, 1_800_000, 48_000, 2, bt601Full = false),
    )

    /**
     * V-M22: the longest sources (VIDEO_MAX_MS = 160 s) in three complexities: `smooth` (moving
     * gradient and box), `mixed` (the same plus a white-noise patch on 1/16 of the frame), `grain`
     * (±8 luma noise on every pixel, a stand-in for sensor noise). Full-frame white noise
     * (`noise`) was tried first: the emulator's encoder wrote about 5 MB/s of it and it was
     * stopped at 951 MB, so it is kept only as a 10-s probe. The t10_* specs are 10-s versions.
     */
    val longSpecs = listOf(
        VideoSpec("long160_smooth.mp4", 1280, 720, 30, 160.0, 4_000_000, 48_000, 2, content = "smooth", canaries = false, location = false),
        VideoSpec("long160_mixed.mp4", 1280, 720, 30, 160.0, 4_000_000, 48_000, 2, content = "mixed", canaries = false, location = false),
        VideoSpec("long160_grain.mp4", 1280, 720, 30, 160.0, 4_000_000, 48_000, 2, content = "grain", canaries = false, location = false),
    )
    val shortSpecs = listOf("smooth", "mixed", "grain", "noise").map {
        VideoSpec("t10_$it.mp4", 1280, 720, 30, 10.0, 4_000_000, 48_000, 2, content = it, canaries = false, location = false)
    }

    fun seiNal(): ByteArray {
        val payload = SEI_UUID + (CANARY + "-SEI-USERDATA").toByteArray()
        return byteArrayOf(0, 0, 0, 1, 0x06, 0x05, payload.size.toByte()) + payload + byteArrayOf(0x80.toByte())
    }

    /** Inserts the SEI canary before the first VCL NAL (types 1 and 5) of an Annex-B access unit. */
    fun withSei(au: ByteArray): ByteArray {
        var i = 0
        while (i + 4 < au.size) {
            val sc3 = au[i] == 0.toByte() && au[i + 1] == 0.toByte() && au[i + 2] == 1.toByte()
            if (sc3) {
                val t = au[i + 3].toInt() and 0x1f
                if (t == 1 || t == 5) {
                    val start = if (i > 0 && au[i - 1] == 0.toByte()) i - 1 else i
                    return au.copyOfRange(0, start) + seiNal() + au.copyOfRange(start, au.size)
                }
                i += 3
            } else {
                i++
            }
        }
        return au
    }

    /** A DSE (ID_DSE = 4, tag 0, no byte alignment) carrying the canary, prepended to a raw AAC frame. */
    fun withDse(frame: ByteArray): ByteArray {
        val c = (CANARY + "-AAC-DSE").toByteArray()
        return byteArrayOf(0x80.toByte(), c.size.toByte()) + c + frame
    }

    fun makeVideo(dir: File, s: VideoSpec): String {
        val out = File(dir, s.name)
        val vf = MediaFormat.createVideoFormat(MediaFormat.MIMETYPE_VIDEO_AVC, s.w, s.h)
        vf.setInteger(MediaFormat.KEY_COLOR_FORMAT, MediaCodecInfo.CodecCapabilities.COLOR_FormatYUV420Flexible)
        vf.setInteger(MediaFormat.KEY_BIT_RATE, s.bitrate)
        vf.setInteger(MediaFormat.KEY_FRAME_RATE, s.fps)
        vf.setInteger(MediaFormat.KEY_I_FRAME_INTERVAL, 2)
        vf.setInteger(MediaFormat.KEY_PROFILE, s.profile)
        if (s.bt601Full) {
            vf.setInteger(MediaFormat.KEY_COLOR_STANDARD, MediaFormat.COLOR_STANDARD_BT601_PAL)
            vf.setInteger(MediaFormat.KEY_COLOR_RANGE, MediaFormat.COLOR_RANGE_FULL)
            vf.setInteger(MediaFormat.KEY_COLOR_TRANSFER, MediaFormat.COLOR_TRANSFER_SDR_VIDEO)
        }
        val venc = MediaCodec.createEncoderByType(MediaFormat.MIMETYPE_VIDEO_AVC)
        venc.configure(vf, null, null, MediaCodec.CONFIGURE_FLAG_ENCODE)
        val af = MediaFormat.createAudioFormat(MediaFormat.MIMETYPE_AUDIO_AAC, s.audioRate, s.audioChannels)
        af.setInteger(MediaFormat.KEY_AAC_PROFILE, MediaCodecInfo.CodecProfileLevel.AACObjectLC)
        af.setInteger(MediaFormat.KEY_BIT_RATE, when (s.audioChannels) { 1 -> 64_000; 2 -> 128_000; else -> 256_000 })
        af.setInteger(MediaFormat.KEY_MAX_INPUT_SIZE, 1024 * 2 * s.audioChannels * 4)
        val aenc = MediaCodec.createEncoderByType(MediaFormat.MIMETYPE_AUDIO_AAC)
        aenc.configure(af, null, null, MediaCodec.CONFIGURE_FLAG_ENCODE)
        venc.start()
        aenc.start()
        val muxer = MediaMuxer(out.path, MediaMuxer.OutputFormat.MUXER_OUTPUT_MPEG_4)
        muxer.setOrientationHint(s.rotation)
        if (s.location) muxer.setLocation(LAT.toFloat(), LON.toFloat())
        var vTrack = -1
        var aTrack = -1
        var started = false
        val pending = ArrayList<Triple<Int, ByteArray, MediaCodec.BufferInfo>>()
        val frames = (s.seconds * s.fps).toInt()
        val audioFrames = (s.seconds * s.audioRate / 1024).toInt()
        var vIn = 0
        var aIn = 0
        var vDone = false
        var aDone = false
        var rng = 0x12345678L
        val info = MediaCodec.BufferInfo()
        var videoSamples = 0
        var audioSamples = 0
        fun write(track: Int, bytes: ByteArray, bi: MediaCodec.BufferInfo) {
            val b = ByteBuffer.wrap(bytes)
            val i2 = MediaCodec.BufferInfo()
            i2.set(0, bytes.size, bi.presentationTimeUs, bi.flags)
            muxer.writeSampleData(track, b, i2)
        }
        fun drain(codec: MediaCodec, isVideo: Boolean) {
            while (true) {
                val idx = codec.dequeueOutputBuffer(info, 0)
                if (idx == MediaCodec.INFO_OUTPUT_FORMAT_CHANGED) {
                    if (isVideo) vTrack = muxer.addTrack(codec.outputFormat) else aTrack = muxer.addTrack(codec.outputFormat)
                    if (vTrack >= 0 && aTrack >= 0 && !started) {
                        muxer.start()
                        started = true
                        for ((t, b, bi) in pending) write(if (t == -2) vTrack else aTrack, b, bi)
                        pending.clear()
                    }
                    continue
                }
                if (idx < 0) return
                val buf = codec.getOutputBuffer(idx)!!
                if (info.flags and MediaCodec.BUFFER_FLAG_CODEC_CONFIG == 0 && info.size > 0) {
                    var bytes = ByteArray(info.size)
                    buf.position(info.offset)
                    buf.get(bytes)
                    if (s.canaries) bytes = if (isVideo) withSei(bytes) else withDse(bytes)
                    val bi = MediaCodec.BufferInfo()
                    bi.set(0, bytes.size, info.presentationTimeUs, info.flags)
                    val track = if (isVideo) vTrack else aTrack
                    if (started) write(track, bytes, bi) else pending += Triple(if (isVideo) -2 else -3, bytes, bi)
                    if (isVideo) videoSamples++ else audioSamples++
                }
                codec.releaseOutputBuffer(idx, false)
                if (info.flags and MediaCodec.BUFFER_FLAG_END_OF_STREAM != 0) {
                    if (isVideo) vDone = true else aDone = true
                    return
                }
            }
        }
        while (!vDone || !aDone) {
            val vt = vIn.toDouble() / s.fps
            val at = aIn * 1024.0 / s.audioRate
            val feedVideo = vIn <= frames && (aIn > audioFrames || vt <= at)
            if (feedVideo) {
                val idx = venc.dequeueInputBuffer(10_000)
                if (idx >= 0) {
                    if (vIn == frames) {
                        venc.queueInputBuffer(idx, 0, 0, (vt * 1e6).toLong(), MediaCodec.BUFFER_FLAG_END_OF_STREAM)
                    } else {
                        val img = venc.getInputImage(idx)!!
                        rng = fillFrame(img, vIn, s, rng)
                        venc.queueInputBuffer(idx, 0, s.w * s.h * 3 / 2, (vt * 1e6).toLong(), 0)
                    }
                    vIn++
                }
            } else if (aIn <= audioFrames) {
                val idx = aenc.dequeueInputBuffer(10_000)
                if (idx >= 0) {
                    if (aIn == audioFrames) {
                        aenc.queueInputBuffer(idx, 0, 0, (at * 1e6).toLong(), MediaCodec.BUFFER_FLAG_END_OF_STREAM)
                    } else {
                        val b = aenc.getInputBuffer(idx)!!
                        b.clear()
                        for (n in 0 until 1024) {
                            val t = (aIn * 1024 + n).toDouble() / s.audioRate
                            for (ch in 0 until s.audioChannels) {
                                val v = (8000 * sin(2 * PI * (330.0 + 110.0 * ch) * t)).toInt()
                                b.put((v and 0xff).toByte()); b.put(((v shr 8) and 0xff).toByte())
                            }
                        }
                        aenc.queueInputBuffer(idx, 0, 1024 * 2 * s.audioChannels, (at * 1e6).toLong(), 0)
                    }
                    aIn++
                }
            }
            drain(venc, true)
            drain(aenc, false)
            if (vIn > frames && aIn > audioFrames) {
                // Inputs finished: drain until both reach end of stream.
                while (!vDone || !aDone) {
                    if (!vDone) drain(venc, true)
                    if (!aDone) drain(aenc, false)
                    Thread.sleep(2)
                }
            }
        }
        val encoders = "${venc.name}+${aenc.name}"
        venc.stop(); venc.release(); aenc.stop(); aenc.release()
        muxer.stop(); muxer.release()
        return "source ${s.name}: ${out.length()} B sha256=${sha256(out.readBytes())} ${s.w}x${s.h}@${s.fps} ${s.seconds}s " +
            "vbitrate=${s.bitrate} audio=${s.audioRate}Hz/${s.audioChannels}ch rotation=${s.rotation} content=${s.content} " +
            "canaries=${s.canaries} location=${s.location} videoSamples=$videoSamples audioSamples=$audioSamples " +
            "encoders=$encoders"
    }

    private fun fillFrame(img: android.media.Image, n: Int, s: VideoSpec, seed: Long): Long {
        var rng = seed
        val y = img.planes[0]
        val yb = y.buffer
        val ys = y.rowStride
        val box = (n * 7) % (s.w - 64).coerceAtLeast(1)
        for (row in 0 until s.h) {
            var p = row * ys
            for (col in 0 until s.w) {
                val v = when (s.content) {
                    "noise" -> {
                        rng = rng * 6364136223846793005L + 1442695040888963407L
                        (rng ushr 56).toInt()
                    }
                    "grain" -> {
                        rng = rng * 6364136223846793005L + 1442695040888963407L
                        val base = 64 + ((col + row + n * 3) and 0x7f)
                        base + (rng ushr 60).toInt() - 8
                    }
                    else -> {
                        val base = (col + row + n * 3) and 0xff
                        if (col in box until box + 64 && row in 100 until 164) 235
                        else if (s.content == "mixed" && row > s.h * 3 / 4 && col < s.w / 4) {
                            rng = rng * 6364136223846793005L + 1442695040888963407L
                            (rng ushr 56).toInt()
                        } else base
                    }
                }
                yb.put(p, v.toByte())
                p += 1
            }
        }
        // The frame index as 16 luma blocks of 40 x 32 px at the top-left (235 = 1, 16 = 0), so a
        // rendered frame can be identified after a seek (V-M2).
        if (s.w >= 640 && s.h >= 64) {
            for (bit in 0 until 16) {
                val v = if ((n shr bit) and 1 == 1) 235 else 16
                for (row in 0 until 32) for (col in bit * 40 until bit * 40 + 40) yb.put(row * ys + col, v.toByte())
            }
        }
        for (pl in 1..2) {
            val c = img.planes[pl]
            val cb = c.buffer
            for (row in 0 until s.h / 2) for (col in 0 until s.w / 2) {
                val v = if (s.content == "noise") {
                    rng = rng * 6364136223846793005L + 1442695040888963407L
                    (rng ushr 56).toInt()
                } else (128 + ((col + n) % 64) - 32 * pl + 16)
                cb.put(row * c.rowStride + col * c.pixelStride, v.toByte())
            }
        }
        return rng
    }

    /** The base picture of the orientation corpus: four coloured quadrants, 600 x 400. */
    fun orientationBase(): Bitmap {
        val b = Bitmap.createBitmap(600, 400, Bitmap.Config.ARGB_8888)
        val c = Canvas(b)
        val p = Paint()
        for ((i, col) in listOf(Color.RED, Color.GREEN, Color.BLUE, Color.WHITE).withIndex()) {
            p.color = col
            val x = (i % 2) * 300f
            val yy = (i / 2) * 200f
            c.drawRect(x, yy, x + 300f, yy + 200f, p)
        }
        return b
    }

    /** The matrix a viewer applies to the stored pixels for EXIF orientation [o] (1 … 8). */
    fun displayMatrix(o: Int): Matrix {
        val m = Matrix()
        when (o) {
            2 -> m.setScale(-1f, 1f)
            3 -> m.setRotate(180f)
            4 -> m.setScale(1f, -1f)
            5 -> { m.setRotate(90f); m.postScale(-1f, 1f) }
            6 -> m.setRotate(90f)
            7 -> { m.setRotate(-90f); m.postScale(-1f, 1f) }
            8 -> m.setRotate(-90f)
        }
        return m
    }

    fun makeOrientationCorpus(dir: File): List<String> {
        val base = orientationBase()
        val out = ArrayList<String>()
        for (o in 1..8) {
            val inv = Matrix()
            displayMatrix(o).invert(inv)
            val stored = Bitmap.createBitmap(base, 0, 0, base.width, base.height, inv, false)
            val f = File(dir, "orient$o.jpg")
            FileOutputStream(f).use { stored.compress(Bitmap.CompressFormat.JPEG, 92, it) }
            val exif = ExifInterface(f)
            exif.setAttribute(ExifInterface.TAG_ORIENTATION, o.toString())
            plantExif(exif)
            exif.saveAttributes()
            out += "source ${f.name}: ${f.length()} B stored=${stored.width}x${stored.height} exifOrientation=$o sha256=${sha256(f.readBytes())}"
        }
        return out
    }

    fun plantExif(exif: ExifInterface) {
        exif.setAttribute(ExifInterface.TAG_MAKE, "$CANARY-MAKE")
        exif.setAttribute(ExifInterface.TAG_MODEL, "$CANARY-MODEL")
        exif.setAttribute(ExifInterface.TAG_SOFTWARE, "$CANARY-SOFTWARE")
        exif.setAttribute(ExifInterface.TAG_BODY_SERIAL_NUMBER, "$CANARY-SERIAL")
        exif.setAttribute(ExifInterface.TAG_IMAGE_UNIQUE_ID, "$CANARY-UNIQUEID")
        exif.setAttribute(ExifInterface.TAG_DATETIME_ORIGINAL, "2026:09:25 07:31:13")
        exif.setAttribute(ExifInterface.TAG_OFFSET_TIME_ORIGINAL, "+03:00")
        exif.setLatLong(LAT, LON)
    }

    fun makeStills(dir: File): List<String> {
        val out = ArrayList<String>()
        // PNG with alpha.
        val a = Bitmap.createBitmap(800, 600, Bitmap.Config.ARGB_8888)
        val c = Canvas(a)
        c.drawColor(Color.TRANSPARENT)
        val p = Paint().apply { color = Color.argb(128, 0, 0, 255) }
        c.drawCircle(400f, 300f, 250f, p)
        File(dir, "alpha.png").also { f -> FileOutputStream(f).use { a.compress(Bitmap.CompressFormat.PNG, 100, it) }; out += "source ${f.name}: ${f.length()} B" }
        // Static WebP with EXIF.
        val base = orientationBase()
        File(dir, "photo.webp").also { f ->
            FileOutputStream(f).use { base.compress(Bitmap.CompressFormat.WEBP_LOSSY, 90, it) }
            try {
                val e = ExifInterface(f); plantExif(e); e.saveAttributes()
            } catch (t: Throwable) {
                out += "note: webp exif not written: ${t.javaClass.simpleName} ${t.message}"
            }
            out += "source ${f.name}: ${f.length()} B"
        }
        // A 320-px canonical-geometry preview (for V-M18) and a 2048 x 1536 photo.
        val prev = Bitmap.createScaledBitmap(base, 320, 208, true)
        File(dir, "preview320.jpg").also { f -> FileOutputStream(f).use { prev.compress(Bitmap.CompressFormat.JPEG, 80, it) }; out += "source ${f.name}: ${f.length()} B" }
        // HEIC through HeifWriter (needs an HEVC encoder) and AVIF through AvifWriter (an AV1 encoder).
        out += try {
            val f = File(dir, "photo.heic")
            val w = HeifWriter.Builder(f.path, 1024, 768, HeifWriter.INPUT_MODE_BITMAP).setQuality(90).build()
            w.start(); w.addBitmap(Bitmap.createScaledBitmap(base, 1024, 768, true)); w.stop(20_000); w.close()
            "source ${f.name}: ${f.length()} B sha256=${sha256(f.readBytes())}"
        } catch (t: Throwable) {
            "source photo.heic: NOT MADE ${t.javaClass.simpleName}: ${t.message}"
        }
        out += try {
            val f = File(dir, "photo.avif")
            val w = AvifWriter.Builder(f.path, 1024, 768, AvifWriter.INPUT_MODE_BITMAP).setQuality(90).build()
            w.start(); w.addBitmap(Bitmap.createScaledBitmap(base, 1024, 768, true)); w.stop(20_000); w.close()
            "source ${f.name}: ${f.length()} B sha256=${sha256(f.readBytes())}"
        } catch (t: Throwable) {
            "source photo.avif: NOT MADE ${t.javaClass.simpleName}: ${t.message}"
        }
        // Display P3 and (API 34+) Ultra HDR JPEGs, for V-M6.
        val p3 = Bitmap.createBitmap(640, 480, Bitmap.Config.ARGB_8888, false, ColorSpace.get(ColorSpace.Named.DISPLAY_P3))
        Canvas(p3).drawColor(Color.rgb(200, 30, 60))
        File(dir, "p3.jpg").also { f -> FileOutputStream(f).use { p3.compress(Bitmap.CompressFormat.JPEG, 90, it) }; out += "source ${f.name}: ${f.length()} B" }
        if (Build.VERSION.SDK_INT >= 34) {
            out += try {
                val hdr = Bitmap.createScaledBitmap(base, 640, 480, true)
                val gm = Bitmap.createBitmap(160, 120, Bitmap.Config.ALPHA_8)
                Canvas(gm).drawColor(Color.argb(200, 0, 0, 0))
                hdr.gainmap = Gainmap(gm)
                val f = File(dir, "ultrahdr.jpg")
                FileOutputStream(f).use { hdr.compress(Bitmap.CompressFormat.JPEG, 90, it) }
                "source ${f.name}: ${f.length()} B"
            } catch (t: Throwable) {
                "source ultrahdr.jpg: NOT MADE ${t.javaClass.simpleName}: ${t.message}"
            }
        }
        return out
    }

    /** V-M5/V-M18 budget: the largest image source the design admits (100 MP, 64 MiB). */
    fun makeBig(dir: File): String {
        for (side in intArrayOf(10_000, 8_000)) {
            try {
                val b = Bitmap.createBitmap(side, side, Bitmap.Config.ARGB_8888)
                val c = Canvas(b)
                val p = Paint()
                for (i in 0 until 400) {
                    p.color = Color.rgb((i * 37) and 255, (i * 91) and 255, (i * 13) and 255)
                    c.drawRect((i % 20) * side / 20f, (i / 20) * side / 20f, (i % 20 + 1) * side / 20f, (i / 20 + 1) * side / 20f, p)
                }
                val f = File(dir, "big${side}.jpg")
                FileOutputStream(f).use { b.compress(Bitmap.CompressFormat.JPEG, 95, it) }
                b.recycle()
                return "source ${f.name}: ${f.length()} B ${side}x$side (${side.toLong() * side / 1_000_000} MP)"
            } catch (t: Throwable) {
                if (side == 8_000) return "source big: NOT MADE ${t.javaClass.simpleName}"
            }
        }
        return "unreachable"
    }

    fun jpegBytes(b: Bitmap, q: Int): ByteArray = ByteArrayOutputStream().also { b.compress(Bitmap.CompressFormat.JPEG, q, it) }.toByteArray()
}
