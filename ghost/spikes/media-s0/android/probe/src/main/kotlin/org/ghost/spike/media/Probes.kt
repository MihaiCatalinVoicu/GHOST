package org.ghost.spike.media

import android.app.ActivityManager
import android.content.Context
import android.content.Intent
import android.graphics.Bitmap
import android.graphics.BitmapFactory
import android.graphics.Canvas
import android.graphics.Color
import android.graphics.ColorSpace
import android.graphics.Gainmap
import android.graphics.ImageDecoder
import android.graphics.ImageFormat
import android.media.ImageReader
import android.media.MediaCodecList
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.HandlerThread
import android.os.SystemClock
import android.system.Os
import android.system.OsConstants
import androidx.media3.common.C
import androidx.media3.common.DataReader
import androidx.media3.common.Format
import androidx.media3.common.MediaItem
import androidx.media3.common.Player
import androidx.media3.common.util.ParsableByteArray
import androidx.media3.datasource.ByteArrayDataSource
import androidx.media3.datasource.ContentDataSource
import androidx.media3.datasource.DataSource
import androidx.media3.datasource.DataSpec
import androidx.media3.exoplayer.DefaultLoadControl
import androidx.media3.exoplayer.ExoPlayer
import androidx.media3.exoplayer.source.ProgressiveMediaSource
import androidx.media3.extractor.DefaultExtractorInput
import androidx.media3.extractor.DefaultExtractorsFactory
import androidx.media3.extractor.Extractor
import androidx.media3.extractor.ExtractorOutput
import androidx.media3.extractor.ExtractorsFactory
import androidx.media3.extractor.PositionHolder
import androidx.media3.extractor.SeekMap
import androidx.media3.extractor.TrackOutput
import androidx.media3.extractor.mp4.FragmentedMp4Extractor
import androidx.media3.extractor.text.SubtitleParser
import java.io.File
import java.io.FileOutputStream
import java.util.Random
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec
import kotlin.math.abs

/** Every probe of the S0 spike (design Appendix C.3). Report lines are the evidence. */
class Probes(private val inst: SpikeRunner, private val args: Bundle) {
    private val ctx: Context = inst.targetContext
    private val src = File(ctx.filesDir, "src").apply { mkdirs() }
    private val outDir = File(ctx.filesDir, "out")
    private val iso = IsoClient(ctx)

    fun run(name: String) {
        when (name) {
            "env" -> env()
            "sources" -> sources()
            "transcode" -> transcode()
            "seek" -> seek()
            "orient" -> orient()
            "iso" -> isoDecode()
            "isoTiming" -> isoTiming()
            "unguarded" -> unguarded()
            "crash" -> crash()
            "compress" -> compress()
            "play" -> play()
            "mtime" -> mtime()
            "preview" -> preview()
            "luma" -> lumaRange()
            "bench" -> bench()
            "pick" -> pick()
            "inventory" -> inventory(ctx).forEach { (k, v) -> report("inv $k $v") }
            "clean" -> { outDir.deleteRecursively(); File(ctx.noBackupFilesDir, "m").deleteRecursively(); report("cleaned") }
            else -> throw IllegalArgumentException("unknown probe $name")
        }
    }

    private fun arg(k: String, d: String) = args.getString(k) ?: d

    // ---------------------------------------------------------------- env
    private fun env() {
        report("mounts: " + File("/proc/mounts").readLines().filter { " /data " in it || " /storage/emulated " in it || "/data/user" in it }.joinToString(" | "))
        val am = ctx.getSystemService(ActivityManager::class.java)
        report("memoryClass=${am.memoryClass}MB largeMemoryClass=${am.largeMemoryClass}MB maxMemory=${Runtime.getRuntime().maxMemory() / 1048576}MB")
        for (c in MediaCodecList(MediaCodecList.REGULAR_CODECS).codecInfos) {
            val types = c.supportedTypes.joinToString(",")
            if (!types.contains("avc") && !types.contains("hevc") && !types.contains("mp4a") && !types.contains("av01") && !types.contains("heic")) continue
            val sb = StringBuilder("codec ${c.name} ${if (c.isEncoder) "enc" else "dec"} [$types] hw=${c.isHardwareAccelerated} sw=${c.isSoftwareOnly} vendor=${c.isVendor}")
            if (c.isEncoder) {
                for (t in c.supportedTypes) {
                    val caps = c.getCapabilitiesForType(t)
                    val ec = caps.encoderCapabilities ?: continue
                    val modes = listOf(0 to "CQ", 1 to "VBR", 2 to "CBR", 3 to "CBR_FD").filter { ec.isBitrateModeSupported(it.first) }.joinToString("/") { it.second }
                    sb.append(" $t:modes=$modes profiles=${caps.profileLevels.joinToString(";") { "${it.profile}@${it.level}" }}")
                    caps.audioCapabilities?.let { a -> sb.append(" maxCh=${a.maxInputChannelCount} rates=${a.supportedSampleRates?.joinToString(",")}") }
                }
            }
            report(sb.toString())
        }
        val pi = ctx.packageManager.getPackageInfo(ctx.packageName, android.content.pm.PackageManager.GET_PROVIDERS or android.content.pm.PackageManager.GET_SERVICES)
        report("manifest providers: " + (pi.providers?.joinToString { "${it.name}@${it.processName}" } ?: "none"))
        report("manifest services: " + (pi.services?.joinToString { "${it.name}@${it.processName} flags=0x${Integer.toHexString(it.flags)}" } ?: "none"))
        report("avc encoder=${Transcoder.avcEncoder()?.name} cbrSupported=${Transcoder.cbrSupported()}")
    }

    // ---------------------------------------------------------------- sources
    private fun sources() {
        val set = arg("set", "all")
        if (set == "all" || set == "video") {
            for (s in SourceMaker.videoSpecs) report(makeVideoWithFallback(s))
        }
        if (set == "all" || set == "stills") {
            SourceMaker.makeOrientationCorpus(src).forEach { report(it) }
            SourceMaker.makeStills(src).forEach { report(it) }
        }
        if (set == "all" || set == "big") report(SourceMaker.makeBig(src))
        if (set == "one") report(makeVideoWithFallback((SourceMaker.videoSpecs + SourceMaker.longSpecs + SourceMaker.shortSpecs + SourceMaker.encoderSpecs).first { it.name == arg("name", "") }))
        if (set == "short") for (s in SourceMaker.shortSpecs) {
            val t0 = SystemClock.elapsedRealtime()
            report(makeVideoWithFallback(s) + " genMs=${SystemClock.elapsedRealtime() - t0}")
        }
        if (set == "long") for (s in SourceMaker.longSpecs) {
            val t0 = SystemClock.elapsedRealtime()
            report(makeVideoWithFallback(s) + " genMs=${SystemClock.elapsedRealtime() - t0}")
        }
    }

    /**
     * The spec as asked; then with stereo audio; then also without the profile and colour keys,
     * which API 29's OMX.google.h264.encoder refuses (`configureCodec` error -38). Each fallback is
     * named in the report line.
     */
    private fun makeVideoWithFallback(s: SourceMaker.VideoSpec): String {
        val tries = listOf(
            s to "as specified",
            SourceMaker.VideoSpec(s.name, s.w, s.h, s.fps, s.seconds, s.bitrate, s.audioRate, 2, s.rotation, s.content, s.canaries, s.location, s.profile, s.bt601Full) to "stereo",
            SourceMaker.VideoSpec(s.name, s.w, s.h, s.fps, s.seconds, s.bitrate, s.audioRate, 2, s.rotation, s.content, s.canaries, s.location, 0, false) to "stereo, no profile or colour keys",
        )
        val notes = StringBuilder()
        for ((spec, label) in tries) {
            try {
                return notes.toString() + SourceMaker.makeVideo(src, spec)
            } catch (t: Throwable) {
                notes.append("note: ${s.name} ($label) failed (${t.javaClass.simpleName}: ${t.message}); ")
            }
        }
        return "$notes FAILED"
    }

    // ---------------------------------------------------------------- transcodes (V-M1, V-M3, V-M12, V-M17, V-M22, V-M24)
    private class Job(
        val src: String,
        val mode: Transcoder.Mode,
        val landscape: Boolean,
        val cbr: Boolean = true,
        val portrait: Boolean? = null,
        val seiFilter: Boolean = true,
        val orientFix: Boolean = false,
        val bt709: Boolean = false,
    ) {
        val tag get() = "${src.removeSuffix(".mp4")}__${mode}${if (!cbr) "_VBR" else ""}${portrait?.let { "_portrait$it" } ?: ""}${if (!seiFilter) "_nofilter" else ""}${if (orientFix) "_orientfix" else ""}${if (bt709) "_bt709" else ""}"
    }

    private fun jobs(set: String): List<Job> = when (set) {
        "basic" -> {
            val one = listOf(
                Job("match720p30.mp4", Transcoder.Mode.DESIGN, true),
                Job("match720p30.mp4", Transcoder.Mode.UNFORCED_EFFECTS, true),
                Job("match720p30.mp4", Transcoder.Mode.PLAIN, true),
                Job("match720p30.mp4", Transcoder.Mode.PLAIN_KEEP_HDR, true),
                Job("match720p30.mp4", Transcoder.Mode.PLAIN_DEFAULTS, true),
                Job("land1080p60.mp4", Transcoder.Mode.DESIGN, true),
                Job("port720x1280p24.mp4", Transcoder.Mode.DESIGN, false),
                Job("port720x1280p24.mp4", Transcoder.Mode.DESIGN, false, portrait = true),
                Job("rot90_1280x720p30.mp4", Transcoder.Mode.DESIGN, false),
                Job("rot90_1280x720p30.mp4", Transcoder.Mode.DESIGN, false, portrait = true),
                Job("vga640x480p30.mp4", Transcoder.Mode.DESIGN, true),
                Job("match720p30.mp4", Transcoder.Mode.DESIGN, true, cbr = false),
            )
            one + one
        }
        // The corrections under test (V-M17 colour, V-M24 orientation), and the colour control.
        "fixes" -> listOf(
            Job("match720p30_709.mp4", Transcoder.Mode.DESIGN, true),
            Job("match720p30.mp4", Transcoder.Mode.DESIGN, true, bt709 = true),
            Job("rot90_1280x720p30.mp4", Transcoder.Mode.DESIGN, false, orientFix = true),
            Job("port720x1280p24.mp4", Transcoder.Mode.DESIGN, false, orientFix = true),
            Job("match720p30.mp4", Transcoder.Mode.PLAIN_DEFAULTS, true),
        )
        "long" -> {
            val reps = arg("reps", "5").toInt()
            val names = arg("names", "long160_smooth.mp4,long160_mixed.mp4,long160_grain.mp4").split(",")
            (0 until reps).flatMap { names.map { n -> Job(n, Transcoder.Mode.DESIGN, true) } }
        }
        "longvbr" -> arg("names", "long160_smooth.mp4,long160_mixed.mp4,long160_grain.mp4").split(",").map { Job(it, Transcoder.Mode.DESIGN, true, cbr = false) }
        "short" -> SourceMaker.shortSpecs.flatMap { listOf(Job(it.name, Transcoder.Mode.DESIGN, true), Job(it.name, Transcoder.Mode.DESIGN, true, cbr = false)) }
        else -> listOf(Job(arg("src", "match720p30.mp4"), Transcoder.Mode.valueOf(arg("mode", "DESIGN")), arg("landscape", "true") == "true"))
    }

    private fun transcode() {
        val observe = arg("observe", "0") == "1"
        val save = arg("save", "0") == "1"
        val list = jobs(arg("set", "basic"))
        if (save) outDir.mkdirs()
        val before = if (observe) inventory(ctx) else emptyMap()
        val watch = if (observe) FsWatch(ctx) else null
        if (watch != null) report("vm1: FileObserver on ${watch.watched.size} directories: ${watch.watched.joinToString(" ")}")
        var ok = 0
        val saved = HashSet<String>()
        for ((i, j) in list.withIndex()) {
            val hwm0 = procStatus("VmHWM")
            // The V-M22 sets only count and hash the stream (their outputs can exceed the heap).
            val keep = !(arg("set", "basic") in setOf("long", "longvbr", "short")) || save
            val r = Transcoder.run(ctx, j.src, j.mode, j.landscape, j.cbr, j.portrait, j.seiFilter, orientationFix = j.orientFix, bt709 = j.bt709, keepBytes = keep)
            if (r.ok) ok++
            report("#$i ${r.summary} appVmHWMkB=${procStatus("VmHWM")} (before $hwm0) outSha256=${if (r.bytes.isNotEmpty()) sha256(r.bytes) else "-"}")
            report("#$i   tracks=${r.rec.tracks}")
            report("#$i   metadataOffered=${r.rec.offered} forwarded=${r.rec.forwarded}")
            report("#$i   nalTypes=${r.rec.nalTypes} seiPayloadTypesSeenBeforeFilter=${r.rec.seiTypesSeen} seiNalsDropped=${r.rec.seiNalsDropped} kept=${r.rec.seiNalsKept} annexB=${r.rec.annexB} avcc=${r.rec.avcc} videoSamples=${r.rec.videoSamples} audioSamples=${r.rec.audioSamples}")
            report("#$i   channel writes=${r.rec.channelWrites} bytes=${r.rec.channelBytes} largestWrite=${r.rec.largestWrite}")
            if (save && r.ok && saved.add(j.tag)) {
                File(outDir, "${j.tag}.mp4").writeBytes(r.bytes)
            }
        }
        if (watch != null) {
            val events = watch.stop()
            val diff = inventoryDiff(before, inventory(ctx))
            report("vm1: transcodes=${list.size} ok=$ok fileObserverEvents=${events.size} inventoryChanges=${diff.size}")
            events.take(200).forEach { report("vm1 event: $it") }
            diff.take(200).forEach { report("vm1 diff: $it") }
        }
    }

    // ---------------------------------------------------------------- V-M2 seeking
    private class Capture : ExtractorOutput {
        var seekMap: SeekMap? = null
        val tracks = HashMap<Int, T>()
        class T(val type: Int) : TrackOutput {
            var format: Format? = null
            val samples = ArrayList<Pair<Long, Int>>()
            private val scratch = ByteArray(64 * 1024)
            override fun format(format: Format) { this.format = format }
            override fun sampleData(input: DataReader, length: Int, allowEndOfInput: Boolean, sampleDataPart: Int): Int {
                val n = input.read(scratch, 0, minOf(length, scratch.size))
                if (n == C.RESULT_END_OF_INPUT) { if (allowEndOfInput) return C.RESULT_END_OF_INPUT; throw java.io.EOFException() }
                return n
            }
            override fun sampleData(data: ParsableByteArray, length: Int, sampleDataPart: Int) { data.skipBytes(length) }
            override fun sampleMetadata(timeUs: Long, flags: Int, size: Int, offset: Int, cryptoData: TrackOutput.CryptoData?) { samples += Pair(timeUs, flags) }
        }
        override fun track(id: Int, type: Int): TrackOutput = tracks.getOrPut(id) { T(type) }
        override fun endTracks() {}
        override fun seekMap(seekMap: SeekMap) { this.seekMap = seekMap }
    }

    /** Runs [ex] over [data] from [start] until [stop] says so; handles RESULT_SEEK. */
    private fun drive(ex: Extractor, data: ByteArray, start: Long, stop: () -> Boolean): Int {
        var pos = start
        var reads = 0
        val holder = PositionHolder()
        outer@ while (true) {
            val ds = ByteArrayDataSource(data)
            ds.open(DataSpec.Builder().setUri(Uri.EMPTY).setPosition(pos).build())
            val input = DefaultExtractorInput(ds, pos, data.size.toLong())
            while (true) {
                if (stop()) { ds.close(); return reads }
                val r = ex.read(input, holder)
                reads++
                when (r) {
                    Extractor.RESULT_CONTINUE -> continue
                    Extractor.RESULT_SEEK -> { pos = holder.position; ds.close(); continue@outer }
                    else -> { ds.close(); return reads }
                }
            }
        }
    }

    private fun seekTest(label: String, data: ByteArray, flags: Int, targets: List<Long>) {
        val cap = Capture()
        val ex = FragmentedMp4Extractor(SubtitleParser.Factory.UNSUPPORTED, flags)
        ex.init(cap)
        drive(ex, data, 0) { cap.seekMap != null && cap.tracks.values.any { it.samples.isNotEmpty() } }
        val sm = cap.seekMap
        report("vm2 $label: seekMap=${sm?.javaClass?.simpleName} seekable=${sm?.isSeekable} durationUs=${sm?.durationUs}")
        if (sm == null || !sm.isSeekable) return
        val video = cap.tracks.values.first { it.type == C.TRACK_TYPE_VIDEO }
        var landedKey = 0
        var maxLag = 0L
        var within = 0
        val examples = ArrayList<String>()
        for (t in targets) {
            val sp = sm.getSeekPoints(t).first
            // As ProgressiveMediaPeriod does: seek to the point's position with the target time.
            ex.seek(sp.position, t)
            video.samples.clear()
            drive(ex, data, sp.position) { video.samples.isNotEmpty() }
            val (ts, fl) = video.samples.first()
            if (fl and C.BUFFER_FLAG_KEY_FRAME != 0) landedKey++
            val lag = t - ts
            // The first sample must be the sync sample at or before the target, within one GOP (1 s).
            if (lag in 0..1_000_000) within++
            maxLag = maxOf(maxLag, abs(lag))
            if (examples.size < 4) examples += "t=$t point=(${sp.timeUs},${sp.position}) firstSampleUs=$ts"
        }
        report("vm2 $label: targets=${targets.size} firstSampleIsKeyFrame=$landedKey firstSampleTimeInTarget-1s..Target=$within maxAbsLagUs=$maxLag e.g. ${examples.joinToString("; ")}")
    }

    private fun seek() {
        val name = arg("file", "match720p30__DESIGN.mp4")
        val raw = File(outDir, name).readBytes()
        val track = Mp4Mini.videoTrackId(raw)
        // The design text as written: tfra times from each moof's tfdt.
        val literal = Mp4Mini.fragmentTimes(raw, track)
        val literalMfra = Mp4Mini.buildMfra(raw, useTfdt = true)
        // The corrected rule: decode times from the running sum of trun durations.
        val summed = Mp4Mini.fragmentTimesFromDurations(raw, track)
        val mfra = Mp4Mini.buildMfra(raw, useTfdt = false)
        val withMfra = raw + mfra
        File(outDir, name.removeSuffix(".mp4") + "_mfra.mp4").writeBytes(withMfra)
        report("vm2 file=$name bytes=${raw.size} videoTrack=$track moofs=${Mp4Mini.boxes(raw, 0, raw.size).count { it.type == "moof" }}")
        report("vm2 design-literal tfra (from tfdt): entries=${literal.size} mfraBytes=${literalMfra.size}")
        report("vm2 corrected tfra (summed trun durations, 90 kHz): entries=${summed.size} mfraBytes=${mfra.size} times=${summed.map { it.second }} offsets=${summed.map { it.first }}")
        val rnd = Random(20260925)
        // The object's duration comes from the manifest in the product (duration_ms); here from the
        // mdhd-timescale sum (90 kHz), because a fragmented file has no duration in mvhd/mehd.
        val lastMoofTime = summed.lastOrNull()?.second ?: 0L
        val durUs = (lastMoofTime + 3 * 90_000L) * 1_000_000L / 90_000L
        val targets = (0 until 50).map { (rnd.nextDouble() * (durUs - 3_000_000L)).toLong() }
        // The fix under test: tfdt inserted into every traf (then the mfra built from tfdt).
        val withTfdt = Mp4Mini.insertTfdt(raw)
        val tfdtMfra = Mp4Mini.buildMfra(withTfdt, useTfdt = true)
        val fixed = withTfdt + tfdtMfra
        File(outDir, name.removeSuffix(".mp4") + "_tfdt_mfra.mp4").writeBytes(fixed)
        report("vm2 tfdt-inserted file: bytes=${withTfdt.size} (+${withTfdt.size - raw.size}) tfra entries=${Mp4Mini.fragmentTimes(withTfdt, track).size}")
        seekTest("literal-mfra+flag", raw + literalMfra, FragmentedMp4Extractor.FLAG_READ_MFRA_FOR_SEEK_MAP, targets)
        seekTest("summed-mfra+flag (no tfdt)", withMfra, FragmentedMp4Extractor.FLAG_READ_MFRA_FOR_SEEK_MAP, targets)
        seekTest("tfdt+mfra+flag", fixed, FragmentedMp4Extractor.FLAG_READ_MFRA_FOR_SEEK_MAP, targets)
        seekTest("summed-mfra,noflag", withMfra, 0, targets)
        seekTest("nomfra+flag", raw, FragmentedMp4Extractor.FLAG_READ_MFRA_FOR_SEEK_MAP, targets)
        // `-e player 0` keeps the extractor half alone; `-e readerFormat private` keeps the player
        // half with timestamps only (no pixel read, so no content check). On API 29 the YUV run
        // aborted in ART's JIT (debuggable app) until the probe was AOT-compiled, and its luma
        // blocks do not decode to frame indices there: API 29 rests on timestamps.
        if (arg("player", "1") != "1") return
        val n = arg("playerSeeks", "50").toInt()
        val fmt = if (arg("readerFormat", "yuv") == "private") ImageFormat.PRIVATE else ImageFormat.YUV_420_888
        playerSeek("summed-mfra (no tfdt)", withMfra, targets.take(n), fmt)
        playerSeek("tfdt+mfra", fixed, targets.take(n), fmt)
        playerSeek("literal-mfra", raw + literalMfra, targets.take(n), fmt)
    }

    /**
     * ExoPlayer over the bytes, fMP4-only extractors with the flag, frames into an ImageReader. The
     * sources carry their frame index as 16 luma blocks (SourceMaker), so each rendered frame is
     * identified: after `seekTo(t)` the frame shown must be frame `floor(t · 30 fps)` — a
     * timestamp check alone cannot see a frame shown at the right time with the wrong content.
     */
    private fun playerSeek(label: String, data: ByteArray, targets: List<Long>, readerFormat: Int = ImageFormat.YUV_420_888) {
        val ht = HandlerThread("player").apply { start() }
        val h = Handler(ht.looper)
        val reader = ImageReader.newInstance(1280, 1280, readerFormat, 4)
        val frames = java.util.concurrent.LinkedBlockingQueue<Int>()
        reader.setOnImageAvailableListener({ r ->
            r.acquireLatestImage()?.let { img ->
                var idx = -1
                if (readerFormat == ImageFormat.YUV_420_888) {
                    val y = img.planes[0]
                    idx = 0
                    for (bit in 0 until 16) {
                        val v = y.buffer.get(16 * y.rowStride + bit * 40 + 20).toInt() and 0xff
                        if (v > 128) idx = idx or (1 shl bit)
                    }
                }
                frames.put(idx)
                img.close()
            }
        }, h)
        lateinit var player: ExoPlayer
        val ready = CountDownLatch(1)
        val ef = ExtractorsFactory { arrayOf(FragmentedMp4Extractor(SubtitleParser.Factory.UNSUPPORTED, FragmentedMp4Extractor.FLAG_READ_MFRA_FOR_SEEK_MAP)) }
        val rendered = java.util.concurrent.LinkedBlockingQueue<Long>()
        h.post {
            player = ExoPlayer.Builder(ctx, ProgressiveMediaSource.Factory({ ByteArrayDataSource(data) }, ef))
                .setLooper(ht.looper)
                .setUsePlatformDiagnostics(false)
                .setLoadControl(DefaultLoadControl.Builder().setBufferDurationsMs(5_000, 15_000, 1_000, 2_000).setTargetBufferBytes(8 * 1024 * 1024).build())
                .build()
            player.setVideoFrameMetadataListener { pts, _, _, _ -> rendered.put(pts) }
            player.setVideoSurface(reader.surface)
            player.volume = 0f
            player.setMediaItem(MediaItem.fromUri(Uri.parse("ghost://object")))
            player.addListener(object : Player.Listener {
                override fun onPlaybackStateChanged(s: Int) { if (s == Player.STATE_READY) ready.countDown() }
            })
            player.prepare()
        }
        ready.await(30, TimeUnit.SECONDS)
        var seekable = false
        h.post { seekable = player.isCurrentMediaItemSeekable }
        Thread.sleep(200)
        var exact = 0
        var within = 0
        var noFrame = 0
        var worst = 0L
        var rightFrame = 0
        var worstFrames = 0
        val examples = ArrayList<String>()
        for (t in targets) {
            rendered.clear()
            frames.clear()
            val tMs = t / 1000
            h.post { player.seekTo(tMs) }
            val pts = rendered.poll(10, TimeUnit.SECONDS)
            val idx = frames.poll(10, TimeUnit.SECONDS)
            if (pts == null || idx == null) { noFrame++; continue }
            val lag = abs(pts - t)
            worst = maxOf(worst, lag)
            if (lag <= 34_000) exact++
            if (lag <= 2_000_000) within++
            val expected = (tMs * 30 / 1000).toInt()
            if (idx >= 0) {
                if (abs(idx - expected) <= 1) rightFrame++
                worstFrames = maxOf(worstFrames, abs(idx - expected))
            }
            if (examples.size < 5) examples += "t=${tMs}ms pts=${pts / 1000}ms frame=${if (idx >= 0) idx.toString() else "n/a"} expected=$expected"
        }
        h.post { player.release() }
        Thread.sleep(500)
        reader.close()
        ht.quitSafely()
        val content = if (readerFormat == ImageFormat.YUV_420_888) "contentFrameWithin1=$rightFrame worstContentErrorFrames=$worstFrames" else "contentFrame=n/a(readerFormat=PRIVATE)"
        report("vm2 player [$label]: seekable=$seekable seeks=${targets.size} ptsWithin1Frame=$exact ptsWithin2s=$within noFrame=$noFrame worstPtsLagUs=$worst $content e.g. ${examples.joinToString("; ")}")
    }

    // ---------------------------------------------------------------- V-M4 orientation
    private fun quadrants(b: Bitmap): String {
        fun cls(c: Int): String {
            val r = Color.red(c); val g = Color.green(c); val bl = Color.blue(c)
            return when {
                r > 200 && g > 200 && bl > 200 -> "W"
                r > 150 && g < 100 && bl < 100 -> "R"
                g > 150 && r < 100 && bl < 100 -> "G"
                bl > 150 && r < 100 && g < 100 -> "B"
                else -> "?"
            }
        }
        val w = b.width; val h = b.height
        return listOf(Pair(w / 4, h / 4), Pair(3 * w / 4, h / 4), Pair(w / 4, 3 * h / 4), Pair(3 * w / 4, 3 * h / 4)).joinToString("") { cls(b.getPixel(it.first, it.second)) }
    }

    private fun fromPixels(px: ByteArray, w: Int, h: Int): Bitmap {
        val b = Bitmap.createBitmap(w, h, Bitmap.Config.ARGB_8888)
        b.copyPixelsFromBuffer(java.nio.ByteBuffer.wrap(px))
        return b
    }

    private fun orient() {
        report("vm4 expected (base 600x400, quadrants TL TR BL BR) = RGBW")
        for (o in 1..8) {
            val bytes = File(src, "orient$o.jpg").readBytes()
            val main = ImageDecoder.decodeBitmap(ImageDecoder.createSource(java.nio.ByteBuffer.wrap(bytes))) { d, _, _ -> d.allocator = ImageDecoder.ALLOCATOR_SOFTWARE }
            val bf = BitmapFactory.decodeByteArray(bytes, 0, bytes.size)
            var isoLine = ""
            val done = iso.oneShot("orient", { b ->
                val (d, out) = iso.decode(b, bytes, 2048, 2048)
                Pair(d, out)
            })
            @Suppress("UNCHECKED_CAST")
            val res = done.result as? Pair<IsoClient.Decoded?, android.os.SharedMemory>
            if (res?.first != null) {
                val d = res.first!!
                val px = IsoClient.takeAndZero(res.second, d.w * d.h * 4)
                isoLine = "isolatedImageDecoder=${d.w}x${d.h} ${quadrants(fromPixels(px, d.w, d.h))} (${d.info})"
            } else isoLine = "isolated: ${done.result} cb=${done.callback}"
            // STRIP_IMAGE in its own instance, then the canonical output decoded in the main process.
            var stripLine: String
            val sd = iso.oneShot("strip", { b -> iso.strip(b, bytes, 1_048_512) })
            @Suppress("UNCHECKED_CAST")
            val sr = sd.result as? Pair<IsoClient.Stripped?, android.os.SharedMemory>
            stripLine = if (sr?.first != null) {
                val s = sr.first!!
                val jpg = IsoClient.takeAndZero(sr.second, s.len)
                outDir.mkdirs(); File(outDir, "strip_orient$o.jpg").writeBytes(jpg)
                val back = BitmapFactory.decodeByteArray(jpg, 0, jpg.size)
                "strip=${s.w}x${s.h} q=${s.q} ${quadrants(back)} len=${s.len}"
            } else "strip failed: ${sd.result}"
            report("vm4 orientation=$o mainImageDecoder=${main.width}x${main.height} ${quadrants(main)} bitmapFactory=${bf.width}x${bf.height} ${quadrants(bf)} $isoLine $stripLine")
        }
    }

    // ---------------------------------------------------------------- V-M5 / V-M19 / V-M6 isolated decode and strip
    private fun isoDecode() {
        // What runs in the isolated process, and what GhostApp-like operations do there.
        val p = iso.oneShot("ping", { b -> Pair(iso.ping(b), iso.ops(b)) })
        @Suppress("UNCHECKED_CAST")
        val pr = p.result as Pair<IsoClient.Ping, String>
        report("vm19 isolated: pid=${pr.first.pid} uid=${pr.first.uid} isIsolated=${pr.first.isolated} processName=${pr.first.processName} applicationOnCreateRan=${pr.first.appRan} sourceProviderCreatedThere=${pr.first.providerCreated} VmHWMkB=${pr.first.hwmKb} mainPid=${android.os.Process.myPid()} mainUid=${android.os.Process.myUid()} bindMs=${"%.1f".format(p.bindMs)} deathMs=${"%.1f".format(p.deathMs)}")
        report("vm19 ghostApp-like operations inside the isolated process: ${pr.second}")
        report("vm19 main process: sourceProviderCreatedHere=${SourceProvider.created}")
        val names = arg("files", "orient1.jpg,alpha.png,photo.webp,photo.heic,photo.avif,p3.jpg,ultrahdr.jpg,big10000.jpg,big8000.jpg").split(",")
        outDir.mkdirs()
        for (n in names) {
            val f = File(src, n)
            if (!f.exists()) { report("vm5 $n: no source on this API level"); continue }
            val bytes = f.readBytes()
            val d = iso.oneShot("dec", { b -> iso.decode(b, bytes, 2048, 2048) })
            @Suppress("UNCHECKED_CAST")
            val dr = d.result as? Pair<IsoClient.Decoded?, android.os.SharedMemory>
            val decLine = if (dr?.first != null) {
                val x = dr.first!!
                IsoClient.takeAndZero(dr.second, 4)
                "decode OK ${x.w}x${x.h} ${"%.1f".format(x.ns / 1e6)}ms isoVmHWM=${x.hwmKb}kB [${x.info}]"
            } else "decode FAILED: ${d.result} cb=${d.callback}"
            val s = iso.oneShot("strip", { b -> iso.strip(b, bytes, 1_048_512) })
            @Suppress("UNCHECKED_CAST")
            val sr = s.result as? Pair<IsoClient.Stripped?, android.os.SharedMemory>
            val stripLine = if (sr?.first != null) {
                val x = sr.first!!
                val jpg = IsoClient.takeAndZero(sr.second, x.len)
                File(outDir, "strip_${n.substringBefore('.')}_${n.substringAfter('.')}.jpg").writeBytes(jpg)
                "strip OK ${x.w}x${x.h} q=${x.q} ${x.len}B ${"%.1f".format(x.ns / 1e6)}ms isoVmHWM=${x.hwmKb}kB [${x.info}]"
            } else "strip FAILED: ${s.result} cb=${s.callback}"
            // Control (measurement only): the same bytes through ImageDecoder in the main process, so a
            // sandbox failure can be told apart from an input the platform cannot decode anywhere.
            val control = try {
                val b = ImageDecoder.decodeBitmap(ImageDecoder.createSource(java.nio.ByteBuffer.wrap(bytes))) { dd, info, _ ->
                    dd.allocator = ImageDecoder.ALLOCATOR_SOFTWARE
                    if (info.size.width > 2048 || info.size.height > 2048) dd.setTargetSampleSize(8)
                }
                "mainProcessControl OK ${b.width}x${b.height}"
            } catch (t: Throwable) {
                "mainProcessControl FAILED ${t.javaClass.simpleName}: ${t.message}"
            }
            val direct = try {
                val region = IsoClient.region("ctl", bytes)
                val m = region.mapReadOnly()
                val b = ImageDecoder.decodeBitmap(ImageDecoder.createSource(m)) { dd, info, _ ->
                    dd.allocator = ImageDecoder.ALLOCATOR_SOFTWARE
                    if (info.size.width > 2048 || info.size.height > 2048) dd.setTargetSampleSize(8)
                }
                android.os.SharedMemory.unmap(m); region.close()
                "mainProcessSharedMemory OK ${b.width}x${b.height}"
            } catch (t: Throwable) {
                "mainProcessSharedMemory FAILED ${t.javaClass.simpleName}: ${t.message}"
            }
            val hc = iso.oneShot("heap", { b -> iso.decode(b, bytes, 2048, 2048, mode = 2) })
            @Suppress("UNCHECKED_CAST")
            val hr = hc.result as? Pair<IsoClient.Decoded?, android.os.SharedMemory>
            val heapLine = if (hr?.first != null) { IsoClient.takeAndZero(hr.second, 4); "isolatedHeapCopy OK ${hr.first!!.w}x${hr.first!!.h}" } else "isolatedHeapCopy FAILED: ${hc.result}"
            report("vm5 $n (${bytes.size} B): pid=${d.pid}/${s.pid} $decLine; $stripLine; $control; $direct; $heapLine")
        }
    }

    // ---------------------------------------------------------------- V-M18 timing
    private fun isoTiming() {
        val n = arg("n", "100").toInt()
        val bytes = File(src, "preview320.jpg").readBytes()
        val pids = HashSet<Int>()
        val total = ArrayList<Double>()
        val bind = ArrayList<Double>()
        val death = ArrayList<Double>()
        var failures = 0
        for (i in 0 until n) {
            val t0 = SystemClock.elapsedRealtimeNanos()
            val d = iso.oneShot("t", { b -> iso.decode(b, bytes, 320, 320) })
            @Suppress("UNCHECKED_CAST")
            val r = d.result as? Pair<IsoClient.Decoded?, android.os.SharedMemory>
            if (r?.first == null) failures++ else IsoClient.takeAndZero(r.second, r.first!!.w * r.first!!.h * 4)
            // Total = bind + decode + copy, not the death wait.
            total += d.bindMs + d.callMs
            bind += d.bindMs
            if (d.deathMs >= 0) death += d.deathMs
            pids += d.pid
        }
        fun stats(v: List<Double>): String {
            if (v.isEmpty()) return "n=0"
            val s = v.sorted()
            return "n=${s.size} min=${"%.1f".format(s.first())} median=${"%.1f".format(s[s.size / 2])} p90=${"%.1f".format(s[(s.size * 9) / 10])} max=${"%.1f".format(s.last())} ms"
        }
        report("vm18 requests=$n failures=$failures distinctPids=${pids.size}")
        report("vm18 bind(to onServiceConnected): ${stats(bind)}")
        report("vm18 bind+decode 320px+reply: ${stats(total)}")
        report("vm18 unbind->binderDied: ${stats(death)} (deaths observed ${death.size}/$n)")
    }

    private fun unguarded() {
        val d = iso.oneShot("unguarded", { b -> iso.ping(b).pid }, timeoutMs = 15_000)
        report("vm19 unguarded (MC-M23: Application work in the isolated process): pid=${d.pid} callback=${d.callback} bindMs=${"%.1f".format(d.bindMs)} result=${d.result}")
        val g = iso.oneShot("guarded", { b -> iso.ping(b).pid })
        report("vm19 guarded control: pid=${g.pid} callback=${g.callback} bindMs=${"%.1f".format(g.bindMs)}")
    }

    private fun crash() {
        val mode = arg("mode", "1").toInt()
        val t = System.currentTimeMillis()
        val d = iso.oneShot("crash", { b -> iso.crash(b, mode); "returned" }, timeoutMs = 15_000)
        report("vm20 crash mode=$mode pid=${d.pid} callback=${d.callback} result=${d.result} deathMs=${"%.1f".format(d.deathMs)} wallclockMs=$t")
    }

    // ---------------------------------------------------------------- V-M6 Bitmap.compress variants
    private fun compress() {
        outDir.mkdirs()
        val base = SourceMaker.orientationBase()
        fun save(name: String, b: Bitmap, q: Int = 85) {
            val bytes = SourceMaker.jpegBytes(b, q)
            File(outDir, "cmp_$name.jpg").writeBytes(bytes)
            report("vm6 cmp_$name.jpg: ${bytes.size} B config=${b.config} cs=${b.colorSpace?.name} ${if (Build.VERSION.SDK_INT >= 34) "hasGainmap=${b.hasGainmap()}" else ""}")
        }
        save("srgb_q85", base)
        save("srgb_q60", base, 60)
        save("srgb_q100", base, 100)
        save("rgb565", base.copy(Bitmap.Config.RGB_565, false))
        val p3 = Bitmap.createBitmap(640, 480, Bitmap.Config.ARGB_8888, false, ColorSpace.get(ColorSpace.Named.DISPLAY_P3))
        Canvas(p3).drawBitmap(base, 0f, 0f, null)
        save("displayp3", p3)
        val f16 = Bitmap.createBitmap(640, 480, Bitmap.Config.RGBA_F16, false, ColorSpace.get(ColorSpace.Named.LINEAR_EXTENDED_SRGB))
        Canvas(f16).drawBitmap(base, 0f, 0f, null)
        save("f16_linear_extended", f16)
        val exifDecoded = ImageDecoder.decodeBitmap(ImageDecoder.createSource(File(src, "orient6.jpg"))) { d, _, _ -> d.allocator = ImageDecoder.ALLOCATOR_SOFTWARE }
        save("from_exif_source", exifDecoded)
        if (Build.VERSION.SDK_INT >= 34) {
            val g = base.copy(Bitmap.Config.ARGB_8888, true)
            val gm = Bitmap.createBitmap(150, 100, Bitmap.Config.ALPHA_8)
            Canvas(gm).drawColor(Color.argb(200, 0, 0, 0))
            g.gainmap = Gainmap(gm)
            save("with_gainmap", g)
            g.gainmap = null
            save("gainmap_removed", g)
            val u = File(src, "ultrahdr.jpg")
            if (u.exists()) {
                val d = ImageDecoder.decodeBitmap(ImageDecoder.createSource(u)) { dec, _, _ -> dec.allocator = ImageDecoder.ALLOCATOR_SOFTWARE }
                save("decoded_ultrahdr", d)
                val d2 = d.copy(Bitmap.Config.ARGB_8888, true)
                d2.gainmap = null
                save("decoded_ultrahdr_gainmap_removed", d2)
                val d3 = ImageDecoder.decodeBitmap(ImageDecoder.createSource(u)) { dec, _, _ -> dec.allocator = ImageDecoder.ALLOCATOR_SOFTWARE; dec.setTargetColorSpace(ColorSpace.get(ColorSpace.Named.SRGB)) }
                save("decoded_ultrahdr_srgb_target", d3)
            }
        }
    }

    // ---------------------------------------------------------------- V-M13 platform diagnostics
    private fun play() {
        val diag = arg("diag", "0") == "1"
        val data = File(outDir, arg("file", "match720p30__DESIGN_mfra.mp4")).readBytes()
        val ht = HandlerThread("player").apply { start() }
        val h = Handler(ht.looper)
        val reader = ImageReader.newInstance(1280, 1280, ImageFormat.YUV_420_888, 4)
        reader.setOnImageAvailableListener({ r -> r.acquireLatestImage()?.close() }, h)
        val ended = CountDownLatch(1)
        lateinit var player: ExoPlayer
        val ef = ExtractorsFactory { arrayOf(FragmentedMp4Extractor(SubtitleParser.Factory.UNSUPPORTED, FragmentedMp4Extractor.FLAG_READ_MFRA_FOR_SEEK_MAP)) }
        val t0 = System.currentTimeMillis()
        h.post {
            player = ExoPlayer.Builder(ctx, ProgressiveMediaSource.Factory({ ByteArrayDataSource(data) }, ef))
                .setLooper(ht.looper).setUsePlatformDiagnostics(diag).build()
            player.setVideoSurface(reader.surface)
            player.addListener(object : Player.Listener {
                override fun onPlaybackStateChanged(s: Int) { if (s == Player.STATE_ENDED) ended.countDown() }
            })
            player.setMediaItem(MediaItem.fromUri(Uri.parse("ghost://object")))
            player.prepare()
            player.play()
        }
        ended.await(60, TimeUnit.SECONDS)
        h.post { player.release() }
        Thread.sleep(500)
        reader.close()
        ht.quitSafely()
        report("vm13 played ${data.size} B with setUsePlatformDiagnostics($diag) from $t0 to ${System.currentTimeMillis()}")
    }

    // ---------------------------------------------------------------- V-M16 mtime
    private fun mtime() {
        val dir = File(ctx.noBackupFilesDir, "m").apply { mkdirs() }
        report("vm16 dir=${dir.path} fs=" + File("/proc/mounts").readLines().filter { " /data " in it }.joinToString(" | "))
        val rnd = java.security.SecureRandom()
        for (i in 0 until arg("n", "17").toInt()) {
            val name = IsoClient.randomHex(16)
            val f = File(dir, name)
            val blob = ByteArray(65_536).also { rnd.nextBytes(it) }
            FileOutputStream(f).use { it.write(blob); it.channel.force(true) }
            val fd = Os.open(dir.path, OsConstants.O_RDONLY, 0)
            Os.fsync(fd); Os.close(fd)
            val before = Os.stat(f.path)
            val setOk = f.setLastModified(0)
            val after = Os.stat(f.path)
            // The fix under test: atime too (setLastModified leaves atime at the creation time, and
            // /data is mounted noatime, so it never moves again).
            java.nio.file.Files.getFileAttributeView(f.toPath(), java.nio.file.attribute.BasicFileAttributeView::class.java)
                .setTimes(java.nio.file.attribute.FileTime.fromMillis(0), java.nio.file.attribute.FileTime.fromMillis(0), null)
            val after2 = Os.stat(f.path)
            report("vm16 $name size=${after.st_size} ino=${after.st_ino} setLastModified(0)=$setOk File.lastModified=${f.lastModified()} mtime ${before.st_mtime}->${after.st_mtime} ctime ${before.st_ctime}->${after.st_ctime} atime ${before.st_atime}->${after.st_atime}; after setTimes(0,0): mtime=${after2.st_mtime} atime=${after2.st_atime} ctime=${after2.st_ctime}")
        }
    }

    // ---------------------------------------------------------------- V-M23 video preview
    private fun preview() {
        val names = arg("files", "match720p30.mp4,rot90_1280x720p30.mp4,port720x1280p24.mp4").split(",")
        // `-e formats yuv` or `private` restricts the reader formats (both work on API 29 and 35).
        val formats = arg("formats", "yuv,private").split(",").map { if (it == "yuv") ImageFormat.YUV_420_888 else ImageFormat.PRIVATE }
        val before = inventory(ctx)
        val watch = FsWatch(ctx)
        for (n in names) {
            for (fmt in formats) {
                val ht = HandlerThread("preview").apply { start() }
                val h = Handler(ht.looper)
                val reader = ImageReader.newInstance(1920, 1920, fmt, 2)
                val got = CountDownLatch(1)
                var desc = "none"
                reader.setOnImageAvailableListener({ r ->
                    val img = r.acquireLatestImage()
                    if (img != null) {
                        desc = "image ${img.width}x${img.height} format=${img.format} planes=${img.planes.size} ts=${img.timestamp}"
                        if (img.format == ImageFormat.YUV_420_888) {
                            val y = img.planes[0].buffer
                            var sum = 0L; var cnt = 0
                            while (y.hasRemaining() && cnt < 100_000) { sum += (y.get().toInt() and 0xff); cnt++ }
                            desc += " meanLuma=${sum / maxOf(1, cnt)}"
                            // V-M17 colour check: the coded luma range of the picture area (a
                            // full-range source spans 0..255; converted to limited range, 16..235).
                            val p = img.planes[0]
                            var lo = 255; var hi = 0
                            for (row in 0 until img.height step 4) for (col in 0 until img.width step 2) {
                                val v = p.buffer.get(row * p.rowStride + col * p.pixelStride).toInt() and 0xff
                                if (v < lo) lo = v
                                if (v > hi) hi = v
                            }
                            desc += " lumaMin=$lo lumaMax=$hi"
                        }
                        img.close()
                        got.countDown()
                    }
                }, h)
                lateinit var player: ExoPlayer
                var size = ""
                var err = ""
                h.post {
                    player = ExoPlayer.Builder(ctx, ProgressiveMediaSource.Factory({ ContentDataSource(ctx) }, DefaultExtractorsFactory()))
                        .setLooper(ht.looper).setUsePlatformDiagnostics(false).build()
                    player.addListener(object : Player.Listener {
                        override fun onVideoSizeChanged(v: androidx.media3.common.VideoSize) { size = "${v.width}x${v.height} rot=${v.unappliedRotationDegrees}" }
                        override fun onPlayerError(e: androidx.media3.common.PlaybackException) { err = e.errorCodeName; got.countDown() }
                    })
                    player.setVideoSurface(reader.surface)
                    player.setMediaItem(MediaItem.fromUri(SourceProvider.uri(n)))
                    player.prepare()
                }
                val ok = got.await(20, TimeUnit.SECONDS)
                h.post { player.release() }
                Thread.sleep(300)
                reader.close()
                ht.quitSafely()
                report("vm23 $n readerFormat=$fmt frame=$ok videoSize=$size $desc error=$err")
            }
        }
        val events = watch.stop()
        val diff = inventoryDiff(before, inventory(ctx))
        report("vm23 fileObserverEvents=${events.size} inventoryChanges=${diff.size}")
        events.take(50).forEach { report("vm23 event: $it") }
        diff.take(50).forEach { report("vm23 diff: $it") }
    }

    // ---------------------------------------------------------------- V-M9 (emulator half) JCA ChaCha20-Poly1305
    private fun bench() {
        val size = arg("bytes", "52428800").toInt()
        val chunk = 262_128
        val key = ByteArray(32).also { java.security.SecureRandom().nextBytes(it) }
        val pt = ByteArray(chunk).also { java.util.Random(1).nextBytes(it) }
        val c = Cipher.getInstance("ChaCha20/Poly1305/NoPadding")
        report("vm9 JCA provider=${c.provider.name} ${c.provider.version}")
        val chunks = (size + chunk - 1) / chunk
        val t0 = SystemClock.elapsedRealtimeNanos()
        var total = 0L
        for (i in 0 until chunks) {
            val nonce = ByteArray(12).also { java.nio.ByteBuffer.wrap(it, 7, 4).putInt(i); it[11] = if (i == chunks - 1) 1 else 0 }
            val cc = Cipher.getInstance("ChaCha20/Poly1305/NoPadding")
            cc.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "ChaCha20"), IvParameterSpec(nonce))
            cc.updateAAD(byteArrayOf(1, 2, 3))
            total += cc.doFinal(pt).size
        }
        val s = (SystemClock.elapsedRealtimeNanos() - t0) / 1e9
        report("vm9 JCA ChaCha20-Poly1305 sealed $chunks chunks (${chunks.toLong() * chunk} B) in ${"%.3f".format(s)} s = ${"%.1f".format(chunks.toLong() * chunk / s / 1e6)} MB/s; appVmHWM=${procStatus("VmHWM")}kB")
    }

    // ---------------------------------------------------------------- V-M17 coded luma range
    /**
     * Decodes the first video frame of each `-e files` source with `MediaCodec` into a buffer (no
     * surface, so no colour conversion between the decoder and the reader) and reports the range
     * of the coded luma values and the colour fields of the decoder's output format: a full-range
     * picture spans about 0..255, a limited-range one 16..235. The preview path (a Surface into an
     * ImageReader) cannot answer this: on the emulators it hands back 16..235 for every input.
     */
    private fun lumaRange() {
        for (n in arg("files", "match720p30.mp4").split(",")) {
            val ex = android.media.MediaExtractor()
            ex.setDataSource(File(src, n).absolutePath)
            val track = (0 until ex.trackCount).first { ex.getTrackFormat(it).getString(android.media.MediaFormat.KEY_MIME)!!.startsWith("video/") }
            ex.selectTrack(track)
            val fmt = ex.getTrackFormat(track)
            fmt.setInteger(android.media.MediaFormat.KEY_COLOR_FORMAT, android.media.MediaCodecInfo.CodecCapabilities.COLOR_FormatYUV420Flexible)
            val codec = android.media.MediaCodec.createDecoderByType(fmt.getString(android.media.MediaFormat.KEY_MIME)!!)
            codec.configure(fmt, null, null, 0)
            codec.start()
            val info = android.media.MediaCodec.BufferInfo()
            var result = "no frame"
            var inputDone = false
            val deadline = SystemClock.elapsedRealtime() + 20_000
            while (result == "no frame" && SystemClock.elapsedRealtime() < deadline) {
                if (!inputDone) {
                    val ii = codec.dequeueInputBuffer(10_000)
                    if (ii >= 0) {
                        val sz = ex.readSampleData(codec.getInputBuffer(ii)!!, 0)
                        if (sz < 0) { codec.queueInputBuffer(ii, 0, 0, 0, android.media.MediaCodec.BUFFER_FLAG_END_OF_STREAM); inputDone = true }
                        else { codec.queueInputBuffer(ii, 0, sz, ex.sampleTime, 0); ex.advance() }
                    }
                }
                val oi = codec.dequeueOutputBuffer(info, 10_000)
                if (oi >= 0) {
                    codec.getOutputImage(oi)?.use { img ->
                        val p = img.planes[0]
                        var lo = 255; var hi = 0; var sum = 0L; var cnt = 0L
                        for (row in 0 until img.height step 2) for (col in 0 until img.width step 2) {
                            val v = p.buffer.get(row * p.rowStride + col * p.pixelStride).toInt() and 0xff
                            if (v < lo) lo = v
                            if (v > hi) hi = v
                            sum += v; cnt++
                        }
                        val of = codec.outputFormat
                        fun f(k: String) = if (of.containsKey(k)) of.getInteger(k).toString() else "-"
                        result = "${img.width}x${img.height} lumaMin=$lo lumaMax=$hi lumaMean=${sum / cnt} outputFormat colorStandard=${f(android.media.MediaFormat.KEY_COLOR_STANDARD)} colorRange=${f(android.media.MediaFormat.KEY_COLOR_RANGE)} colorTransfer=${f(android.media.MediaFormat.KEY_COLOR_TRANSFER)}"
                    }
                    codec.releaseOutputBuffer(oi, false)
                }
            }
            report("vm17 luma $n decoder=${codec.name} $result")
            codec.stop(); codec.release(); ex.release()
        }
    }

    // ---------------------------------------------------------------- V-M21 / V-M11 picker
    private fun pick() {
        PickActivity.result = null
        PickActivity.picked = null
        PickActivity.done = CountDownLatch(1)
        val before = inventory(ctx)
        PickActivity.watch = FsWatch(ctx)
        val i = Intent(ctx, PickActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        ctx.startActivity(i)
        report("vm21 picker launched at ${System.currentTimeMillis()}; waiting for the host to pick")
        val ok = PickActivity.done!!.await(arg("waitS", "180").toLong(), TimeUnit.SECONDS)
        val events = PickActivity.watch!!.stop()
        val diff = inventoryDiff(before, inventory(ctx))
        report("vm21 picked=$ok ${PickActivity.result}")
        report("vm11 read of the picked stream: fileObserverEvents=${events.size} inventoryChanges=${diff.size}")
        events.take(50).forEach { report("vm11 event: $it") }
        diff.take(50).forEach { report("vm11 diff: $it") }
        // After the observation only: the bytes the picker handed over, for the host to compare
        // with the file that was pushed (does the picker pass the file through unchanged?).
        PickActivity.picked?.let { File(ctx.filesDir, "picked.bin").writeBytes(it); report("vm21 picked bytes saved to files/picked.bin after the watch") }
        PickActivity.picked = null
    }
}
