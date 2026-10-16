package org.ghost.media.send

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
import java.nio.ByteBuffer

/**
 * `GhostMuxer` of Phase 11 design §8.3: the one `Muxer` Transformer drives, around
 * `FragmentedMp4Muxer.Builder(WritableByteChannel)` (the `Mp4Muxer` alternative seeks back to patch
 * box sizes, so it cannot feed a one-pass sealer; `FragmentedMp4Writer` is strictly sequential).
 * The channel it writes into is a [SealingChannel]: the sealed bytes are the bytes the recipient's
 * walker validates, so this class is where metadata is dropped and where the writing-side bounds
 * are enforced **while writing** (§6.2), before a whole oversized export is buffered:
 *
 *  1. **No metadata passes.** [addMetadataEntry] forwards nothing; this muxer adds one constant
 *     `Mp4TimestampData(0, 0)` at construction (Media3's collector otherwise stamps the wall
 *     clock) and, for the video track, one `Mp4OrientationData(format.rotationDegrees)` when that
 *     is 0, 90, 180 or 270 (anything else fails the export) — the rotation Transformer carries
 *     only in `Format.rotationDegrees` (S0 V-M24), which is what Media3's own
 *     `InAppFragmentedMp4Muxer.addTrack` does.
 *  2. **Only H.264 video and AAC audio.** Any other offered track is refused.
 *  3. **The SEI filter** ([Avc.filterSample]): user-data SEI never reaches the muxer.
 *  4. **The fragment bound** (S0-2): the writer buffers a whole fragment before the sealing
 *     channel sees it, so this class mirrors the writer's flush rule (a fragment closes at the
 *     first video sync sample once the pending video samples span ≥ 2 s, first to last
 *     presentation time) on the samples it is given and fails as soon as one fragment's samples
 *     exceed [FRAGMENT_BOUND] — the walker's 16 MiB bound is the second line, in Rust.
 *  5. **The class cap while writing** (§6.2, S0-18): the channel's byte count is the sealed
 *     stream's length (samples plus the container's boxes plus the inserted `tfdt`s), checked
 *     against the largest class the send may use; the moment it trips, [Oversize] carries the
 *     projection `bytes × source duration ÷ media time written`, which decides the 15-fps retry.
 *  6. **The preview's input** (S0-19): a copy of the first video sync sample after the SEI filter
 *     and the video track's `avcC` (the format's csd), for [GhostTranscoder] to decode after the
 *     export — the preview comes from the canonical output, never from the source.
 *
 * Runs on the media worker thread (§13.7); no logging, no clock (§13.1).
 */
class GhostMuxer(
    private val channel: SealingChannel,
    private val sourceDurationUs: Long,
    private val maxClass: Int,
) : Muxer {

    private val inner: FragmentedMp4Muxer = FragmentedMp4Muxer.Builder(channel).build()
    private val mime = HashMap<Int, String>()

    // The fragment-bound mirror (point 4).
    private var fragmentStartUs = -1L
    private var lastVideoUs = -1L
    private var fragmentBytes = 0L

    // The class cap (point 5) and the media time for the projection.
    private var mediaWrittenUs = 0L

    // The preview input (point 6).
    private var firstSync: ByteArray? = null
    private var avcC: ByteArray? = null
    private var videoRotation = 0

    /** What [GhostTranscoder] reads after a successful export: the preview decode input. */
    class PreviewInput(val firstSyncSample: ByteArray, val avcC: ByteArray)

    init {
        inner.addMetadataEntry(Mp4TimestampData(0, 0))
    }

    /** The output track's rotation degrees: what the preview is turned by (S0-20). */
    fun rotationDegrees(): Int = videoRotation

    /** The preview input captured during the export, or null when the export failed first. */
    fun previewInput(): PreviewInput? {
        val sample = firstSync ?: return null
        val csd = avcC ?: return null
        return PreviewInput(sample, csd)
    }

    override fun addTrack(format: Format): Int {
        val m = format.sampleMimeType ?: ""
        if (m != MimeTypes.VIDEO_H264 && m != MimeTypes.AUDIO_AAC) {
            throw MuxerException("GhostMuxer refuses track $m", IllegalArgumentException(m))
        }
        val id = inner.addTrack(format)
        if (m == MimeTypes.VIDEO_H264) {
            if (format.rotationDegrees !in listOf(0, 90, 180, 270)) {
                throw MuxerException(
                    "GhostMuxer refuses rotation ${format.rotationDegrees}",
                    IllegalArgumentException("rotation"),
                )
            }
            videoRotation = format.rotationDegrees
            inner.addMetadataEntry(Mp4OrientationData(format.rotationDegrees))
            for (csd in format.initializationData) {
                // csd-0 is the avcC box in an H.264 format; keep the first.
                if (avcC == null && csd.size > 8) avcC = csd.copyOf()
            }
        }
        mime[id] = m
        return id
    }

    override fun writeSampleData(trackId: Int, data: ByteBuffer, info: BufferInfo) {
        if (mime[trackId] == MimeTypes.VIDEO_H264) {
            writeVideo(trackId, data, info)
        } else {
            fragmentBytes += data.remaining()
            checkFragmentBound()
            inner.writeSampleData(trackId, data, info)
        }
        checkClassCap()
    }

    private fun writeVideo(trackId: Int, data: ByteBuffer, info: BufferInfo) {
        val bytes = ByteArray(data.remaining())
        data.get(bytes)
        val filtered = Avc.filterSample(bytes)
        if (filtered.isEmpty()) {
            throw MuxerException("GhostMuxer: an empty video sample", IllegalArgumentException("sample"))
        }
        val sync = info.flags and C.BUFFER_FLAG_KEY_FRAME != 0
        if (sync) {
            if (firstSync == null) firstSync = filtered.copyOf()
            // The writer's flush rule mirrored: a sync sample closes the pending fragment once
            // its video samples span >= 2 s (first to last presentation time).
            if (fragmentStartUs < 0 || lastVideoUs - fragmentStartUs >= 2_000_000L) {
                fragmentStartUs = info.presentationTimeUs
                fragmentBytes = 0
            }
        }
        lastVideoUs = info.presentationTimeUs
        mediaWrittenUs = maxOf(mediaWrittenUs, info.presentationTimeUs)
        fragmentBytes += filtered.size
        checkFragmentBound()
        inner.writeSampleData(
            trackId,
            ByteBuffer.wrap(filtered),
            BufferInfo(info.presentationTimeUs, filtered.size, info.flags),
        )
    }

    override fun addMetadataEntry(entry: Metadata.Entry) {
        // Nothing forwards: location, timestamps, XMP and mdta entries die here (§8.3 point 1).
    }

    override fun close() {
        inner.close()
    }

    /** The bytes the sealing channel has accepted: the sealed stream's length so far. */
    private fun sealedBytes(): Long = channel.sealedBytes()

    private fun checkFragmentBound() {
        if (fragmentBytes > FRAGMENT_BOUND) {
            throw MuxerException("GhostMuxer: a fragment exceeds 16 MiB", FragmentTooLarge())
        }
    }

    private fun checkClassCap() {
        val bytes = sealedBytes()
        if (bytes > MediaSendLimits.contentCapBytes(maxClass)) {
            val mediaUs = maxOf(mediaWrittenUs, 1L)
            val projection = bytes.toDouble() * (sourceDurationUs.toDouble() / mediaUs.toDouble())
            throw MuxerException("GhostMuxer: above the class cap", Oversize(projection.toLong(), maxClass))
        }
    }

    /** A fragment's samples exceeded 16 MiB (detail `FRAGMENT_TOO_LARGE`). */
    class FragmentTooLarge : IllegalStateException("a fragment exceeds 16 MiB")

    /**
     * The class cap tripped while writing (detail `OVERSIZE`): [projection] is
     * `bytes × source duration ÷ media time written` at the tripping moment (§6.2).
     */
    class Oversize(val projection: Long, val maxClass: Int) :
        IllegalStateException("above the class cap for class $maxClass")

    /** The fragment bound of §8.3 point 5: 16 MiB of samples per fragment, both tracks. */
    companion object {
        const val FRAGMENT_BOUND: Long = 16L * 1024 * 1024
    }
}

/**
 * The `Muxer.Factory` Transformer requires: [create] ignores the path (nothing may ever write a
 * plaintext file, V-M1) and hands back the one [GhostMuxer] over the caller's [SealingChannel].
 */
class GhostMuxerFactory(
    private val channel: SealingChannel,
    private val sourceDurationUs: Long,
    private val maxClass: Int,
) : Muxer.Factory {
    override fun create(path: String): Muxer = GhostMuxer(channel, sourceDurationUs, maxClass)

    override fun getSupportedSampleMimeTypes(trackType: Int): ImmutableList<String> = when (trackType) {
        C.TRACK_TYPE_VIDEO -> ImmutableList.of(MimeTypes.VIDEO_H264)
        C.TRACK_TYPE_AUDIO -> ImmutableList.of(MimeTypes.AUDIO_AAC)
        else -> ImmutableList.of()
    }
}
