package org.ghost.spike.r8

import android.content.Context
import android.graphics.Bitmap
import android.media.MediaCodecInfo
import android.net.Uri
import android.os.Looper
import androidx.media3.common.C
import androidx.media3.common.Format
import androidx.media3.common.MediaItem
import androidx.media3.common.Metadata
import androidx.media3.common.MimeTypes
import androidx.media3.common.audio.ChannelMixingAudioProcessor
import androidx.media3.common.audio.ChannelMixingMatrix
import androidx.media3.common.audio.SonicAudioProcessor
import androidx.media3.common.util.BitmapLoader
import androidx.media3.common.util.Clock
import androidx.media3.common.util.Log
import androidx.media3.container.Mp4OrientationData
import androidx.media3.container.Mp4TimestampData
import androidx.media3.datasource.BaseDataSource
import androidx.media3.datasource.ContentDataSource
import androidx.media3.datasource.DataSource
import androidx.media3.datasource.DataSpec
import androidx.media3.effect.FrameDropEffect
import androidx.media3.effect.Presentation
import androidx.media3.exoplayer.DefaultLoadControl
import androidx.media3.exoplayer.ExoPlayer
import androidx.media3.exoplayer.Renderer
import androidx.media3.exoplayer.RenderersFactory
import androidx.media3.exoplayer.audio.MediaCodecAudioRenderer
import androidx.media3.exoplayer.mediacodec.MediaCodecSelector
import androidx.media3.exoplayer.source.ProgressiveMediaSource
import androidx.media3.exoplayer.video.MediaCodecVideoRenderer
import androidx.media3.extractor.ExtractorsFactory
import androidx.media3.extractor.mp4.FragmentedMp4Extractor
import androidx.media3.extractor.mp4.Mp4Extractor
import androidx.media3.extractor.text.SubtitleParser
import androidx.media3.muxer.BufferInfo
import androidx.media3.muxer.FragmentedMp4Muxer
import androidx.media3.muxer.Muxer
import androidx.media3.transformer.Composition
import androidx.media3.transformer.DefaultAssetLoaderFactory
import androidx.media3.transformer.DefaultDecoderFactory
import androidx.media3.transformer.DefaultEncoderFactory
import androidx.media3.transformer.EditedMediaItem
import androidx.media3.transformer.EditedMediaItemSequence
import androidx.media3.transformer.Effects
import androidx.media3.transformer.Transformer
import androidx.media3.transformer.VideoEncoderSettings
import com.google.common.collect.ImmutableList
import com.google.common.util.concurrent.Futures
import com.google.common.util.concurrent.ListenableFuture
import java.io.ByteArrayOutputStream
import java.nio.ByteBuffer
import java.nio.channels.Channels

/** Media flavour: Media3 used the way design §8.3 and §10.2 use it (reachable from [Main]). */
object Probe {
    /** A stand-in for GhostMediaDataSource: bytes from memory, nothing cached. */
    class MemorySource(private val data: ByteArray) : BaseDataSource(false) {
        private var pos = 0
        private var uri: Uri? = null
        override fun open(dataSpec: DataSpec): Long {
            uri = dataSpec.uri
            pos = dataSpec.position.toInt()
            transferStarted(dataSpec)
            return (data.size - pos).toLong()
        }
        override fun read(buffer: ByteArray, offset: Int, length: Int): Int {
            if (pos >= data.size) return C.RESULT_END_OF_INPUT
            val n = minOf(length, data.size - pos)
            System.arraycopy(data, pos, buffer, offset, n)
            pos += n
            bytesTransferred(n)
            return n
        }
        override fun getUri(): Uri? = uri
        override fun close() {
            transferEnded()
        }
    }

    class Ghost(out: ByteArrayOutputStream) : Muxer {
        private val inner = FragmentedMp4Muxer.Builder(Channels.newChannel(out)).build()
        init { inner.addMetadataEntry(Mp4TimestampData(0, 0)) }
        override fun addTrack(format: Format): Int {
            val id = inner.addTrack(format)
            if (MimeTypes.isVideo(format.sampleMimeType)) inner.addMetadataEntry(Mp4OrientationData(format.rotationDegrees))
            return id
        }
        override fun writeSampleData(trackId: Int, data: ByteBuffer, bufferInfo: BufferInfo) = inner.writeSampleData(trackId, data, bufferInfo)
        override fun addMetadataEntry(metadataEntry: Metadata.Entry) {}
        override fun close() = inner.close()
    }

    fun run(ctx: Context): String {
        Log.setLogLevel(Log.LOG_LEVEL_OFF)
        val ef = ExtractorsFactory { arrayOf(FragmentedMp4Extractor(SubtitleParser.Factory.UNSUPPORTED, FragmentedMp4Extractor.FLAG_READ_MFRA_FOR_SEEK_MAP)) }
        // Review I2/H2 (2026-10-04): the player as G-M3 requires it, a renderers factory that
        // builds only a MediaCodec video and a MediaCodec audio renderer (the 2026-09-25 probe used
        // ExoPlayer.Builder(ctx, mediaSourceFactory), i.e. DefaultRenderersFactory, which keeps
        // ImageRenderer -> BitmapFactoryImageDecoder, TextRenderer and MetadataRenderer).
        val renderers = RenderersFactory { h, v, a, _, _ ->
            arrayOf<Renderer>(MediaCodecVideoRenderer(ctx, MediaCodecSelector.DEFAULT, 0L, h, v, 50), MediaCodecAudioRenderer(ctx, MediaCodecSelector.DEFAULT, h, a))
        }
        val player = ExoPlayer.Builder(ctx, renderers, ProgressiveMediaSource.Factory({ MemorySource(ByteArray(16)) }, ef))
            .setUsePlatformDiagnostics(false)
            .setLoadControl(DefaultLoadControl.Builder().setBufferDurationsMs(5_000, 15_000, 1_000, 2_000).setTargetBufferBytes(8 shl 20).build())
            .build()
        player.setMediaItem(MediaItem.fromUri("ghost://object"))
        player.prepare()
        val out = ByteArrayOutputStream()
        val muxerFactory = object : Muxer.Factory {
            override fun create(path: String): Muxer = Ghost(out)
            override fun getSupportedSampleMimeTypes(trackType: Int): ImmutableList<String> =
                if (trackType == C.TRACK_TYPE_VIDEO) ImmutableList.of(MimeTypes.VIDEO_H264) else ImmutableList.of(MimeTypes.AUDIO_AAC)
        }
        val noBitmaps = object : BitmapLoader {
            override fun supportsMimeType(mimeType: String) = false
            override fun decodeBitmap(data: ByteArray): ListenableFuture<Bitmap> = Futures.immediateFailedFuture(UnsupportedOperationException())
            override fun loadBitmap(uri: Uri): ListenableFuture<Bitmap> = Futures.immediateFailedFuture(UnsupportedOperationException())
        }
        val encoders = DefaultEncoderFactory.Builder(ctx)
            .setRequestedVideoEncoderSettings(
                VideoEncoderSettings.Builder().setBitrate(2_000_000)
                    .setEncodingProfileLevel(MediaCodecInfo.CodecProfileLevel.AVCProfileBaseline, MediaCodecInfo.CodecProfileLevel.AVCLevel31)
                    .setMaxBFrames(0).setiFrameIntervalSeconds(1f).build(),
            )
            .build()
        // Review I2: sources are parsed by Mp4Extractor alone (no DefaultExtractorsFactory).
        val sourceExtractors = ExtractorsFactory { arrayOf(Mp4Extractor(SubtitleParser.Factory.UNSUPPORTED)) }
        val sonic = SonicAudioProcessor().apply { setOutputSampleRateHz(48_000) }
        val mixer = ChannelMixingAudioProcessor().apply { putChannelMixingMatrix(ChannelMixingMatrix.createForConstantGain(1, 2)) }
        val transformer = Transformer.Builder(ctx)
            .setLooper(Looper.getMainLooper())
            .setVideoMimeType(MimeTypes.VIDEO_H264)
            .setAudioMimeType(MimeTypes.AUDIO_AAC)
            .setEncoderFactory(encoders)
            .setAssetLoaderFactory(
                DefaultAssetLoaderFactory(
                    ctx, DefaultDecoderFactory.Builder(ctx).build(), Clock.DEFAULT,
                    ProgressiveMediaSource.Factory(DataSource.Factory { ContentDataSource(ctx) }, sourceExtractors), noBitmaps,
                ),
            )
            .setMuxerFactory(muxerFactory)
            .setUsePlatformDiagnostics(false)
            .build()
        val item = EditedMediaItem.Builder(MediaItem.fromUri("content://x/y"))
            .setEffects(Effects(listOf(sonic, mixer), listOf(Presentation.createForWidthAndHeight(1280, 720, Presentation.LAYOUT_SCALE_TO_FIT), FrameDropEffect.createDefaultFrameDropEffect(30f))))
            .build()
        transformer.start(
            Composition.Builder(EditedMediaItemSequence.Builder(item).experimentalSetForceAudioTrack(true).build())
                .setHdrMode(Composition.HDR_MODE_TONE_MAP_HDR_TO_SDR_USING_OPEN_GL)
                .build(),
            "/unused",
        )
        return "media " + player.playbackState
    }
}
