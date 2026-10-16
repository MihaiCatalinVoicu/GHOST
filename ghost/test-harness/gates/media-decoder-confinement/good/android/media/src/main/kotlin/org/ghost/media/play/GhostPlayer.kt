package org.ghost.media.play

import androidx.media3.extractor.mp4.FragmentedMp4Extractor
import androidx.media3.exoplayer.video.MediaCodecVideoRenderer
import androidx.media3.exoplayer.audio.MediaCodecAudioRenderer

/** The one player builder (fixture shape; §10.2's configuration). */
object GhostPlayer {
    const val FLAG = FragmentedMp4Extractor.FLAG_READ_MFRA_FOR_SEEK_MAP
    val video = MediaCodecVideoRenderer::class
    val audio = MediaCodecAudioRenderer::class
    const val DIAG = "setUsePlatformDiagnostics(false)"
    const val LOG = "Log.setLogLevel(Log.LOG_LEVEL_OFF)"
}
