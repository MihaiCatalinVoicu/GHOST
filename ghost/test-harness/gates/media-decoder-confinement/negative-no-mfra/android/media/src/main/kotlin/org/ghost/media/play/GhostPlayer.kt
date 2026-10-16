package org.ghost.media.play

import androidx.media3.extractor.mp4.FragmentedMp4Extractor
import androidx.media3.exoplayer.video.MediaCodecVideoRenderer
import androidx.media3.exoplayer.audio.MediaCodecAudioRenderer

/** MC-M24's shape: the seek-map flag gone — every seek replays from the start. */
object GhostPlayer {
    val extractor = FragmentedMp4Extractor::class
    val video = MediaCodecVideoRenderer::class
    val audio = MediaCodecAudioRenderer::class
    const val DIAG = "setUsePlatformDiagnostics(false)"
    const val LOG = "Log.setLogLevel(Log.LOG_LEVEL_OFF)"
}
