package org.ghost.messaging.engine

import org.ghost.media.send.ImageStripper
import org.ghost.media.send.JpegCanonicalizer
import org.ghost.media.send.MediaPreparer
import org.ghost.media.send.MediaSealerFactory
import org.ghost.media.send.VideoExport
import org.ghost.media.store.CiphertextFiles
import org.ghost.media.store.PreparingFiles

/**
 * The device-side pieces the sender pipeline needs, injected by the wiring (`:app` on a device,
 * fakes in the worlds, §15.1): the ciphertext file store the sealer writes, and the [MediaPreparer]
 * ports — the sandbox stripper, the video export, the sealer factory over the native context, and
 * the JPEG canonicaliser. Null wherever media is not wired (every Phase 9 world): the facade then
 * answers `CRYPTO_UNAVAILABLE`.
 */
class MediaPipelinePorts(
    val files: CiphertextFiles,
    val preparing: PreparingFiles,
    val stripper: ImageStripper,
    val video: VideoExport,
    val sealerFactory: MediaSealerFactory,
    val canonicalizer: JpegCanonicalizer,
) {
    fun preparer(): MediaPreparer =
        MediaPreparer(stripper, video, sealerFactory, canonicalizer, files, preparing)
}
