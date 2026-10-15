package org.ghost.messaging.engine

import org.ghost.media.send.ImageStripper
import org.ghost.media.send.VideoExport
import org.ghost.media.store.CiphertextFiles
import org.ghost.media.store.PreparingFiles

/**
 * The device-side pieces the sender pipeline needs, injected by the wiring (`:app` on a device,
 * fakes in the worlds, §15.1): the ciphertext file store the sealer writes, and the [org.ghost.media.send.MediaPreparer]
 * ports that need a device — the sandbox stripper and the video export. The sealer factory and the
 * canonicaliser are built inside [MediaEngineSupport], from the DM crypto port and `MediaCrypto`
 * (keeping the native context handle inside `:messaging`, where the context lives). Null wherever
 * media is not wired (every Phase 9 world): the facade then answers `CRYPTO_UNAVAILABLE`.
 */
class MediaPipelinePorts(
    val files: CiphertextFiles,
    val preparing: PreparingFiles,
    val stripper: ImageStripper,
    val video: VideoExport,
)
