package org.ghost.messaging.engine

import org.ghost.media.send.ImageDecoder
import org.ghost.media.send.ImageStripper
import org.ghost.media.send.VideoExport
import org.ghost.media.store.CiphertextFiles
import org.ghost.media.store.PreparingFiles
import org.ghost.messaging.port.MediaReaders

/**
 * The device-side pieces the media pipelines need, injected by the wiring (`:app` on a device,
 * fakes in the worlds, §15.1): the ciphertext file store the sealer writes and the ingest reads,
 * the [org.ghost.media.send.MediaPreparer] ports that need a device — the sandbox stripper and the
 * video export —, and the recipient half (slice S6): the reader surface behind `MEDIA-BIND`/
 * `MEDIA-VERIFY`/the preview path and the sandbox image decoder behind `mediaPreview`. The sealer
 * factory and the canonicaliser are built inside [MediaEngineSupport], from the DM crypto port and
 * `MediaCrypto` (keeping the native context handle inside `:messaging`, where the context lives).
 * Null wherever media is not wired (every Phase 9 world): the facade then answers
 * `CRYPTO_UNAVAILABLE` and previews answer null.
 */
class MediaPipelinePorts(
    val files: CiphertextFiles,
    val preparing: PreparingFiles,
    val stripper: ImageStripper,
    val video: VideoExport,
    /** S6: the M5–M8 reader surface; the device binding resolves the DM context per call. */
    val readers: MediaReaders,
    /** S6: `DECODE_IMAGE` behind the preview path, so the zero-click rules are provable with a fake. */
    val decoder: ImageDecoder,
)
