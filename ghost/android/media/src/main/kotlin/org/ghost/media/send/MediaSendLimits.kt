package org.ghost.media.send

import org.ghost.media.store.MediaLimits

/**
 * The sender pipeline's constants (Phase 11 design §3.1, §6.1, §6.6), the ones the stores do not
 * already hold. The class table itself lives in [MediaLimits] (the schema's CHECKs mirror it); the
 * video/image bounds and the worker's limits live here.
 */
object MediaSendLimits {
    /** The eleven size classes' fragment counts (§3.1): `class_code` is the index. */
    val CLASSES: IntArray get() = MediaLimits.CLASSES

    /** The largest class code (class 10, `F = 804`). */
    const val MAX_CLASS: Int = 10

    /** §3.1 `MAX_CONTENT` = 50 MiB: the largest content any object may seal. */
    const val MAX_CONTENT: Long = 52_428_800L

    /** §3.1 `IMAGE_MAX_CONTENT` = 4 × CHUNK_PT: an image always fits class 0. */
    const val IMAGE_MAX_CONTENT: Int = 4 * MediaLimits.CHUNK_PLAINTEXT

    /** §8.2: the canonical geometry's long-edge ladder top. */
    const val IMAGE_LONG_EDGE: Int = 2_048

    /** §8.2: the preview's long edge. */
    const val PREVIEW_LONG_EDGE: Int = 320

    /** §6.1: an image source's bounds, checked before a byte is decoded. */
    const val IMAGE_SOURCE_MAX_BYTES: Long = 64L * 1024 * 1024
    const val IMAGE_SOURCE_MAX_MEGAPIXELS: Long = 100_000_000L

    /** §6.1: a video source's duration bounds (the byte budget over 1.2 × 2.128 Mbit/s). */
    const val VIDEO_MAX_MS: Long = 160_000L
    const val VIDEO_MAX_MS_SHORT: Long = 85_000L

    /** §6.1: the profile's target video bitrate and the AAC-LC audio bitrate (§8.3). */
    const val VIDEO_TARGET_BITRATE: Int = 2_000_000
    const val AUDIO_TARGET_BITRATE: Int = 128_000

    /** §6.2/§8.3: the output's frame rate and the retry's. */
    const val OUTPUT_FPS: Float = 30f
    const val RETRY_FPS: Float = 15f

    /** §6.2: the encoder's requested key-frame interval (seconds). */
    const val KEY_FRAME_INTERVAL_S: Float = 1f

    /** §6.2: an export whose progress has not advanced for this long is cancelled (`STALLED`). */
    const val EXPORT_STALL_MS: Long = 30_000L

    /** §6.2: at most this many source audio channels are mixed down; more refuse the send. */
    const val MAX_AUDIO_CHANNELS: Int = 8

    /** §6.6: concurrent preparations, per object and per device upload windows. */
    const val MAX_CONCURRENT_PREPARATIONS: Int = 2
    const val MEDIA_WINDOW_PER_OBJECT: Int = MediaLimits.OPEN_PER_OBJECT
    const val MEDIA_WINDOW: Int = MediaLimits.OPEN_PER_DEVICE

    /** §6.6: a caption's bound; every media message stays in the 4 KiB class. */
    const val MAX_CAPTION_BYTES: Int = 1_024

    /** §6.5: a send is refused below `3 × F × 64 KiB` of free space (class 10's need). */
    val SEND_FREE_FLOOR: Long = 3L * MediaLimits.CLASSES[MAX_CLASS] * MediaLimits.FRAGMENT_BYTES

    /** §9.2: live decoder processes and the per-request timeout. */
    const val MAX_DECODER_PROCESSES: Int = 2
    const val SANDBOX_TIMEOUT_MS: Long = 10_000L

    /** The sealed-content cap of [classCode]: `min(MAX_CONTENT, F/4 × CHUNK_PT)` (§3.6, §6.1). */
    fun contentCapBytes(classCode: Int): Long {
        if (classCode !in CLASSES.indices) throw IllegalArgumentException("class_code")
        val chunks = CLASSES[classCode] / 4
        return minOf(MAX_CONTENT, chunks * MediaLimits.CHUNK_PLAINTEXT.toLong())
    }
}
