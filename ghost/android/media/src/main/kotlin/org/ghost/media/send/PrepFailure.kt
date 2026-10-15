package org.ghost.media.send

/**
 * The typed outcome of a preparation that failed after `sendMedia` returned `QUEUED` (Phase 11
 * design §6.5, S0-23): `preparationState` reports one of these exactly once, counted locally, and
 * the registry forgets the preparation after its final state was read. `MediaResultCodesTest` is
 * exhaustive over this enumeration in the messaging facade.
 */
sealed class PrepFailure {
    /** The source could not be turned into the canonical output; [detail] says which stage. */
    class UnsupportedSource(val detail: Detail) : PrepFailure() {
        /** The stage that refused (§6.2's list). */
        enum class Detail {
            /** The container did not parse (`Mp4Extractor` refused it, S0-21). */
            CONTAINER,

            /** A decoder or the codec setup failed mid-export. */
            CODEC,

            /** More than 8 input audio channels. */
            CHANNELS,

            /** The GL stack failed (no OpenGL ES 3: `eglChooseConfig failed`, S0-1). */
            GL_UNAVAILABLE,

            /** One fragment's samples exceeded 16 MiB (the walker's bound is the second line). */
            FRAGMENT_TOO_LARGE,

            /** An encoder failed to configure or start (seen twice on the API 35 emulator, R-M19). */
            ENCODER_FAILED,

            /** The export stalled: no progress for `EXPORT_STALL_MS` (R-M19). */
            STALLED,

            /** The export ran no encoder for a track (transmuxed): the forcing wrapper was bypassed. */
            NOT_ENCODED,

            /** The encoder coded neither BT.601 nor BT.709 limited within 8 levels (S0-13). */
            COLOUR_UNVERIFIED,
        }
    }

    /** The image sandbox could not decode the source (a timeout, a crash, a bad answer). */
    data object Undecodable : PrepFailure()

    /** The output exceeded its class cap twice, or the projection was above twice the cap. */
    data object TooLarge : PrepFailure()

    /** [TooLarge] under R-MT2 (a 1-hour bucket's class-8 cap). */
    data object TooLargeForTimer : PrepFailure()

    /** The ciphertext store failed (a full disk or an I/O error). */
    data object StorageFull : PrepFailure()

    /** The user or the system cancelled the preparation. */
    data object Cancelled : PrepFailure()
}
