package org.ghost.media.play

import java.io.IOException

/**
 * The one seam between playback and the engine (Phase 11 design §10.2, slice S7): what
 * [GhostMediaDataSource] needs of an opened media object, supplied by `:messaging` over the
 * reader surface (`MediaReaders`) and the ciphertext file store. `:media` owns the Media3
 * glue; the reader, the fragment rows and the database stay in the engine, exactly as the
 * preview path keeps them (slice S6).
 *
 * One [MediaPlayable] is one open native reader over one object. [readChunk] is random
 * access — the reader's `READ` mode serves any index in any order — so Media3's re-opens
 * after a seek land on the same cursor. The implementation erases the fragment bytes it
 * assembled and hands out each plaintext chunk exactly once per call; the data source
 * erases its cached copy on eviction and at [close] (§10.5's hygiene, as far as the
 * JVM-held copy can honour it: the native plaintext is zeroised by the reader itself).
 */
interface MediaPlayable {

    /** The object's exact content length (the manifest's `content_len`). */
    val contentLength: Long

    /**
     * The plaintext of chunk [index] (at most [org.ghost.media.store.MediaLimits.CHUNK_PLAINTEXT]
     * bytes; the last chunk may be shorter). The caller erases the returned array when done.
     *
     * @throws MediaPlayException.Corrupt a fragment fails authentication or the chunk's tag
     *         does not verify — the object is being recorded `corrupt` by the caller.
     * @throws MediaPlayException.Closed the reader or its context is gone (a lock, a wipe,
     *         a handle closed by the UI): a typed playback error, never a crash.
     * @throws MediaPlayException.Defect an index or sequencing refusal the reader's `READ`
     *         mode must not produce: a GHOST bug, surfaced like every other (sync-no-catch-all).
     */
    fun readChunk(index: Int): ByteArray

    /** Close the native reader and zeroise what it holds (§13.2 M8). Idempotent in effect. */
    fun close()
}

/** What [GhostMediaDataSource] may throw, mapped one-to-one from the reader's refusals. */
sealed class MediaPlayException(message: String, cause: Throwable?) : IOException(message, cause) {

    /**
     * `HASH_MISMATCH` or `NOT_OPEN` from a chunk read (§7.3): the object is recorded
     * `verified → corrupt` by the engine before this reaches the player.
     */
    class Corrupt(cause: Throwable? = null) : MediaPlayException("media object corrupt", cause)

    /** The reader or the DM context is gone (a lock, a wipe, a UI close). */
    class Closed(cause: Throwable? = null) : MediaPlayException("media reader closed", cause)

    /** `SEQUENCE` or `INDEX_RANGE` in random-access mode: a GHOST defect, not bad media. */
    class Defect(message: String, cause: Throwable? = null) : MediaPlayException(message, cause)
}
