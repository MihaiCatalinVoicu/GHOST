package org.ghost.update.harness

import org.ghost.network.NetworkException

/**
 * A model mirror's hostile behaviour (Phase 14 design §11.2), applied where the honest model
 * serves bytes. A mode is one enum entry and one branch of [ModelMirror.serveBundle]/
 * [ModelMirror.serveApkChunk] — the world sets the mode's parameter (the equivocating bundle,
 * the dropped mid-range, the rollback generation) when it arms the mirror.
 *
 * The seam's honesty note: on the real wire, ENDLESS's bound and SLOW's deadline are enforced
 * inside the native Tor fetch; over the harness's byte seam they are modeled at the layer the
 * engine observes (an oversized answer, a clock stepped past the run's end).
 */
internal enum class MirrorMode {
    /** The honest mirror: the fresh bundle and the offered APK's exact bytes. */
    NONE,

    /** The expired-manifest bundle (an old manifest, expired on the trusted clock). */
    STALE,

    /** The previous generation's bundle (a lower pair than the client's stored one). */
    ROLLBACK,

    /** Bytes that are not a bundle at all. */
    GARBAGE,

    /** The honest bundle, cut short (a truncated answer). */
    TRUNCATE,

    /** This mirror's own manifest at the pair the other mirror serves differently. */
    EQUIVOCATE,

    /** An answer past the bundle's 1 MiB bound (the bound itself is the native fetch's). */
    ENDLESS,

    /** Chunks served only after the run's fixed end has passed (the run stalls out). */
    SLOW,

    /** The bundle with no proof section (the proof withheld). */
    WITHHOLD_PROOF,

    /** The bundle with another manifest's proof section (a proof of another file). */
    WRONG_PROOF,

    /** A manifest of another root, in the fixture chain's bundle. */
    MIXED_ROOT,

    /** The pair pushed to its maximum (the fast-forward). */
    FAST_FORWARD,

    /** A different APK (same length, different bytes: the full-file hash must catch it). */
    APK_SWAP,

    /** The offered APK with bytes spliced inside its signing block (same length). */
    APK_EXTRA,

    /** A middle chunk never served (the run aborts and resumes). */
    DROP_MID_RANGE,

    /** An old expired manifest with a higher pair (accepted as a fact, applied to nothing). */
    EXPIRED_REPLAY,

    /** The floor at the manifest's bound (accepted; the offer answers UNSUPPORTED below it). */
    FLOOR_MAX,

    /** The committed relays relabeled (the directory guard refuses the operator change). */
    RELABEL,
}

/**
 * One model mirror of the world (§11.2): it serves the bundle and the APK's fixed 4 MiB ranges
 * (§7.2) per its [mode], counts what it served (the world's mirror view, T51's observatory),
 * and holds the bytes under the names the engine asks for — the path and the range are built
 * natively (PM-D9, PM-D10), the harness only answers with bytes.
 */
internal class ModelMirror(
    val index: Int,
    var mode: MirrorMode = MirrorMode.NONE,
    /** The world clock (the SLOW mode steps it past the run's end). */
    var clock: VirtualClock? = null,
) {

    /** Served requests, the world-side view of what the mirrors saw. */
    val bundleRequests: Int get() = bundleRequestsN.get()
    val chunkRequests: Int get() = chunkRequestsN.get()
    private val bundleRequestsN = java.util.concurrent.atomic.AtomicInteger()
    private val chunkRequestsN = java.util.concurrent.atomic.AtomicInteger()
    var chunkIndexesServed: MutableList<Long> = mutableListOf()
        private set

    /** The EQUIVOCATE mode's bytes: this mirror's manifest at the shared pair. */
    var equivocateBundle: ByteArray? = null

    /** The ROLLBACK mode's bytes: the previous generation's bundle. */
    var rollbackBundle: ByteArray? = null

    /** The DROP_MID_RANGE mode's never-served chunk indexes. */
    var droppedChunks: Set<Long> = emptySet()

    /** The release under test when it is not the small fixture APK (the multi-chunk worlds). */
    var apkOverride: ByteArray? = null

    /** The bundle under test when it is not the small fixture bundle. */
    var bundleOverride: ByteArray? = null

    fun serveBundle(fixtures: WorldFixtures): ByteArray =
        bundleOverride?.also { bundleRequestsN.incrementAndGet() } ?: serveBundleByMode(fixtures)

    private fun serveBundleByMode(fixtures: WorldFixtures): ByteArray = when (mode) {
        MirrorMode.NONE -> fixtures.bundle
        MirrorMode.STALE -> fixtures.staleBundle
        MirrorMode.ROLLBACK -> rollbackBundle ?: fixtures.bundle
        MirrorMode.GARBAGE -> ByteArray(256) { (it * 31 + 7).toByte() }
        MirrorMode.TRUNCATE -> fixtures.bundle.copyOfRange(0, fixtures.bundle.size / 2)
        MirrorMode.EQUIVOCATE -> equivocateBundle ?: throw IllegalStateException("world sets the equivocating bundle")
        MirrorMode.ENDLESS -> ByteArray(2 * 1024 * 1024) { (it * 17 + 1).toByte() }
        MirrorMode.SLOW -> fixtures.bundle
        MirrorMode.WITHHOLD_PROOF -> fixtures.doc("bundle-nowproof.ghrb")
        MirrorMode.WRONG_PROOF -> fixtures.doc("bundle-wrongproof.ghrb")
        MirrorMode.MIXED_ROOT -> fixtures.doc("bundle-wrongroot.ghrb")
        MirrorMode.FAST_FORWARD -> fixtures.doc("bundle-ff.ghrb")
        MirrorMode.EXPIRED_REPLAY -> fixtures.doc("bundle-replay.ghrb")
        MirrorMode.FLOOR_MAX -> fixtures.doc("bundle-floor.ghrb")
        MirrorMode.RELABEL -> fixtures.doc("bundle-relabel.ghrb")
        MirrorMode.APK_SWAP, MirrorMode.APK_EXTRA, MirrorMode.DROP_MID_RANGE -> fixtures.bundle
    }.also { bundleRequestsN.incrementAndGet() }

    /** The fixed 4 MiB range of the offered APK (§7.2); the last range is the file's tail. */
    fun serveApkChunk(fixtures: WorldFixtures, chunkIndex: Long): ByteArray {
        if (mode == MirrorMode.SLOW) {
            // Serve only after the run's fixed end: the next engine loop sees the lease closed.
            clock?.advance(60_001)
        }
        if (mode == MirrorMode.DROP_MID_RANGE && chunkIndex in droppedChunks) {
            throw NetworkException("transport")
        }
        val file = when (mode) {
            MirrorMode.APK_SWAP -> fixtures.doc("app-v2-swap.apk")
            MirrorMode.APK_EXTRA -> fixtures.doc("app-v2-extra.apk")
            else -> apkOverride ?: fixtures.apk
        }
        val start = chunkIndex * CHUNK
        if (start < 0 || start >= file.size) {
            throw NetworkException("invalid_argument")
        }
        val end = minOf(start + CHUNK, file.size.toLong())
        chunkRequestsN.incrementAndGet()
        synchronized(chunkIndexesServed) { chunkIndexesServed += chunkIndex }
        return file.copyOfRange(start.toInt(), end.toInt())
    }

    companion object {
        const val CHUNK: Long = 4L * 1024 * 1024
    }
}
