package org.ghost.update.harness

/**
 * A model mirror's hostile behaviour (Phase 14 design §11.2), applied where the honest model
 * serves bytes. A mode is one enum entry and one branch of [ModelMirror.serveBundle]/
 * [ModelMirror.serveApkChunk]: the remaining §11.2 modes (EQUIVOCATE, ENDLESS, SLOW,
 * WITHHOLD_PROOF, WRONG_PROOF, MIXED_ROOT, FAST_FORWARD, APK_SWAP, APK_EXTRA, DROP_MID_RANGE,
 * EXPIRED_REPLAY, FLOOR_MAX, RELABEL) join as new entries, most needing only a second fixture
 * document beside the world's bundle set.
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
}

/**
 * One model mirror of the world (§11.2): it serves the bundle and the APK's fixed 4 MiB ranges
 * (§7.2) per its [mode], counts what it served (the world's mirror view, T51's observatory),
 * and holds the bytes under the names the engine asks for — the path and the range are built
 * natively (PM-D9, PM-D10), the harness only answers with bytes.
 */
internal class ModelMirror(val index: Int, var mode: MirrorMode = MirrorMode.NONE) {

    /** Served requests, the world-side view of what the mirrors saw. */
    var bundleRequests: Int = 0
        private set
    var chunkRequests: Int = 0
        private set
    var chunkIndexesServed: MutableList<Long> = mutableListOf()
        private set

    /** The ROLLBACK mode's bytes: the world sets the previous generation's bundle when one
     *  exists (with a single published generation the honest bundle is the only one). */
    var rollbackBundle: ByteArray? = null

    fun serveBundle(fixtures: WorldFixtures): ByteArray = when (mode) {
        MirrorMode.NONE -> fixtures.bundle
        MirrorMode.STALE -> fixtures.staleBundle
        MirrorMode.ROLLBACK -> rollbackBundle ?: fixtures.bundle
        MirrorMode.GARBAGE -> ByteArray(256) { (it * 31 + 7).toByte() }
        MirrorMode.TRUNCATE -> fixtures.bundle.copyOfRange(0, fixtures.bundle.size / 2)
    }.also { bundleRequests++ }

    /** The fixed 4 MiB range of the offered APK (§7.2); the last range is the file's tail. */
    fun serveApkChunk(fixtures: WorldFixtures, chunkIndex: Long): ByteArray {
        val start = chunkIndex * CHUNK
        if (start < 0 || start >= fixtures.apk.size) {
            throw org.ghost.network.NetworkException("invalid_argument")
        }
        val end = minOf(start + CHUNK, fixtures.apk.size.toLong())
        chunkRequests++
        chunkIndexesServed += chunkIndex
        return fixtures.apk.copyOfRange(start.toInt(), end.toInt())
    }

    companion object {
        const val CHUNK: Long = 4L * 1024 * 1024
    }
}
