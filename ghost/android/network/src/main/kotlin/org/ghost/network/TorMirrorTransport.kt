package org.ghost.network

/**
 * The mirror half of the update channel (Phase 14 design §7.1, §7.2, §7.8): one fetch of an
 * update run, over the Tor client of a [TorRelayTransport] handle, on the `Update` isolation
 * scope. Kotlin names neither an onion nor a path nor an offset: the [UpdateNative.MirrorSet]
 * built by `nativeMirrorSet` holds the two canonical onions and the offered APK's hash and
 * length, and the native side builds the path and the 4 MiB range from them (PM-D9, PM-D10).
 * Failures are [NetworkException] categories (`transport`, `deadline`, `malformed_response`,
 * `closed`, `invalid_argument`); a chunk index beyond the offered length is refused before
 * anything is sent.
 */
object TorMirrorTransport {
    const val KIND_BUNDLE = 0
    const val KIND_APK_CHUNK = 1

    /** The bundle (`/ghost/v1/<net>/current.ghrb`, 200, at most 1 MiB). */
    fun fetchBundle(transport: Long, mirrorSet: Long, slot: Int, deadlineMs: Long): ByteArray {
        NativeLibrary.ensureLoaded()
        if (slot !in 0..1) throw NetworkException("invalid_argument")
        return nativeFetch(transport, mirrorSet, slot, KIND_BUNDLE, 0, deadlineMs)
    }

    /** One 4 MiB chunk of the offered APK (206 with the matching `content-range`). */
    fun fetchApkChunk(
        transport: Long,
        mirrorSet: Long,
        slot: Int,
        chunkIndex: Long,
        deadlineMs: Long,
    ): ByteArray {
        NativeLibrary.ensureLoaded()
        if (slot !in 0..1 || chunkIndex < 0) throw NetworkException("invalid_argument")
        return nativeFetch(transport, mirrorSet, slot, KIND_APK_CHUNK, chunkIndex, deadlineMs)
    }

    @JvmStatic
    private external fun nativeFetch(
        transport: Long,
        mirrorSet: Long,
        slot: Int,
        kind: Int,
        chunkIndex: Long,
        deadlineMs: Long,
    ): ByteArray
}
