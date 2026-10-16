package org.ghost.media.send

import org.ghost.crypto.bridge.MediaCrypto
import org.ghost.crypto.bridge.MediaNative

/**
 * The production [StreamSealer]: one begun object sealer of §3.7 over `MediaCrypto` (the closed
 * JNI surface, S2). `K_f` never crosses this boundary — [objectId] and `key_env` are all the
 * caller ever sees.
 */
class NativeStreamSealer private constructor(
    private val handle: Long,
    private val sealerId: Long,
    val objectId: ByteArray,
) : StreamSealer {

    override fun append(plaintext: ByteArray): List<SealedFragmentGroup> =
        when (val result = MediaCrypto.append(handle, sealerId, plaintext)) {
            is MediaCrypto.Appended.Ok -> result.chunks.map {
                SealedFragmentGroup(it.index, it.fragments, it.hashes)
            }
            MediaCrypto.Appended.NonCanonical -> throw SealException.NonCanonical()
            MediaCrypto.Appended.Oversize -> throw SealException.Oversize()
            MediaCrypto.Appended.IndexReused,
            MediaCrypto.Appended.Sequence,
            -> throw SealException.Internal("sealAppend returned ${result.javaClass.simpleName}")
            MediaCrypto.Appended.Unavailable -> throw SealException.Unavailable()
        }

    override fun finish(preview: ByteArray): SealedObject =
        when (val result = MediaCrypto.finish(handle, sealerId, preview)) {
            is MediaCrypto.FinishedResult.Ok -> {
                val finished = result.finished
                SealedObject(
                    classCode = finished.classCode,
                    contentLen = finished.contentLen,
                    width = finished.width,
                    height = finished.height,
                    durationMs = finished.durationMs,
                    keyEnv = finished.keyEnv,
                    manifestBlob = finished.manifestBlob,
                    manifestHash = finished.manifestHash,
                    preview = finished.preview,
                    finishGroups = finished.chunks.map {
                        SealedFragmentGroup(it.index, it.fragments, it.hashes)
                    },
                )
            }
            MediaCrypto.FinishedResult.NonCanonical -> throw SealException.NonCanonical()
            MediaCrypto.FinishedResult.Oversize -> throw SealException.Oversize()
            MediaCrypto.FinishedResult.Sequence -> throw SealException.Internal("sealFinish returned Sequence")
            MediaCrypto.FinishedResult.Unavailable -> throw SealException.Unavailable()
        }

    override fun abort() {
        MediaCrypto.abort(handle, sealerId)
    }

    companion object {
        /** M1 `sealBegin`: the registry's limit (2 sealers) and the native surface's refusals. */
        sealed interface Begun {
            class Ok(val sealer: NativeStreamSealer) : Begun
            data object Limited : Begun
            data object NonCanonical : Begun
            data object Unavailable : Begun
        }

        fun begin(
            handle: Long,
            destId: ByteArray,
            kind: MediaCrypto.Kind,
            viewOnce: Boolean,
            maxClass: Int,
        ): Begun = when (val result = MediaCrypto.begin(handle, destId, kind, viewOnce, maxClass)) {
            is MediaCrypto.Begun.Ok -> {
                val sealer = result.sealer
                Begun.Ok(NativeStreamSealer(handle, sealer.id, sealer.objectId))
            }
            MediaCrypto.Begun.Limited -> Begun.Limited
            MediaCrypto.Begun.NonCanonical -> Begun.NonCanonical
            MediaCrypto.Begun.Unavailable -> Begun.Unavailable
        }

        /** Stateless M9/M10 need no handle, but the library's presence decides availability. */
        fun isAvailable(): Boolean = MediaNative.isAvailable()
    }
}
