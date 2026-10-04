package org.ghost.media.store

import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

// G-DM3 negative fixture (Phase 11, slice S3): a MAC keyed by an object identifier, and a derivation label,
// in the package of the media store, which the gate reads like the rest of the DM modules (every media
// derivation lives in ghost-client-media behind MediaNative, design faza11-media.md 13.2). Expected: exactly
// two violations, lines 14 and 19.
internal object MediaLeak {
    fun tag(objectId: ByteArray): ByteArray {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(
            SecretKeySpec(objectId, "HmacSHA256"),
        )
        return mac.doFinal()
    }

    const val LABEL = "ghost/v1/media/fragment"
}
