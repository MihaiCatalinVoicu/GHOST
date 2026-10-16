package org.ghost.messaging.engine

import org.ghost.media.send.MediaOpId
import java.security.MessageDigest

/**
 * The production [MediaOpId] (Phase 11 design §6.4):
 * `SHA-256("ghost/v1/media/op" || object_id(16) || i16_be(ordinal) || u8(retry_gen) || u8(resend_count))[0..16]`.
 *
 * The label is a `ghost/v1/` derivation label, so this file is on G-DM3's motivated allowlist
 * (`dm-derivation-inputs.allow`) like the verifier labels: an **unkeyed** digest of structured,
 * non-secret material — the inputs are the object id, the ordinal and the counters, none of them
 * key material — and the determinism is the point (a repeated feed or a crash mid-burst re-derives
 * the same op id, which `Outbox.enqueue`'s `AlreadyEnqueued` and the store's guarded ordinal make
 * idempotent). It lives in `:messaging`, not `:media`, because G-DM3 keeps `ghost/v<n>/` labels
 * out of the media module (§22.8 F-S5-3's pattern).
 */
internal object MediaOpIds {
    private const val LABEL = "ghost/v1/media/op"

    fun sha256(): MediaOpId = MediaOpId { objectId, ordinal, retryGen, resendCount ->
        if (objectId.size != 16) throw IllegalArgumentException("object_id")
        if (ordinal < -1 || ordinal > 803) throw IllegalArgumentException("ordinal")
        if (retryGen !in 0..3 || resendCount !in 0..2) throw IllegalArgumentException("counters")
        val digest = MessageDigest.getInstance("SHA-256")
        digest.update(LABEL.toByteArray(Charsets.UTF_8))
        digest.update(objectId)
        digest.update(byteArrayOf((ordinal ushr 8).toByte(), ordinal.toByte()))
        digest.update(retryGen.toByte())
        digest.update(resendCount.toByte())
        digest.digest().copyOf(16)
    }
}
