package org.ghost.crypto.bridge

import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

// A listed site written across lines, with a trailing comma: layout is not part of the call.
internal object Recognition {
    const val HINT_LABEL: String = "ghost/v1/dm-hint"

    fun hint(recognitionKey: ByteArray, salt: ByteArray): ByteArray {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(
            SecretKeySpec(
                recognitionKey,
                "HmacSHA256",
            ),
        )
        mac.update(HINT_LABEL.toByteArray(Charsets.US_ASCII))
        mac.update(salt)
        return mac.doFinal()
    }
}
