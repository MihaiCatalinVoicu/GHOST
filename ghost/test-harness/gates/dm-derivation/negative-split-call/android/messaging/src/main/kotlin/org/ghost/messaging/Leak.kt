package org.ghost.messaging

import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

// G-DM3 negative fixture: an HMAC keyed by a public key, its call split across three lines (the
// evasion of a line-by-line reading). Expected: exactly one violation, line 11.
internal object Leak {
    fun tag(identityPublicKey: ByteArray): ByteArray {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(
            identityPublicKey,
            "HmacSHA256"))
        return mac.doFinal()
    }
}
