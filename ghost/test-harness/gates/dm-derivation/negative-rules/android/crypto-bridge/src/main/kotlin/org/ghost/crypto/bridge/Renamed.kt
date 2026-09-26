package org.ghost.crypto.bridge

import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

// Rule 1: the listed call, but its key now comes from another value. Expected: line 11.
internal object Renamed {
    fun tag(contactIdentityKey: ByteArray): ByteArray {
        val key = contactIdentityKey
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(key, "HmacSHA256"))
        return mac.doFinal()
    }
}
