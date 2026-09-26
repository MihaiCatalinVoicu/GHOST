package org.ghost.crypto.bridge

import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

// Rule 1: a listed call found twice where the allowlist permits it once. Expected: lines 10 and 14.
internal object Twice {
    fun order(namespace: ByteArray): ByteArray {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(namespace, "HmacSHA256"))
        return mac.doFinal()
    }

    fun again(namespace: ByteArray): ByteArray = SecretKeySpec(namespace, "HmacSHA256").encoded
}
