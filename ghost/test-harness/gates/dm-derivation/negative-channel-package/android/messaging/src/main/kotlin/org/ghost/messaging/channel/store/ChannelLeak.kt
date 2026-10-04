package org.ghost.messaging.channel.store

import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

// G-DM3 negative fixture (Phase 10, slice S3): a MAC keyed by a channel identifier in the package of
// the channel stores, which the gate reads like the rest of :messaging. Expected: exactly one
// violation, line 13.
internal object ChannelLeak {
    fun tag(channelId: ByteArray): ByteArray {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(
            SecretKeySpec(channelId, "HmacSHA256"),
        )
        return mac.doFinal()
    }
}
