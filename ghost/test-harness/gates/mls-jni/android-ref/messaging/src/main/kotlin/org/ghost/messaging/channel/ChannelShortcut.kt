package org.ghost.messaging.channel

import org.ghost.crypto.bridge.ChannelCrypto

/**
 * Fixture: prose may name MlsNative (the design's KDoc does); code may not.
 */
object ChannelShortcut {
    fun open(key: ByteArray) = org.ghost.crypto.bridge.MlsNative.ctxOpen(key) // MlsNative, past the facade
    fun facade(key: ByteArray) = ChannelCrypto.open(key)
}
