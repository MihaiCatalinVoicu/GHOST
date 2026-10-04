package org.ghost.crypto.bridge

object MlsNative {
    @JvmStatic
    internal external fun ctxOpen(stateKey: ByteArray): ByteArray?

    @JvmStatic
    @JvmName("ctxClose")
    internal external fun ctxClose(handle: Long): ByteArray?
}
