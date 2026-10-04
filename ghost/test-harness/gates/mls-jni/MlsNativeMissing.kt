package org.ghost.crypto.bridge

object MlsNative {
    @JvmStatic
    @JvmName("ctxOpen")
    internal external fun ctxOpen(stateKey: ByteArray): ByteArray?
}
