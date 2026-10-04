package org.ghost.crypto.bridge

object MlsNative {
    @JvmStatic @JvmName("ctxOpen") external fun ctxOpen(stateKey: ByteArray): ByteArray?

    @JvmStatic
    @JvmName("ctxClose")
    internal external fun ctxClose(handle: Long): ByteArray?
}
