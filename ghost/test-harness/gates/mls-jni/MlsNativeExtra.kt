package org.ghost.crypto.bridge

object MlsNative {
    @JvmStatic
    @JvmName("ctxOpen")
    internal external fun ctxOpen(stateKey: ByteArray): ByteArray?

    @JvmStatic
    @JvmName("ctxClose")
    internal external fun ctxClose(handle: Long): ByteArray?

    @JvmStatic
    @JvmName("debugDump")
    internal external fun debugDump(handle: Long): ByteArray?
}
