package org.ghost.crypto.bridge

object MlsNative {
    @JvmStatic
    @JvmName("ctxOpen")
    internal external fun ctxOpen(stateKey: ByteArray): ByteArray?

    // The handle as an Int: JNI binds by name, so this would bind and read the wrong argument.
    @JvmStatic
    @JvmName("ctxClose")
    internal external fun ctxClose(
        handle: Int,
    ): ByteArray?
}
