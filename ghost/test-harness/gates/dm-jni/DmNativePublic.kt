package org.ghost.crypto.bridge

/**
 * Fixture: the declarations are public, so any module that depends on `:crypto-bridge` could call
 * the ratchet without the typed facade (design §2.6, §13.1). G-R6 rejects it.
 */
object DmNative {
    @JvmStatic
    @JvmName("ctxOpen")
    external fun ctxOpen(a: ByteArray, b: ByteArray, c: ByteArray): ByteArray?

    @JvmStatic
    @JvmName("ctxClose")
    internal external fun ctxClose(handle: Long): ByteArray?
}
