package org.ghost.crypto.bridge

/**
 * Fixture: an internal declaration without `@JvmName`. Kotlin compiles it to
 * `ctxClose$crypto_bridge`, a name no JNI symbol matches, and nothing fails until a device calls
 * it. G-R6 rejects it.
 */
object DmNative {
    @JvmStatic
    @JvmName("ctxOpen")
    internal external fun ctxOpen(a: ByteArray, b: ByteArray, c: ByteArray): ByteArray?

    @JvmStatic
    internal external fun ctxClose(handle: Long): ByteArray?
}
