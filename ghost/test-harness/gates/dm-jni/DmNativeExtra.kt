package org.ghost.crypto.bridge

/** Fixture: Kotlin declares a native method the crate does not export. */
object DmNative {
    @JvmName("ctxOpen")
    internal external fun ctxOpen(a: ByteArray, b: ByteArray, c: ByteArray): ByteArray?

    @JvmName("debugDumpState")
    internal external fun debugDumpState(handle: Long): ByteArray?
}
