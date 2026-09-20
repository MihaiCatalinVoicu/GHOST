package org.ghost.crypto.bridge

/** Fixture: Kotlin declares a native method the crate does not export. */
object DmNative {
    external fun ctxOpen(a: ByteArray, b: ByteArray, c: ByteArray): ByteArray?
    external fun debugDumpState(handle: Long): ByteArray?
}
