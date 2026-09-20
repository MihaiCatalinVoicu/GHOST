package org.ghost.crypto.bridge

/** Fixture: Kotlin is missing a declaration for a function the crate exports. */
object DmNative {
    external fun ctxOpen(a: ByteArray, b: ByteArray, c: ByteArray): ByteArray?
}
