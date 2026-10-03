package org.ghost.crypto.bridge

/**
 * Fixture (review of S2b): a public declaration written on one line with its `@JvmName`. The
 * visibility check once skipped any line that held a `@JvmName`, so this one passed. G-R6 rejects it.
 */
object DmNative {
    @JvmStatic @JvmName("ctxOpen") external fun ctxOpen(a: ByteArray, b: ByteArray, c: ByteArray): ByteArray?

    @JvmStatic
    @JvmName("ctxClose")
    internal external fun ctxClose(handle: Long): ByteArray?
}
