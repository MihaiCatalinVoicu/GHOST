package org.ghost.crypto.bridge

/** Fixture: a second native class in :crypto-bridge — no closed-list entry, no facade. */
object MlsDebug {
    // A comment that says external fun does not count.
    @JvmStatic
    @JvmName("dump")
    internal external fun dump(handle: Long): ByteArray?
}
