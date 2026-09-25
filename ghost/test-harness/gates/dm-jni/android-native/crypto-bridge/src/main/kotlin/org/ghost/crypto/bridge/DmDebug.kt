package org.ghost.crypto.bridge

/**
 * Fixture (Phase 9 review GATES-3): a second native class in `:crypto-bridge`. It is not `DmNative`,
 * so it needed no closed-list entry and the reference rule did not see a caller in `:messaging`.
 */
object DmDebug {
    @JvmStatic
    external fun exportSessionState(handle: Long): ByteArray
}
