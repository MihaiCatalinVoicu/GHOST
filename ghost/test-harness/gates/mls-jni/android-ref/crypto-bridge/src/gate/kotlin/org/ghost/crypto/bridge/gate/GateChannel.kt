package org.ghost.crypto.bridge.gate

/** Fixture: the gate source set of :crypto-bridge is not src/main. */
object GateChannel {
    fun close(handle: Long) = org.ghost.crypto.bridge.MlsNative.ctxClose(handle)
}
