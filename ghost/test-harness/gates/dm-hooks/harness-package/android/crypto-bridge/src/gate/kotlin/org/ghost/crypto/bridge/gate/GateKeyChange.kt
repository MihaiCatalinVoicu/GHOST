package org.ghost.crypto.bridge.gate

/** Fixture: the debug key-change hook, declared in a gate source set as in the real tree. */
object GateKeyChange {
    fun alternateBranch(branch: ByteArray): ByteArray = branch.copyOf()
}
