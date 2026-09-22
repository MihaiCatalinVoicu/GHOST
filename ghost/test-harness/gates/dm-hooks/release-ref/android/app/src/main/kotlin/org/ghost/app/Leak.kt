package org.ghost.app

import org.ghost.crypto.bridge.gate.GateKeyChange

// Fixture: a release source set that reaches the debug key-change hook. The comment naming
// GateKeyChange is prose and must not count; the import above and the call below both do.
internal object Leak {
    fun branch(real: ByteArray): ByteArray = GateKeyChange.alternateBranch(real) // G-DM5
}
