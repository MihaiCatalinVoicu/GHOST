package org.ghost.app.gate

import org.ghost.app.GhostApp
import org.ghost.crypto.bridge.gate.GateKeyChange
import org.ghost.identity.RootEntropy
import java.io.File

/**
 * The `gate` variant's application (Phase 9 design §15.10, §21.13 points 4 and 7, ADR-34; slice
 * S12): the release application with the debug key-change hook of `crypto-bridge/src/gate` behind
 * a switch the gate instrumentation flips.
 *
 * The variant is built locally or in a job that uploads nothing, signed with the build machine's
 * throwaway debug key, installed only on the gate devices and never distributed (ADR-34, G-L5,
 * ADR-39). Nothing here is reachable from a release source set (gate G-DM5).
 */
class GateGhostApp : GhostApp() {

    /** The switch: present while the gate device runs under the alternate Olm identity (§15.10 step 5). */
    private val switch: File get() = File(noBackupFilesDir, KEY_CHANGE_FILE)

    /** True while the key-change hook is on. */
    val keyChanged: Boolean get() = switch.isFile

    /** Turns the key-change hook on or off; the next unlock opens the context accordingly. */
    fun setKeyChanged(on: Boolean) {
        if (on) switch.writeBytes(ByteArray(0)) else switch.delete()
    }

    override fun messagingBranch(root: RootEntropy): ByteArray {
        val derived = super.messagingBranch(root)
        if (!keyChanged) return derived
        return try {
            GateKeyChange.alternateBranch(derived)
        } finally {
            derived.fill(0)
        }
    }

    private companion object {
        const val KEY_CHANGE_FILE = "gate-key-change"
    }
}
