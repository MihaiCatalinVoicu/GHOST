package org.ghost.app

import android.content.Context
import org.ghost.crypto.bridge.gate.GateKeyChange
import org.ghost.identity.DerivationLabels
import org.ghost.identity.RootEntropy
import java.io.File

/**
 * The `gate` build type's MESSAGING branch (Phase 9 design §15.10 step 5, §21.13 points 4 and 7,
 * ADR-34; slice S12): the plain derivation of `src/release`'s `DmBranch`, or — while the switch is
 * on — the debug key-change hook of `crypto-bridge/src/gate` applied to it, which is another Olm
 * identity bound by the same Ed25519 key (§15.1's "stolen seed on a modified client").
 *
 * The switch is a flag file in `noBackupFilesDir` that `GateInstrumentation`'s `key-change` command
 * sets or clears; it survives the process, as the key change must across the orchestrator's
 * commands, each of which is a new process. The variant is built locally or in a job that uploads
 * nothing, signed with the build machine's throwaway debug key and installed only on the gate
 * devices (ADR-34, G-L5, ADR-39). This file is the one `DmBranch` that names the hook, and gate
 * G-DM5 refuses the hook in every release source set and in R8's release mapping.
 */
internal object DmBranch {
    private const val KEY_CHANGE_FILE = "gate-key-change"

    private fun switch(app: Context): File = File(app.noBackupFilesDir, KEY_CHANGE_FILE)

    /** True while the key-change hook is on. */
    fun keyChanged(app: Context): Boolean = switch(app).isFile

    /** Turns the key-change hook on or off; the next context open follows it. */
    fun setKeyChanged(app: Context, on: Boolean) {
        val file = switch(app)
        if (on) file.writeBytes(ByteArray(0)) else file.delete()
    }

    /** The branch function for the app: the switch is read at every open. */
    fun forApp(app: Context): (RootEntropy) -> ByteArray = { root ->
        val derived = root.deriveBranch(DerivationLabels.MESSAGING)
        if (!keyChanged(app)) {
            derived
        } else {
            try {
                GateKeyChange.alternateBranch(derived)
            } finally {
                derived.fill(0)
            }
        }
    }
}
