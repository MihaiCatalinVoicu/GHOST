package org.ghost.app

import android.content.Context
import org.ghost.identity.DerivationLabels
import org.ghost.identity.RootEntropy

/**
 * The MESSAGING branch the DM context is opened with, for the `debug` build type: the same plain
 * derivation as `src/release`'s `DmBranch` (see its note), byte for byte in behaviour. Only
 * `src/gate` defines a `DmBranch` that can switch to the debug key-change hook.
 */
internal object DmBranch {
    /** The branch function for the app; the debug build ignores [app]. */
    @Suppress("UNUSED_PARAMETER")
    fun forApp(app: Context): (RootEntropy) -> ByteArray = { root -> root.deriveBranch(DerivationLabels.MESSAGING) }
}
