package org.ghost.app

import android.content.Context
import org.ghost.identity.DerivationLabels
import org.ghost.identity.RootEntropy

/**
 * The MESSAGING branch the DM context is opened with (Phase 9 design §3.1, §13.7; slice S12): `m =
 * HKDF(root, "ghost/v1/messaging")`, and nothing else.
 *
 * **Why a per-build-type object** (S12 review). The `gate` build type opens the context with the
 * debug key-change hook instead (`crypto-bridge/src/gate`, §15.1, §21.13 point 7). It used to do so
 * by overriding an `open` member of an `open` `GhostApp`, which left a virtual method — an override
 * point that exists only for a debug hook — in the release APK. Now `GhostApp` is final and passes
 * `DmBranch.forApp(this)` to `DmKeys`; `src/release` and `src/debug` define this object with the
 * plain derivation, and only `src/gate` defines one that can switch. Gate G-DM5 treats the three as
 * one declaration (it is in a release source set) and still refuses the hook itself, which only the
 * `gate` twin names, anywhere in a release source set or R8's mapping.
 */
internal object DmBranch {
    /** The branch function for the app; the release ignores [app]. */
    @Suppress("UNUSED_PARAMETER")
    fun forApp(app: Context): (RootEntropy) -> ByteArray = { root -> root.deriveBranch(DerivationLabels.MESSAGING) }
}
