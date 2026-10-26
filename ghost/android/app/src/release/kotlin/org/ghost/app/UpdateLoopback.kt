package org.ghost.app

import android.content.Context
import org.ghost.sync.api.MirrorAccess

/**
 * The `Update` session's mirror override for the release build (Phase 14 design §11.4, G-DM5's
 * rules): none — the session always fetches over the Tor mirror of the transport lease. Only
 * `src/gate`'s twin can return the emulator's loopback model-mirror access, and only after the
 * gate instrumentation enabled it. See `DmBranch` for the per-build-type twin pattern.
 */
internal object UpdateLoopback {
    @Suppress("UNUSED_PARAMETER")
    fun mirror(app: Context): MirrorAccess? = null
}
