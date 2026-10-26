package org.ghost.app

import android.content.Context
import org.ghost.sync.api.MirrorAccess

/**
 * The debug build's mirror override: the same none as `src/release`'s `UpdateLoopback` (see its
 * note), byte for byte in behaviour. Only `src/gate` defines a twin that can switch to the
 * emulator's loopback model-mirror access.
 */
internal object UpdateLoopback {
    @Suppress("UNUSED_PARAMETER")
    fun mirror(app: Context): MirrorAccess? = null
}
