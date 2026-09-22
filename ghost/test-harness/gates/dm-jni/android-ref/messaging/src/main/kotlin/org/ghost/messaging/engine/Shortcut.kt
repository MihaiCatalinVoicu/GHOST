package org.ghost.messaging.engine

import org.ghost.crypto.bridge.DmNative

// Fixture for G-R6's source-set half (Phase 9 §16.1, slice S12): `:messaging` reaching past the
// typed facade. This comment names DmNative and is prose; the import and the call are code.
internal object Shortcut {
    fun available(): Boolean = DmNative.isAvailable()
}
