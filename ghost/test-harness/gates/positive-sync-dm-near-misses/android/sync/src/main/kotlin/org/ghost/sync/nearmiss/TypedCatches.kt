package org.ghost.sync.nearmiss

import java.io.IOException

// Typed catches, split or qualified, are what the sync engine is allowed to write.
internal object TypedCatches {
    fun io(block: () -> Unit) {
        try { block() } catch (
            e: IOException
        ) { }
    }

    fun qualified(block: () -> Unit) {
        try { block() } catch (e: java.io.IOException) { }
    }

    val handler: (Throwable) -> Unit = {}
}
