package org.ghost.messaging.other

/** G-DM2 negative fixture (§19.38): a file named like an allowed step, outside the DM engine's directory. Line 6. */
internal class OwnerSteps(private val sync: Any) {
    fun reflex(tx: Any, blob: Any) {
        sync.outbox.enqueue(tx, blob)
    }
}
