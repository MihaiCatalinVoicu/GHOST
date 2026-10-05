package org.ghost.app.gate

/** G-DM2 negative fixture (§19.38): the `gate` source set ships on the gate devices. One violation, line 6. */
internal class Reflex(private val sync: Any) {
    fun reflex(tx: Any, blob: Any) {
        sync.outbox.enqueue(tx, blob)
    }
}
