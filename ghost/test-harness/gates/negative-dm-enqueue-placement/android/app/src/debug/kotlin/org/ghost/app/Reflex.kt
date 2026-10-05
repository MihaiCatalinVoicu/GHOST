package org.ghost.app

/** G-DM2 negative fixture (§19.38): the `debug` source set ships in every debug build. One violation, line 6. */
internal class Reflex(private val sync: Any) {
    fun reflex(tx: Any, blob: Any) {
        sync.outbox.enqueue(tx, blob)
    }
}
