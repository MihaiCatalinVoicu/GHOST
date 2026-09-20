package org.ghost.messaging.engine

/**
 * G-DM2 negative fixture: SWEEP may call `Namespaces.remove` (§21.12 point 3) **and nothing else**.
 * The removal below is allowed and must not be reported; the enqueue beside it is a store caused by
 * the sweep and must be, which is what keeps `Sweeper.kt` out of the gate's main allowlist.
 */
internal class Sweeper(private val sync: SyncPorts) {
    fun sweep(tx: Any, namespace: Any, blob: Any) {
        sync.namespaces.remove(tx, namespace)
        sync.outbox.enqueue(tx, blob)
    }
}
