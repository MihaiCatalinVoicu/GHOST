package org.ghost.messaging.engine

/**
 * G-DM2 negative fixture: the reflex T28 forbids. A `RECV` step that registers a namespace
 * because a blob arrived makes the relay-visible behaviour depend on what was in the inbox.
 */
internal class ReceiveStep(private val sync: SyncPorts) {
    fun receive(tx: Any, blob: Any) {
        sync.namespaces.register(tx, blob, listen = true)
    }
}
