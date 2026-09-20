package org.ghost.messaging.engine

/**
 * G-DM2 negative fixture: the three shapes that hid a call site from the first version of this
 * gate, which matched a receiver and its call on one physical line. All three are the reflex T28
 * forbids — a RECV step that changes relay-visible state because a blob arrived — written so that
 * the receiver is not beside the call.
 */
internal class ReceiveStep(private val sync: SyncPorts) {
    fun receive(tx: Any, blob: Any, relays: Any, ns: Any) {
        // 1. The receiver on the line above its call.
        sync.namespaces
            .setRelays(tx, ns, relays)
        // 2. A local alias of the port.
        val ob = sync.outbox
        ob.enqueue(tx, blob)
        // 3. A scope function over the port, and a bare call inside it.
        with(sync.registrations) {
            forget(tx, ns, 1)
        }
    }
}
