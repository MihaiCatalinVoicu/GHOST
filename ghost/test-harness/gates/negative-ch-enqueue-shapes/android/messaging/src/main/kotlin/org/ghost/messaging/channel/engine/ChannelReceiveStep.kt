package org.ghost.messaging.channel.engine

/*
 * G-M5 negative fixture (Phase 10 design §19.38, the review of S4): the shapes the first recognizer let through, in
 * CH-RECV. Seven violations: a block comment between the receiver and its call (14), backticked names (15), a line that
 * ends with the dot (16, reported at the receiver's line), an unbound callable reference of the port type (18), a port as
 * a qualified function parameter (21), a port as a parameter of a type alias of the port type (23), and a port bound by a
 * destructuring declaration (27).
 */
typealias Ox = org.ghost.sync.api.Outbox

internal class ChannelReceiveStep(private val sync: ChannelSyncPorts) {
    fun consume(tx: Any, ns: Any, blob: Any) {
        sync.outbox /* not here */ .enqueue(tx, blob)
        sync.`outbox`.`enqueue`(tx, blob)
        sync.outbox.
            enqueue(tx, blob)
        (org.ghost.sync.api.Outbox::enqueue)(sync.outbox, tx, blob)
    }

    fun viaParameter(o: org.ghost.sync.api.Outbox, tx: Any, blob: Any) { o.enqueue(tx, blob) }

    fun viaAlias(q: Ox, tx: Any, blob: Any) { q.enqueue(tx, blob) }

    fun viaDestructuring(tx: Any, blob: Any) {
        val (a, _) = sync.outbox to sync.funding
        a.enqueue(tx, blob)
    }
}
