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

/**
 * The fourth shape, added by the S9 review: a Kotlin **safe call** on the port. `outbox?.cancel(`
 * is the same call site as `outbox.cancel(`, and the receiver check matched only a bare `.`, so
 * the whole of `Outbox.cancel` — mutant ME-21, which SWEEP must never make — could be written in
 * a file the gate refuses and pass.
 */
internal class OutcomeStep(private val sync: SyncPorts) {
    fun apply(tx: Any, op: Any) {
        sync.outbox?.cancel(tx, op)
    }
}

/**
 * The fifth shape, added by the S9 review: a port injected as a **constructor property under a
 * name of the author's choosing**. `RECEIVERS` matched the four conventional names and the alias
 * rule needed an initialiser (`val ob = sync.outbox`), so neither saw `ops`, and this file could
 * write mutant ME-21 in full and pass. `Sweeper.kt` is the one production file that takes a port
 * this way, which is what made the shape worth a fixture rather than a caveat. `RECEIVER_TYPES`
 * is what sees it: the declaration has to write the type out.
 */
internal class SweepStep(private val ops: Outbox, private val registry: Namespaces) {
    fun sweep(tx: Any, op: Any, ns: Any) {
        registry.remove(tx, ns)
        ops.cancel(tx, op)
    }
}

/**
 * The sixth and seventh shapes, added by the Phase 10 review of S1a: a **callable reference** to a
 * restricted call (the call is made later, through the reference) and a **parenthesized receiver**
 * (`(port).call(…)`, where the `)` stood between the receiver and the `.` the rule looked for). Both were
 * open for every restricted call; the review tried them on `Funding.set`.
 */
internal class FundStep(private val sync: SyncPorts) {
    fun fund(tx: Any, ns: Any) {
        val later = sync.funding::set
        later(tx, ns, true)
        (sync.funding).set(tx, ns, false)
    }
}
