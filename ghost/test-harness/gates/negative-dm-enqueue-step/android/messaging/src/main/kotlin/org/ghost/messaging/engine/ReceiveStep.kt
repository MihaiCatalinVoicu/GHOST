package org.ghost.messaging.engine

/**
 * G-DM2 negative fixture: the reflex that goes through a **step object** instead of through a
 * restricted call or the facade. Nothing here calls `Outbox.enqueue`, and nothing here names
 * `runOwnerMaintenance`, so the first three rules see nothing; `SendStep.sendControl` and
 * `EstablishmentSteps.estStart` reach the enqueue one frame down, inside the files allowlisted for
 * it. A card holder with AD-1 who deposits a probe would make a CONTROL deposit and a `P_c` fetch
 * window follow it — T28 and §21.9 rule 2, one frame lower than mutants PM-11 and PM-30.
 *
 * The receivers are constructor properties, which is exactly the alias shape the call-site rule
 * declares it does not see.
 */
internal class ReceiveStep(
    private val sendStep: Any,
    private val establishment: Any,
) {
    fun receive(blob: Any) {
        sendStep.sendControl(blob)
        establishment.estStart(blob)
    }
}
