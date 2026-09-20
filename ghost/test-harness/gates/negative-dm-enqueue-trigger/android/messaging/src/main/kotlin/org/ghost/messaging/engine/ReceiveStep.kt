package org.ghost.messaging.engine

/**
 * G-DM2 negative fixture: the reflex that goes through the **facade** instead of through a
 * restricted call. Nothing here calls `Outbox.enqueue`; the owner pass does, one frame down, and a
 * card holder with AD-1 who deposits a probe would make the owner publish a bundle a minute later
 * whenever `t_pub(w)` had already passed — mutants PM-11 and PM-30, which the call-site rule alone
 * does not see, because the enqueue stays inside the allowlisted `OwnerSteps.kt`.
 */
internal class ReceiveStep(private val engine: Any) {
    fun receive(blob: Any) {
        engine.runOwnerMaintenance()
    }
}
