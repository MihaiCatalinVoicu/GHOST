package org.ghost.messaging.engine

import org.ghost.messaging.api.ActivationOutcome
import org.ghost.messaging.api.CardExport
import org.ghost.messaging.api.MaintenanceReport
import org.ghost.messaging.api.Messaging

/**
 * The DM engine behind the facade (Phase 9 design §13.1 `…messaging.engine`), at the size slice S6
 * gives it: the owner side.
 *
 * It holds no state of its own. Every call goes straight to [OwnerSteps], whose methods are each
 * one `SyncDatabase.transaction`; the ordering between them is the order of §13.7's pass, written
 * out once here so that a caller cannot run KEEPER before OWNER-WEEK and register credentials for
 * a set the new bundle week is about to change.
 */
class MessagingEngine(private val steps: OwnerSteps) : Messaging {

    override fun myCard(): CardExport? =
        steps.myCard()?.let { CardExport(it.card, it.link) }

    override fun onActivated(): ActivationOutcome =
        ActivationOutcome.of(steps.activate(restored = false))

    override fun onRestored(): ActivationOutcome =
        ActivationOutcome.of(steps.activate(restored = true))

    /**
     * OWNER-WEEK, then KEEPER, then REGROWS (§13.7's pass order for the time-triggered steps).
     *
     * The order matters in one direction only, and it is this one: OWNER-WEEK may move the bundle
     * week, KEEPER then recomputes the relay sets and installs the READ credential for the set as
     * it now is, and REGROWS finally records the registrations for those relays. Reversed, a week
     * change would leave a registration row for a relay the owner no longer reads from until the
     * next pass.
     *
     * Each step's own guard makes the pass idempotent: a second pass in the same week, on the same
     * slot table, with credentials that are not near expiry, writes nothing at all.
     */
    override fun runOwnerMaintenance(): MaintenanceReport = MaintenanceReport(
        ownerWeek = steps.ownerWeek(),
        keeper = steps.keeper(),
        regrows = steps.regrows(),
    )

    override fun toString(): String = "MessagingEngine"
}
