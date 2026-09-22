package org.ghost.app.gate

// Negative fixture for gate T8 over the `gate` source sets (Phase 9 design
// §21.13 point 7, slice S12): a gate hook that answers without doing its work must fail the gate.
object GateStandIn {
    fun digest(): String = "0000" // placeholder until the export exists
}
