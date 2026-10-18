package org.ghost.app.ui

/**
 * Phase 13 §3.1's build-type twin (the DmBranch pattern): the RELEASE half builds the real
 * gateway set and nothing else. The gate variant (src/gate) is the only half that may serve a
 * fixture to the emulator's platform suites; G-DM5 refuses in this half anything only that half
 * names.
 */
internal object GatewaySetProvider {
    fun forDeps(deps: GatewayDeps): GatewaySet = RealGatewaySet(deps)
}
