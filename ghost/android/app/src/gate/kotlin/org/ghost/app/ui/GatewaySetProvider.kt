package org.ghost.app.ui

/**
 * The GATE half of the twin (design §3.1, §12.3, Q45): the real adapters, plus the fixture hook
 * the emulator's platform suites drive through `am instrument` commands (T10's scripted screens,
 * the notification canary). The hook is inert until a suite sets it; release and debug halves
 * never name it (G-DM5).
 */
internal object GatewaySetProvider {
    @Volatile
    var fixture: GateFixture? = null

    fun forDeps(deps: GatewayDeps): GatewaySet = fixture?.wrap(RealGatewaySet(deps)) ?: RealGatewaySet(deps)
}

/** The emulator suites' door into the app process; each suite's slice fills what it needs. */
internal interface GateFixture {
    fun wrap(real: GatewaySet): GatewaySet
}
