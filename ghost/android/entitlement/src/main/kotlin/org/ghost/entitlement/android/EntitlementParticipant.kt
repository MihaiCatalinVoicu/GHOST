package org.ghost.entitlement.android

import org.ghost.entitlement.engine.EntitlementEngine
import org.ghost.entitlement.port.IssuerPort
import org.ghost.entitlement.port.RedeemPort
import org.ghost.entitlement.port.SessionPort
import org.ghost.sync.api.ParticipantSession
import org.ghost.sync.api.SessionKind
import org.ghost.sync.api.SessionParticipant

/**
 * The entitlement engine as the one `SessionParticipant` of the sync runtime (design §11.6, D16):
 * relay sessions drive the redeem lane, quiet runs the one issuer call. Every callback runs on its own
 * runtime thread and returns when the session closes (a quiet run returns after its call).
 */
class EntitlementParticipant(private val engine: EntitlementEngine) : SessionParticipant {
    override fun onRelaySession(session: ParticipantSession) = engine.onRelaySession(ParticipantSessionPort(session))

    override fun onQuietRun(session: ParticipantSession) = engine.onQuietRun(ParticipantSessionPort(session))

    override fun toString(): String = "EntitlementParticipant"
}

/** [SessionPort] over a `ParticipantSession`: the accesses it grants, and nothing else. */
internal class ParticipantSessionPort(private val session: ParticipantSession) : SessionPort {
    override val kind: SessionKind get() = session.kind
    override val closed: Boolean get() = session.closed

    override fun clockTrusted(): Boolean = session.clockTrusted()

    override val issuer: IssuerPort? = session.issuer?.let(::TorIssuerPort)
    override val redeem: RedeemPort? = session.relayRedeem?.let(::TorRedeemPort)

    override fun toString(): String = "ParticipantSessionPort($kind)"
}
