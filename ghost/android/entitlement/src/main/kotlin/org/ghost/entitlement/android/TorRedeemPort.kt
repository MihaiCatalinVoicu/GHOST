package org.ghost.entitlement.android

import org.ghost.entitlement.port.RedeemPort
import org.ghost.network.OnionAddress
import org.ghost.network.TorRelayTransport
import org.ghost.sync.api.NamespaceId
import org.ghost.sync.api.RelayRedeemAccess

/**
 * [RedeemPort] over the `RelayRedeemAccess` of a relay session (design §10.9, §11.6): `nativeRedeem`
 * on the namespace's own circuits of the process's one Tor transport. No protocol logic here.
 */
class TorRedeemPort(private val access: RelayRedeemAccess) : RedeemPort {
    override fun redeem(relay: OnionAddress, namespace: NamespaceId, token: ByteArray, requestId: ByteArray): TorRelayTransport.RedeemAnswer =
        access.redeem(relay, namespace, token, requestId)

    override fun stepDone() = access.stepDone()

    override fun toString(): String = "TorRedeemPort"
}
