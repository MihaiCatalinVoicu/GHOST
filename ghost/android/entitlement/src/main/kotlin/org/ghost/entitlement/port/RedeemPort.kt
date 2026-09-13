package org.ghost.entitlement.port

import org.ghost.network.OnionAddress
import org.ghost.network.TorRelayTransport
import org.ghost.sync.api.NamespaceId

/**
 * Token redemption at a relay (Phase 8 design §10.9), on the namespace's own circuits. Production:
 * `android.TorRedeemPort` over the relay session's `RelayRedeemAccess` (relay sessions only). Before
 * any I/O the native side requires the token to be bound by the schedule to this relay's slot in its
 * week; the answer is checked against the schedule. `REPLAYED` and `WRONG_PERIOD` are results;
 * failures are `NetworkException(category)` or [IllegalArgumentException].
 */
interface RedeemPort {
    fun redeem(relay: OnionAddress, namespace: NamespaceId, token: ByteArray, requestId: ByteArray): TorRelayTransport.RedeemAnswer
}
