package org.ghost.sync.api

/** Capabilities are stored and used here, never minted (Phase 8 writes, Phase 7 uses; design §3.8). */
interface Capabilities {
    /**
     * Installs a token for (relay, namespace, kind): usable, a new generation, expiry floored to the
     * hour (null = unknown). For a write token, deliveries parked for lack of a capability and
     * pending key registrations of the pair are re-armed in the same transaction.
     */
    fun put(
        tx: SyncTransaction,
        relay: RelayId,
        namespace: NamespaceId,
        kind: CapabilityKind,
        token: ByteArray,
        expiresAtEpochSeconds: Long?,
    )

    fun needed(): List<CapabilityNeed>
}

/**
 * What Phase 8 should obtain for a pair. [source] is the namespace's [CapabilitySource]: the
 * entitlement planner never redeems a LOCAL need (Phase 9 design §13.4), it only counts it.
 */
class CapabilityNeed(
    val relay: RelayId,
    val namespace: NamespaceId,
    val kind: CapabilityKind,
    val reason: Reason,
    val source: CapabilitySource = CapabilitySource.REDEEM,
) {
    enum class Reason { MISSING, REJECTED, EXHAUSTED, EXPIRING }

    override fun equals(other: Any?): Boolean =
        other is CapabilityNeed && other.relay == relay && other.namespace == namespace && other.kind == kind &&
            other.reason == reason && other.source == source

    override fun hashCode(): Int =
        (((relay.hashCode() * 31 + namespace.hashCode()) * 31 + kind.hashCode()) * 31 + reason.hashCode()) * 31 + source.hashCode()

    override fun toString(): String = "CapabilityNeed($kind, $reason, $source)"
}
