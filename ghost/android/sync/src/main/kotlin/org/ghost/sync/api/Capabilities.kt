package org.ghost.sync.api

/** Capabilities are stored and used here, never minted (Phase 8 writes, Phase 7 uses; design §3.8). */
interface Capabilities {
    /**
     * Installs a token for (relay, namespace, kind): usable, a new generation, expiry floored to the
     * hour (null = unknown). For a write token, deliveries parked for lack of a capability are
     * re-armed in the same transaction.
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

class CapabilityNeed(val relay: RelayId, val namespace: NamespaceId, val kind: CapabilityKind, val reason: Reason) {
    enum class Reason { MISSING, REJECTED, EXHAUSTED, EXPIRING }

    override fun equals(other: Any?): Boolean =
        other is CapabilityNeed && other.relay == relay && other.namespace == namespace && other.kind == kind && other.reason == reason

    override fun hashCode(): Int = ((relay.hashCode() * 31 + namespace.hashCode()) * 31 + kind.hashCode()) * 31 + reason.hashCode()

    override fun toString(): String = "CapabilityNeed($kind, $reason)"
}
