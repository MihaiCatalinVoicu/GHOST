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

    /**
     * What is installed for the triple today, in the caller's transaction, or null when nothing
     * is. Reads only: it installs nothing and wakes nothing.
     *
     * Phase 9's `KEEPER` step (design §4.8) needs it. The owner's READ credential v3 is a bearer
     * credential it mints itself, with an 8-day expiry it refreshes "when fewer than 7 days
     * remain", so the step has to see what it put there the last time — and it must not re-put on
     * every pass, because [put] bumps the generation and re-arms parked deliveries. A copy of the
     * expiry kept in memory would be lost at every restart and would re-arm on every start.
     */
    fun installed(
        tx: SyncTransaction,
        relay: RelayId,
        namespace: NamespaceId,
        kind: CapabilityKind,
    ): InstalledCapability?
}

/** The state and floored expiry hour of an installed capability ([Capabilities.installed]). */
class InstalledCapability(val state: State, val expiresHour: Long?) {
    /** The `relay_capability.state` values of design §3.8. */
    enum class State { USABLE, REJECTED, EXHAUSTED }

    /** Never shows the token: this class deliberately carries none (T3). */
    override fun toString(): String = "InstalledCapability($state)"
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
