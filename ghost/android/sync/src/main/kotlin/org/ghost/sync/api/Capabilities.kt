package org.ghost.sync.api

/** Capabilities are stored and used here, never minted (Phase 8 writes, Phase 7 uses; design §3.8). */
interface Capabilities {
    /**
     * Installs a token for (relay, namespace, kind): usable, a new generation, expiry floored to the
     * hour (null = unknown). For a write token, deliveries parked for lack of a capability are re-armed
     * in the same transaction, and so are the pending key registrations of the pair when the write
     * token is the capability that serves them (an unfunded namespace of source REDEEM, Phase 9).
     *
     * **[CapabilityKind.REGISTER]** (Phase 10 design §7.5): the registration capability of a funded
     * namespace, a row of its own table. It re-arms the pair's pending key registrations when the
     * namespace is funded ([Funding]) and nothing else; it is never read by a store, a listing, a
     * fetch or a check. A write token put for a funded namespace — the channel's shared DEPOSIT
     * credential — re-arms the parked deliveries and leaves the registrations alone.
     */
    fun put(
        tx: SyncTransaction,
        relay: RelayId,
        namespace: NamespaceId,
        kind: CapabilityKind,
        token: ByteArray,
        expiresAtEpochSeconds: Long?,
    )

    /**
     * What Phase 8 should obtain for each (relay, namespace) pair (design §3.8). For a namespace this
     * client funds ([Funding]) it also reports [CapabilityKind.REGISTER] needs (Phase 10 design §7.5
     * item 1): a registration is pending at the relay and no registration capability is held (MISSING),
     * or a held one is rejected, exhausted or expiring. A REGISTER need always has the source
     * [CapabilitySource.REDEEM], whatever the namespace's own source is.
     */
    fun needed(): List<CapabilityNeed>

    /**
     * What is installed for the triple today, in the caller's transaction, or null when nothing
     * is. Reads only: it installs nothing and wakes nothing. For [CapabilityKind.REGISTER] the
     * registration capability of the pair.
     *
     * Phase 9's `KEEPER` step (design §4.8) needs it. The owner's READ credential v3 is a bearer
     * credential it mints itself, with an 8-day expiry it refreshes "when fewer than 7 days
     * remain", so the step has to see what it put there the last time — and it must not re-put on
     * every pass, because [put] bumps the generation (and, for a write token, re-arms parked
     * deliveries and pending registrations). A copy of the expiry kept in memory would be lost at
     * every restart and would re-put on every start.
     *
     * The **state** matters as much as the expiry: §21.2 point 8 has a refused own READ credential
     * heal its pair's registrations and stay refused — reads fall back to the write capability —
     * until those rows are done again, which is a decision the step can only make by reading the
     * row back.
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
 * entitlement planner never redeems a LOCAL need (Phase 9 design §13.4), it only counts it. The one
 * exception is by construction: a [CapabilityKind.REGISTER] need is reported with the source
 * REDEEM even for a LOCAL namespace, because the capability it asks for is bought with the funder's
 * own token and is no credential the consumer could install itself (Phase 10 design §7.6).
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
