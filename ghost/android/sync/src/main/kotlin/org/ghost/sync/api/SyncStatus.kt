package org.ghost.sync.api

/** State of the Tor transport as the sync engine last saw it. */
enum class TransportStatus { OFF, STARTING, READY, UNAVAILABLE, BRIDGE_CONFIG, TRANSPORT_FAILED, NATIVE_MISSING }

/** Conditions worth surfacing (design §3.6, §4.3); enums only, never an identifier. */
enum class StatusFlag {
    /** A relay acknowledged a store and later did not show it (design §3.4). */
    RELAY_SUSPECT,

    /** A relay refused an item permanently (`rejected`). */
    RELAY_REJECTS,

    /** A local bug category was seen (`invalid_argument`, `not_bucket_sized`, `not_onion`, ...). */
    BUG,

    /** A category missing from the error table was seen. */
    UNKNOWN_CATEGORY,

    /** A fetched blob was offered three or more times without being consumed. */
    CONSUMER_POISONED,

    /** A fetched blob is still unconsumed after its retention day (design §11.2 #7). */
    EXPIRED_UNCONSUMED,

    /** Some (relay, namespace) pair needs a capability ([Capabilities.needed]). */
    CAPABILITY_NEEDED,
}

/** Durable counts derived from the sync tables. */
class SyncCounts(
    /** Operations whose outcome is not decided yet. */
    val pendingOperations: Int,
    /** Deliveries parked for lack of a usable write capability. */
    val waitingForCapability: Int,
    /** Decided outcomes not yet released by their consumer. */
    val unreleasedOutcomes: Int,
    /** Listed or unavailable hashes not fetched yet. */
    val listedBacklog: Int,
    /** Fetched blobs not consumed yet. */
    val fetchedUnconsumed: Int,
    /** Fetched blobs offered three or more times without being consumed. */
    val consumerPoisoned: Int,
    /** Fetched blobs still unconsumed after their retention day. */
    val expiredUnconsumed: Int,
    /** Capability needs ([Capabilities.needed] size). */
    val capabilityNeeds: Int,
) {
    override fun toString(): String =
        "SyncCounts(pending=$pendingOperations, waitingForCapability=$waitingForCapability, unreleased=$unreleasedOutcomes, " +
            "backlog=$listedBacklog, fetched=$fetchedUnconsumed, poisoned=$consumerPoisoned, expiredUnconsumed=$expiredUnconsumed, " +
            "capabilityNeeds=$capabilityNeeds)"

    companion object {
        val EMPTY: SyncCounts = SyncCounts(0, 0, 0, 0, 0, 0, 0, 0)
    }
}

/** What [SyncController.status] reports: counts and enums only (design §7.3). */
class SyncStatus(
    val transport: TransportStatus,
    val mode: PrivacyMode,
    val flags: Set<StatusFlag>,
    val counts: SyncCounts,
) {
    val consumerPoisoned: Int get() = counts.consumerPoisoned
    val expiredUnconsumed: Int get() = counts.expiredUnconsumed

    override fun toString(): String = "SyncStatus($transport, $mode, $flags, $counts)"
}
