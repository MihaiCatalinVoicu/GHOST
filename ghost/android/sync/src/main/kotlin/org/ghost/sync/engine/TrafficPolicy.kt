package org.ghost.sync.engine

import org.ghost.sync.store.StoreLimits

/**
 * Traffic, capacity and budget parameters (design §6.2, §3.7, §11.2 #1, #2, #12), in one place so
 * Phase 12 can tune them against NFR-1 and NFR-5. [DEFAULT] is the production policy; the exit-gate
 * harness passes a policy with a small [listLimit] (design §8.3). Durations are milliseconds of
 * monotonic time unless the name says seconds.
 */
class TrafficPolicy(
    /** T: foreground interval per pair; each step is T × U[0.5, 1.5] (ADR-15). */
    val intervalMillis: Long = 30_000,
    /** W: a background job gives each pair one event at a keyed offset within this window. */
    val backgroundWindowMillis: Long = 90_000,
    /** `limit` of every list request, identical for all clients (ADR-09 fixed batches). */
    val listLimit: Int = 128,
    /** STANDARD: pages per event, a further page only while the previous one was full and advanced. */
    val standardPagesPerEvent: Int = 4,
    /** HIGH: exactly this many pages per event. */
    val highPagesPerEvent: Int = 1,
    /** Fetches per pair event in the foreground (events every ~T). */
    val foregroundFetchesPerEvent: Int = 8,
    /** Fetches per pair event in a background job (§11.2 #2). */
    val backgroundFetchesPerEvent: Int = 32,
    /** HIGH: stores per pair event. */
    val storesPerPairEvent: Int = 8,
    /** STANDARD: stores per maintenance pass. */
    val storesPerPass: Int = 32,
    /**
     * Fetched, due, not suspect rows per namespace that stop further fetches (§11.2 #1). The
     * exit-gate harness scales it down so a backlog above the cap stays enumerable (S-H).
     */
    val fetchedCap: Int = StoreLimits.FETCHED_CAP,
    /** Listed and unavailable rows per (relay, namespace) above which pages are dropped (§11.2 #2). */
    val backlogCap: Int = StoreLimits.BACKLOG_CAP,
    /** Hashes per `check` request (verification and resolution together). */
    val checkBatch: Int = StoreLimits.CHECK_BATCH,
    /** A read event that cannot start within this of its scheduled time is skipped, not delayed. */
    val lateToleranceMillis: Long = 2_000,
    /** Deadline of a list request. */
    val listDeadlineMillis: Int = 20_000,
    /** Deadline of every other relay call. */
    val callDeadlineMillis: Int = 60_000,
    /** Read-lane workers for events (first pages), serialized per pair (§11.2 #12). */
    val readWorkers: Int = 4,
    /** Read pairs listed at every one of their events; beyond it pairs share events round-robin. */
    val maxReadPairs: Int = 64,
    /** Acked deliveries of write-only pairs and pairs without a read token are checked after this. */
    val verifyAckAgeSeconds: Long = 60,
    /** Other acked deliveries are checked when listing has not verified them within this. */
    val verifyFallbackSeconds: Long = 600,
    /** Background session budget (under the ~10 min job limit). */
    val backgroundSessionMillis: Long = 8 * 60_000,
    /** Background: work-lane call time per relay per session. */
    val backgroundRelayWorkMillis: Long = 90_000,
    /** A call's deadline leaves this much of the session budget unused. */
    val deadlineReserveMillis: Long = 5_000,
    /** Shortest deadline worth a call; with less budget left the call is not made. */
    val minCallMillis: Int = 1_000,
    /** Bound on one transport bootstrap in the foreground (native bound: 180 s). */
    val bootstrapMillis: Long = 180_000,
    /** Maintenance pass period (M2–M4; STANDARD stores). Due times are minute-granular. */
    val passIntervalMillis: Long = 60_000,
    /** Foreground garbage-collection period. */
    val gcIntervalMillis: Long = 3_600_000,
) {
    init {
        require(intervalMillis >= 2) { "interval out of range" }
        require(backgroundWindowMillis >= 0) { "background window out of range" }
        require(listLimit in 1..MAX_BATCH) { "list limit out of range" }
        require(standardPagesPerEvent >= 1 && highPagesPerEvent >= 1) { "pages per event out of range" }
        require(foregroundFetchesPerEvent >= 1 && backgroundFetchesPerEvent >= 1) { "fetches per event out of range" }
        require(storesPerPairEvent >= 1 && storesPerPass >= 1) { "stores per event out of range" }
        require(fetchedCap >= 1 && backlogCap >= 1) { "caps out of range" }
        require(checkBatch in 1..StoreLimits.CHECK_BATCH) { "check batch out of range" }
        require(lateToleranceMillis >= 0) { "late tolerance out of range" }
        require(listDeadlineMillis in 1..MAX_DEADLINE_MILLIS && callDeadlineMillis in 1..MAX_DEADLINE_MILLIS) { "deadline out of range" }
        require(readWorkers >= 1 && maxReadPairs >= 1) { "read capacity out of range" }
        require(minCallMillis in 1..listDeadlineMillis) { "minimum call time out of range" }
        require(backgroundSessionMillis > deadlineReserveMillis && backgroundRelayWorkMillis > 0) { "budget out of range" }
        require(passIntervalMillis > 0 && gcIntervalMillis > 0 && bootstrapMillis > 0) { "period out of range" }
    }

    override fun toString(): String = "TrafficPolicy(interval=$intervalMillis, listLimit=$listLimit)"

    companion object {
        /** Largest list page and check batch the Rust core accepts. */
        const val MAX_BATCH: Int = 256

        /** Largest per-call deadline (RELAY_RPC_DEADLINE). */
        const val MAX_DEADLINE_MILLIS: Int = 60_000

        val DEFAULT: TrafficPolicy = TrafficPolicy()
    }
}
