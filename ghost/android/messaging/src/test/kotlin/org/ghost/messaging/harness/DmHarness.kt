package org.ghost.messaging.harness

import org.ghost.messaging.DmWorld

/**
 * Harness-wide settings, and the one switch that separates a PR run from the exit-gate run
 * (Phase 9 design §15.3, §15.4; the `ghost.sync.exhaustive` / `ghost.sync.seeds` pattern of the
 * Phase 7 harness, which the `sync-exit-gate` job of `ci.yml` already sets the same way — a job,
 * not a workflow file of its own, unlike `messaging-exit-gate.yml`).
 *
 * A DM crash run is expensive in a way a `:sync` one is not: every run opens real DM contexts,
 * builds real Olm sessions through `ghost-dm-host` and writes real SQLite files. So the default is
 * a **sampled** enumeration — every [DEFAULT_SAMPLE]-th event — and `-Dghost.dm.crash=full` is the
 * gate's every-event run. The sampling is on the event index and nothing else, so a sampled run is
 * a subset of the full one and never a different enumeration.
 */
internal object DmHarness {

    /** Every n-th crash point on a PR; 1 in the gate. */
    const val DEFAULT_SAMPLE: Int = 13

    /** Seeded worlds per run (§15.4: "1 000 seeds per PR … 20 000 in `messaging-exit-gate.yml`"). */
    const val DEFAULT_SEEDS: Int = 8

    val full: Boolean get() = System.getProperty("ghost.dm.crash") == "full"

    val sample: Int
        get() = System.getProperty("ghost.dm.sample")?.toIntOrNull() ?: if (full) 1 else DEFAULT_SAMPLE

    val seeds: Int
        get() = System.getProperty("ghost.dm.seeds")?.toIntOrNull() ?: if (full) 64 else DEFAULT_SEEDS

    /** Where the run writes its report; `messaging-exit-gate.yml` reads it with `dm-report-check.sh`. */
    val reportPath: String
        get() = System.getProperty("ghost.dm.report") ?: "build/reports/dm/report.txt"

    /** True when `ghost-dm-host` is loadable: every world here needs the real ratchet. */
    fun nativeAvailable(): Boolean = DmWorld.nativeAvailable()

    const val SKIP_MESSAGE: String =
        "set -Dghost.dm.native to the ghost-dm-host library: every S10 world runs the real ratchet"

    /**
     * Worker threads for independent runs.
     *
     * Each run builds its own world on its own temporary directory with its own DM contexts, so
     * runs share nothing but the loaded library — which is the same sharing the Phase 7 harness
     * relies on in `Harness.parallel`, and the same the `crypto-bridge` native tests already do.
     */
    val threads: Int
        get() = System.getProperty("ghost.dm.threads")?.toIntOrNull()
            ?: Runtime.getRuntime().availableProcessors().coerceIn(1, 8)

    /** Runs [tasks] on [threads] workers; the first failure is rethrown with its label. */
    fun <T> parallel(tasks: List<Pair<String, () -> T>>): List<T> {
        if (tasks.isEmpty()) return emptyList()
        val pool = java.util.concurrent.Executors.newFixedThreadPool(minOf(threads, tasks.size))
        try {
            val futures = tasks.map { (label, task) ->
                label to pool.submit(java.util.concurrent.Callable { task() })
            }
            return futures.map { (label, future) ->
                try {
                    future.get()
                } catch (e: java.util.concurrent.ExecutionException) {
                    val cause = e.cause ?: e
                    throw AssertionError("$label: ${cause.message}", cause)
                }
            }
        } finally {
            pool.shutdownNow()
            pool.awaitTermination(20, java.util.concurrent.TimeUnit.MINUTES)
        }
    }
}
