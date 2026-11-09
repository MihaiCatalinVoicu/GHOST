package org.ghost.messaging.media

/**
 * The §15.3 crash-scenario reporting and sharding (design faza11-media.md §15.3; media-exit-gate.sh's
 * shard step). Each SCN scenario writes one line after its enumeration: `SCN-MX: N crash points
 * (<what was enumerated>), invariants hold` — the N is the run's real count and the parenthesis
 * names the coverage honestly (§15.3's full per-scenario scope is wider than every slice's; the
 * line must not claim more than the enumeration measured, ADR-10).
 *
 * Sharding: `-Dghost.media.shard=<1..shards>` `-Dghost.media.shards=<n>` assign scenario index i
 * (0-based, in SCN-MA…SCN-MF order) to shard `i % shards + 1`; the default (no properties) runs
 * everything in one invocation, as the PR job does.
 */
internal object MediaScenarios {

    val shard: Int = (System.getProperty("ghost.media.shard") ?: "1").toInt()
    val shards: Int = (System.getProperty("ghost.media.shards") ?: "1").toInt()

    /** Whether scenario [index] (0-based, SCN-MA…SCN-MF order) runs in this invocation's shard. */
    fun owns(index: Int): Boolean = (index % shards) + 1 == shard

    /** The enumeration's close-out line, written to the shared media report. */
    fun report(id: String, crashPoints: Int, coverage: String) {
        MediaPrivacyReport.line("$id: $crashPoints crash points ($coverage), invariants hold")
    }
}
