package org.ghost.update.harness

/**
 * The world's model of the Phase 7 `relay_directory` (Phase 14 design §7.8, §9.6.1's ACCEPT
 * transaction): seeded with the committed bootstrap relays, updated by the client's directory
 * hook from fresh manifests only. The write-once guard models what the device's directory
 * transaction enforces (a known onion's operator id is never overwritten — MC-D31's RELABEL):
 * an upsert that would relabel a known onion is refused and recorded, changing nothing.
 */
internal class WorldRelayDirectory {

    class Entry(val onion: String, val operator: ByteArray, val source: String)

    /** By onion (the canonical `<56>.onion:<port>` spelling). */
    val entries = LinkedHashMap<String, Entry>()

    /** Onions a manifest tried to relabel (the refused upserts). */
    val relabelAttempts = ArrayList<String>()

    /** Manifests the hook saw past their expiry (applied to nothing, MC-D30). */
    var staleSuppressions: Int = 0
        private set

    /** Instrumentation: relays the hook was asked to upsert (fresh manifests). */
    var upsertCalls: Int = 0
        private set

    fun seed(onion: String, operator: ByteArray) {
        entries[onion] = Entry(onion, operator, "config")
    }

    /** Applies one manifest upsert; false (and recorded) when it relabels a known onion. */
    fun upsert(onion: String, operator: ByteArray): Boolean {
        upsertCalls++
        val known = entries[onion]
        if (known != null && !known.operator.contentEquals(operator)) {
            relabelAttempts += onion
            return false
        }
        entries[onion] = Entry(onion, operator, "manifest")
        return true
    }

    fun recordStaleSuppression() {
        staleSuppressions++
    }
}
