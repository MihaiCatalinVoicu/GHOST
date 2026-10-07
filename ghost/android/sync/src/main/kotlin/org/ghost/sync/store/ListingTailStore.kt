package org.ghost.sync.store

import org.ghost.sync.api.NamespaceId
import org.ghost.sync.api.RelayId
import java.util.concurrent.ConcurrentHashMap

/**
 * The last **completed tail listing** per (relay, namespace), in monotonic milliseconds (design
 * §6.3.1 (a) and §6.4 CO-4 (ii); finding F-S4-1 of §19.37, built in S5a): the read lane records the
 * time it finished listing a namespace from one relay to that relay's tail — a page that returned
 * fewer rows than the limit, an empty next cursor, or a cursor unchanged from the one sent. A
 * further page then means the tail was not reached and nothing is recorded; a page dropped at
 * BACKLOG_CAP is not a completed pass either (the member does not hold everything the relay serves).
 *
 * In-memory, deliberately: a process start forgets every pass, so a consumer that needs "one listing
 * pass over every relay of the current generation's set" (CO-4 (ii)) treats an absent relay as "no
 * pass yet" — conservative after a restart, and no schema change for a signal the channel engine
 * re-derives within one listing interval (§19.37 row 34; the engine slice consumes it, S5).
 */
internal class ListingTailStore {

    private class Key(val relay: Long, val ns: ByteArray) {
        override fun equals(other: Any?): Boolean =
            other is Key && other.relay == relay && other.ns.contentEquals(ns)

        override fun hashCode(): Int = 31 * relay.hashCode() + ns.contentHashCode()
    }

    private val tails = ConcurrentHashMap<Key, Long>()

    /** Records that [relay] was listed in [ns] to its tail at monotonic [atMillis] (later wins). */
    fun record(relay: RelayId, ns: NamespaceId, atMillis: Long) {
        tails[Key(relay.value, ns.raw.copyOf())] = atMillis
    }

    /** Every relay with a completed tail listing of [ns] in this process, and when (monotonic ms). */
    fun of(ns: NamespaceId): Map<RelayId, Long> =
        tails
            .filterKeys { it.ns.contentEquals(ns.raw) }
            .mapKeys { RelayId(it.key.relay) }

    override fun toString(): String = "ListingTailStore(tails=${tails.size})"
}
