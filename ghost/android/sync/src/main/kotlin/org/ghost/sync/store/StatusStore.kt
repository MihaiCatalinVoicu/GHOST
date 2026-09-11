package org.ghost.sync.store

import org.ghost.sync.api.SyncCounts
import org.ghost.sync.api.SyncTransaction

/** Durable counts for [org.ghost.sync.api.SyncStatus] (counts only, design §7.3, §11.2 #7). */
internal class StatusStore(private val capabilities: CapabilityStore) {

    fun counts(tx: SyncTransaction, now: Long): SyncCounts {
        val row = tx.sql.single(
            "SELECT (SELECT count(*) FROM outbox_op WHERE outcome = 'pending'), " +
                "(SELECT count(*) FROM outbox_delivery WHERE state = 'wait_capability'), " +
                "(SELECT count(*) FROM outbox_op WHERE outcome <> 'pending' AND released = 0), " +
                "(SELECT count(*) FROM inbox_blob WHERE state IN ('listed', 'unavailable')), " +
                "(SELECT count(*) FROM inbox_blob WHERE state = 'fetched'), " +
                "(SELECT count(*) FROM inbox_blob WHERE state = 'fetched' AND offers >= ${StoreLimits.BACKOFF_OFFERS}), " +
                "(SELECT count(*) FROM inbox_blob WHERE state = 'fetched' AND retain_until_day < ?1)",
            listOf(Time.day(now)),
        ) { r -> IntArray(7) { r.int(it) } } ?: throw IllegalStateException("status query returned no row")
        return SyncCounts(
            pendingOperations = row[0],
            waitingForCapability = row[1],
            unreleasedOutcomes = row[2],
            listedBacklog = row[3],
            fetchedUnconsumed = row[4],
            consumerPoisoned = row[5],
            expiredUnconsumed = row[6],
            capabilityNeeds = capabilities.needed(tx, now).size,
        )
    }
}
