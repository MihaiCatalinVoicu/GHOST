package org.ghost.sync.store

import org.ghost.sync.api.BlobHash
import org.ghost.sync.api.InboundBlob
import org.ghost.sync.api.NamespaceId
import org.ghost.sync.api.OperationId
import org.ghost.sync.api.RelayId
import org.ghost.sync.api.SyncChange
import org.ghost.sync.api.SyncTransaction
import org.ghost.sync.store.Sql.DEFER_CLAMP_SECONDS
import org.ghost.sync.store.Sql.DUE_CLAMP_SECONDS
import org.ghost.sync.store.Sql.OFFER_BACKOFF_CLAMP_SECONDS

/** What happened to a listed page (design §4.1). */
internal class PageCommit(
    val disposition: Disposition,
    /** Hashes of the page inserted or refreshed as listed rows (own and consumed hashes excluded). */
    val listedRows: Int,
    /** Own operations verified by this listing (design §3.4). */
    val verified: List<OperationId>,
    /** This commit stored the page's next cursor. */
    val cursorStored: Boolean,
    storedCursor: ByteArray?,
    /**
     * The stored cursor was no longer the one the request sent (a remove and re-register raced the
     * request, design §11.5 #3): the hashes were committed, the next cursor was not stored.
     */
    val staleCursor: Boolean,
) {
    private val after: ByteArray? = storedCursor?.copyOf()

    /**
     * The pair's stored cursor after this commit (empty = from the beginning), which the read lane
     * adopts; null when the page was dropped because the pair is no longer listened.
     */
    val cursor: ByteArray? get() = after?.copyOf()

    enum class Disposition {
        /** Hashes and cursor committed. */
        ACCEPTED,

        /** Over BACKLOG_CAP for this (relay, namespace): page discarded, cursor unchanged. */
        DROPPED_BACKLOG,

        /** The namespace no longer listens or the relay left its set: page discarded. */
        DROPPED_NOT_LISTENED,
    }

    override fun toString(): String = "PageCommit($disposition, listed=$listedRows, verified=${verified.size}, cursor=$cursorStored)"
}

internal enum class NotFoundResult {
    /** First `not_found` from this source: it is retried once, at least an hour later (§11.3). */
    RETRY_LATER,

    /** The source gave up (second `not_found`); other sources remain. */
    SOURCE_DROPPED,

    /** No usable source remains: the row is unavailable until a relay lists it again. */
    UNAVAILABLE,

    /** The row or the source was not in a state this answer applies to. */
    IGNORED,
}

/**
 * Inbox state (design §4 with §11.2 #1–#3 and §11.3). One row per (namespace, hash) is the dedup
 * key; sources record which relays listed a row that is not fetched yet.
 *
 * Source states: `candidate` (listed, not tried or not refused yet); `not_found` (answered
 * `not_found` once: retried once, at least [StoreLimits.NOT_FOUND_RETRY_SECONDS] later, when no
 * candidate is left); `bad` (unusable for this hash: served wrong bytes, or `not_found` twice).
 */
internal class InboxStore(private val outbox: OutboxStore, private val cursors: CursorStore) {

    // ------------------------------------------------------------------ list commit (§4.1)

    /**
     * Commits one page from relay [relay] for namespace [ns]: rows, sources, relisting, own-copy
     * verification and, only when [nextCursor] is non-empty, the cursor — all in the caller's one
     * transaction (IN-3). An empty cursor keeps the stored one (sticky tail). The cursor is a
     * compare-and-set (design §11.5 #3): it is stored only while the stored cursor is still
     * [sentCursor], the one the request was sent with (no row = the empty cursor). Otherwise a remove
     * and re-register raced the request: the hashes are committed, the stored cursor stays, and
     * [PageCommit.cursor] tells the read lane where to list from. [backlogCap] is the engine policy's
     * BACKLOG_CAP ([StoreLimits.BACKLOG_CAP] in production).
     */
    fun commitPage(
        tx: SyncTransaction,
        relay: RelayId,
        ns: NamespaceId,
        hashes: List<BlobHash>,
        sentCursor: ByteArray,
        nextCursor: ByteArray,
        now: Long,
        backlogCap: Int = StoreLimits.BACKLOG_CAP,
    ): PageCommit {
        require(backlogCap > 0) { "backlog cap must be positive" }
        require(nextCursor.isEmpty() || nextCursor.size == StoreLimits.CURSOR_SIZE) { "cursor has the wrong length" }
        require(sentCursor.isEmpty() || sentCursor.size == StoreLimits.CURSOR_SIZE) { "cursor has the wrong length" }
        val sql = tx.sql
        val listened = sql.single(
            "SELECT 1 FROM sync_namespace n JOIN namespace_relay nr ON nr.namespace_id = n.namespace_id " +
                "JOIN relay_directory rd ON rd.relay_id = nr.relay_id " +
                "WHERE n.namespace_id = ?1 AND n.listening = 1 AND nr.relay_id = ?2 AND rd.state = 'active'",
            listOf(ns.raw, relay.value),
        ) { 1 } != null
        if (!listened) return PageCommit(PageCommit.Disposition.DROPPED_NOT_LISTENED, 0, emptyList(), false, null, false)
        val stored = cursors.cursor(tx, relay, ns) ?: ByteArray(0)
        val stale = !stored.contentEquals(sentCursor)
        if (backlog(tx, relay, ns) >= backlogCap) {
            return PageCommit(PageCommit.Disposition.DROPPED_BACKLOG, 0, emptyList(), false, stored, stale)
        }
        val retain = RetentionPolicy.listedRetainDay(now)
        var listedRows = 0
        val verified = ArrayList<OperationId>()
        for (hash in LinkedHashSet(hashes)) {
            listedRows += sql.execUpdate(
                "INSERT INTO inbox_blob(namespace_id, blob_hash, state, retain_until_day) VALUES (?1, ?2, 'listed', ?3) " +
                    "ON CONFLICT(namespace_id, blob_hash) DO UPDATE " +
                    "SET retain_until_day = max(inbox_blob.retain_until_day, excluded.retain_until_day) " +
                    "WHERE inbox_blob.state IN ('listed', 'unavailable')",
                listOf(ns.raw, hash.raw, retain),
            )
            sql.execUpdate(
                "INSERT INTO inbox_source(namespace_id, blob_hash, relay_id, state) " +
                    "SELECT namespace_id, blob_hash, ?3, 'candidate' FROM inbox_blob " +
                    "WHERE namespace_id = ?1 AND blob_hash = ?2 AND state IN ('listed', 'unavailable') " +
                    "ON CONFLICT(namespace_id, blob_hash, relay_id) DO NOTHING",
                listOf(ns.raw, hash.raw, relay.value),
            )
            sql.execUpdate(
                "UPDATE inbox_blob SET state = 'listed' WHERE namespace_id = ?1 AND blob_hash = ?2 AND state = 'unavailable' " +
                    "AND EXISTS (SELECT 1 FROM inbox_source s WHERE s.namespace_id = ?1 AND s.blob_hash = ?2 AND s.state = 'candidate')",
                listOf(ns.raw, hash.raw),
            )
            outbox.verifyListed(tx, relay, ns, hash, now)?.let { verified += it }
        }
        val cursorStored = !stale && nextCursor.isNotEmpty()
        if (cursorStored) cursors.put(tx, relay, ns, nextCursor)
        return PageCommit(PageCommit.Disposition.ACCEPTED, listedRows, verified, cursorStored, if (cursorStored) nextCursor else stored, stale)
    }

    /** Listed or unavailable rows attributable to [relay] in [ns] (any source state), for BACKLOG_CAP. */
    fun backlog(tx: SyncTransaction, relay: RelayId, ns: NamespaceId): Int =
        tx.sql.single(
            "SELECT count(*) FROM inbox_source s JOIN inbox_blob b ON b.namespace_id = s.namespace_id AND b.blob_hash = s.blob_hash " +
                "WHERE s.relay_id = ?1 AND s.namespace_id = ?2 AND b.state IN ('listed', 'unavailable')",
            listOf(relay.value, ns.raw),
        ) { it.int(0) } ?: 0

    // ------------------------------------------------------------------ fetch (§4.2)

    /**
     * Fetched rows of [ns] that count against FETCHED_CAP: due for an offer and not suspect
     * (offers < 3, §11.2 #1). Deferred and backed-off rows do not throttle fetching.
     */
    fun fetchedLoad(tx: SyncTransaction, ns: NamespaceId, now: Long): Int =
        tx.sql.single(
            "SELECT count(*) FROM inbox_blob WHERE namespace_id = ?1 AND state = 'fetched' AND offers < ${StoreLimits.BACKOFF_OFFERS} " +
                "AND (offer_after_minute <= ?2 OR offer_after_minute > ?2 + $DEFER_CLAMP_SECONDS)",
            listOf(ns.raw, now),
        ) { it.int(0) } ?: 0

    /**
     * Up to [limit] listed rows of [ns] due for a fetch from [relay]: the relay is a candidate for
     * the row, or it answered `not_found` once and no candidate is left (the retry). Oldest
     * retention first, then hash. Empty while the namespace is at [fetchedCap] (the engine policy's
     * FETCHED_CAP, [StoreLimits.FETCHED_CAP] in production).
     */
    fun dueFetches(
        tx: SyncTransaction,
        relay: RelayId,
        ns: NamespaceId,
        now: Long,
        limit: Int,
        fetchedCap: Int = StoreLimits.FETCHED_CAP,
    ): List<BlobHash> {
        require(limit > 0 && fetchedCap > 0) { "limit must be positive" }
        val room = fetchedCap - fetchedLoad(tx, ns, now)
        if (room <= 0) return emptyList()
        return tx.sql.rows(
            "SELECT b.blob_hash FROM inbox_blob b JOIN inbox_source s ON s.namespace_id = b.namespace_id AND s.blob_hash = b.blob_hash " +
                "WHERE b.namespace_id = ?1 AND b.state = 'listed' " +
                "AND (b.next_fetch_minute <= ?2 OR b.next_fetch_minute > ?2 + $DUE_CLAMP_SECONDS) " +
                "AND s.relay_id = ?3 AND (s.state = 'candidate' OR (s.state = 'not_found' AND NOT EXISTS (SELECT 1 FROM inbox_source c " +
                "WHERE c.namespace_id = b.namespace_id AND c.blob_hash = b.blob_hash AND c.state = 'candidate'))) " +
                "ORDER BY b.retain_until_day, b.blob_hash LIMIT ?4",
            listOf(ns.raw, now, relay.value, minOf(limit, room)),
        ) { BlobHash(it.blob(0)) }
    }

    /** Fetch attempts already leased for a listed row (the backoff exponent of the next lease), or null. */
    fun fetchAttempts(tx: SyncTransaction, ns: NamespaceId, hash: BlobHash): Int? =
        tx.sql.single(
            "SELECT fetch_attempts FROM inbox_blob WHERE namespace_id = ?1 AND blob_hash = ?2 AND state = 'listed'",
            listOf(ns.raw, hash.raw),
        ) { it.int(0) }

    /** Write-ahead fetch lease: attempts + 1 and the next try after [backoffSeconds]. False if not due. */
    fun leaseFetch(tx: SyncTransaction, ns: NamespaceId, hash: BlobHash, now: Long, backoffSeconds: Long): Boolean {
        require(backoffSeconds in 0..Time.HOUR) { "backoff out of range" }
        return tx.sql.execUpdate(
            "UPDATE inbox_blob SET fetch_attempts = fetch_attempts + 1, next_fetch_minute = ?1 " +
                "WHERE namespace_id = ?2 AND blob_hash = ?3 AND state = 'listed' " +
                "AND (next_fetch_minute <= ?4 OR next_fetch_minute > ?4 + $DUE_CLAMP_SECONDS)",
            listOf(Time.dueMinute(now, backoffSeconds), ns.raw, hash.raw, now),
        ) == 1
    }

    /**
     * Fetch success: the row becomes fetched with the next local hand-off number and a retention
     * of `ceil7(day(relay expiry) + TAIL)`; its sources are dropped by trigger. The caller has
     * verified the ciphertext hash; it is checked again here.
     */
    fun recordFetched(tx: SyncTransaction, ns: NamespaceId, hash: BlobHash, ciphertext: ByteArray, expiryEpochSeconds: Long): Boolean {
        require(sha256(ciphertext) == hash) { "ciphertext does not match its hash" }
        val changed = tx.sql.execUpdate(
            "UPDATE inbox_blob SET state = 'fetched', ciphertext = ?1, fetch_seq = (SELECT COALESCE(MAX(fetch_seq), 0) + 1 FROM inbox_blob), " +
                "fetch_attempts = 0, next_fetch_minute = 0, retain_until_day = ?2 " +
                "WHERE namespace_id = ?3 AND blob_hash = ?4 AND state = 'listed'",
            listOf(ciphertext, RetentionPolicy.expiryRetainDay(expiryEpochSeconds), ns.raw, hash.raw),
        )
        if (changed == 1) tx.hint(SyncChange.INBOX)
        return changed == 1
    }

    /**
     * `get` answered `not_found` from [relay]. The first answer turns the source to `not_found` and,
     * if no candidate is left, holds the row for at least an hour before the retry; a second answer
     * makes the source `bad`. With no usable source left the row becomes unavailable.
     */
    fun recordNotFound(tx: SyncTransaction, relay: RelayId, ns: NamespaceId, hash: BlobHash, now: Long): NotFoundResult {
        val sql = tx.sql
        val source = sourceState(tx, relay, ns, hash) ?: return NotFoundResult.IGNORED
        return when (source) {
            "candidate" -> {
                sql.updateExactly(
                    1,
                    "UPDATE inbox_source SET state = 'not_found' WHERE namespace_id = ?1 AND blob_hash = ?2 AND relay_id = ?3 AND state = 'candidate'",
                    listOf(ns.raw, hash.raw, relay.value),
                )
                holdForRetry(tx, ns, hash, now)
                NotFoundResult.RETRY_LATER
            }
            "not_found" -> {
                sql.updateExactly(
                    1,
                    "UPDATE inbox_source SET state = 'bad' WHERE namespace_id = ?1 AND blob_hash = ?2 AND relay_id = ?3 AND state = 'not_found'",
                    listOf(ns.raw, hash.raw, relay.value),
                )
                if (makeUnavailableIfNoSource(tx, ns, hash)) NotFoundResult.UNAVAILABLE else NotFoundResult.SOURCE_DROPPED
            }
            else -> NotFoundResult.IGNORED
        }
    }

    /**
     * `get` from [relay] served wrong bytes (`malformed_response`): the source is `bad`. If only sources
     * that answered `not_found` once are left, their retry waits at least an hour. True if the row
     * became unavailable.
     */
    fun recordBadSource(tx: SyncTransaction, relay: RelayId, ns: NamespaceId, hash: BlobHash, now: Long): Boolean {
        tx.sql.execUpdate(
            "UPDATE inbox_source SET state = 'bad' WHERE namespace_id = ?1 AND blob_hash = ?2 AND relay_id = ?3 AND state IN ('candidate', 'not_found')",
            listOf(ns.raw, hash.raw, relay.value),
        )
        if (makeUnavailableIfNoSource(tx, ns, hash)) return true
        holdForRetry(tx, ns, hash, now)
        return false
    }

    /** With no candidate left, a listed row waits at least NOT_FOUND_RETRY_SECONDS before its `not_found` sources are retried. */
    private fun holdForRetry(tx: SyncTransaction, ns: NamespaceId, hash: BlobHash, now: Long) {
        tx.sql.execUpdate(
            "UPDATE inbox_blob SET next_fetch_minute = max(next_fetch_minute, ?1) WHERE namespace_id = ?2 AND blob_hash = ?3 " +
                "AND state = 'listed' AND NOT EXISTS (SELECT 1 FROM inbox_source c WHERE c.namespace_id = ?2 AND c.blob_hash = ?3 " +
                "AND c.state = 'candidate')",
            listOf(Time.dueMinute(now, StoreLimits.NOT_FOUND_RETRY_SECONDS), ns.raw, hash.raw),
        )
    }

    private fun sourceState(tx: SyncTransaction, relay: RelayId, ns: NamespaceId, hash: BlobHash): String? =
        tx.sql.single(
            "SELECT s.state FROM inbox_source s JOIN inbox_blob b ON b.namespace_id = s.namespace_id AND b.blob_hash = s.blob_hash " +
                "WHERE s.namespace_id = ?1 AND s.blob_hash = ?2 AND s.relay_id = ?3 AND b.state = 'listed'",
            listOf(ns.raw, hash.raw, relay.value),
        ) { it.string(0) }

    private fun makeUnavailableIfNoSource(tx: SyncTransaction, ns: NamespaceId, hash: BlobHash): Boolean =
        tx.sql.execUpdate(
            "UPDATE inbox_blob SET state = 'unavailable' WHERE namespace_id = ?1 AND blob_hash = ?2 AND state = 'listed' " +
                "AND NOT EXISTS (SELECT 1 FROM inbox_source s WHERE s.namespace_id = ?1 AND s.blob_hash = ?2 " +
                "AND s.state IN ('candidate', 'not_found'))",
            listOf(ns.raw, hash.raw),
        ) == 1

    // ------------------------------------------------------------------ hand-off (§4.3, §11.2 #3)

    /**
     * Offers fetched rows of the consumer's namespaces in local arrival order. The offer counter
     * (and, from the third offer, the backoff) is written before anything is returned, in the
     * caller's transaction, which must commit before the consumer handles the blobs. A suspect row
     * (offered twice already) is returned alone.
     */
    fun claim(tx: SyncTransaction, consumerCode: String, limit: Int, now: Long): List<InboundBlob> {
        require(limit > 0) { "limit must be positive" }
        val sql = tx.sql
        val due = sql.rows(
            "SELECT b.namespace_id, b.blob_hash, b.offers FROM inbox_blob b JOIN sync_namespace n ON n.namespace_id = b.namespace_id " +
                "WHERE n.consumer = ?1 AND b.state = 'fetched' AND (b.offer_after_minute <= ?2 OR b.offer_after_minute > ?2 + " +
                "CASE WHEN b.offers >= ${StoreLimits.BACKOFF_OFFERS} THEN $OFFER_BACKOFF_CLAMP_SECONDS ELSE $DEFER_CLAMP_SECONDS END) " +
                "ORDER BY b.fetch_seq LIMIT ?3",
            listOf(consumerCode, now, limit),
        ) { Offer(NamespaceId(it.blob(0)), BlobHash(it.blob(1)), it.int(2)) }
        val suspect = due.firstOrNull { it.offers >= StoreLimits.SUSPECT_OFFERS }
        val chosen = if (suspect != null) listOf(suspect) else due
        val out = ArrayList<InboundBlob>(chosen.size)
        for (offer in chosen) {
            val offers = offer.offers + 1
            val offerAfter = if (offers >= StoreLimits.BACKOFF_OFFERS) Time.dueMinute(now, offerBackoffSeconds(offers)) else null
            sql.updateExactly(
                1,
                "UPDATE inbox_blob SET offers = offers + 1, offer_after_minute = COALESCE(?1, offer_after_minute) " +
                    "WHERE namespace_id = ?2 AND blob_hash = ?3 AND state = 'fetched' AND offers = ?4",
                listOf(offerAfter, offer.namespace.raw, offer.hash.raw, offer.offers),
            )
            val ciphertext = sql.single(
                "SELECT ciphertext FROM inbox_blob WHERE namespace_id = ?1 AND blob_hash = ?2 AND state = 'fetched'",
                listOf(offer.namespace.raw, offer.hash.raw),
            ) { it.blob(0) } ?: throw IllegalStateException("claimed row vanished")
            out += InboundBlob(offer.namespace, offer.hash, ciphertext)
        }
        return out
    }

    private class Offer(val namespace: NamespaceId, val hash: BlobHash, val offers: Int)

    /** Consumed: the row becomes a tombstone carrying only (namespace, hash, retain_until_day). True exactly once. */
    fun markConsumed(tx: SyncTransaction, ns: NamespaceId, hash: BlobHash): Boolean =
        tx.sql.execUpdate(
            "UPDATE inbox_blob SET state = 'done', ciphertext = NULL, fetch_seq = NULL, offers = 0, offer_after_minute = 0 " +
                "WHERE namespace_id = ?1 AND blob_hash = ?2 AND state = 'fetched'",
            listOf(ns.raw, hash.raw),
        ) == 1

    /** Re-offer no earlier than [seconds] from now (1 s .. 7 d); resets the offer counter. */
    fun defer(tx: SyncTransaction, ns: NamespaceId, hash: BlobHash, seconds: Int, now: Long): Boolean {
        require(seconds in 1..StoreLimits.MAX_DEFER_SECONDS) { "defer is out of range" }
        return tx.sql.execUpdate(
            "UPDATE inbox_blob SET offer_after_minute = ?1, offers = 0 WHERE namespace_id = ?2 AND blob_hash = ?3 AND state = 'fetched'",
            listOf(Time.dueMinute(now, seconds.toLong()), ns.raw, hash.raw),
        ) == 1
    }

    companion object {
        /** Claim backoff for the n-th offer (n >= 3): 1 h, 2 h, 4 h, ... capped at 24 h. */
        fun offerBackoffSeconds(offers: Int): Long {
            require(offers >= StoreLimits.BACKOFF_OFFERS) { "no backoff before the third offer" }
            val doublings = minOf(offers - StoreLimits.BACKOFF_OFFERS, 5)
            return minOf(Time.HOUR shl doublings, StoreLimits.MAX_OFFER_BACKOFF_SECONDS)
        }
    }
}
