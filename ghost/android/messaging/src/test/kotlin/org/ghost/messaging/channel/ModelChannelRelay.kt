package org.ghost.messaging.channel

import org.ghost.messaging.DmWorld
import org.ghost.sync.api.NamespaceId
import java.security.MessageDigest

/**
 * The model relay set of the channel worlds (Phase 10 design §12.1 "`ModelRelay` … plus"; the recipe of the DM's
 * `ModelDmRelay`): it takes the stores off each client's outbox, keeps them for their TTL, serves them to every client
 * that listens on the namespace (never back to their author: Phase 7 writes an own tombstone at the enqueue, so an own
 * blob is never fetched) and writes back the delivery rows and the outcome the Phase 7 engine would have written.
 *
 * **The hostile modes of §12.1 that slice S4's tests need**, each built by the first test that needs it:
 *  - [Mode.DROP_WELCOME] — the relay drops every WELCOME blob (and still reports it stored): the joiner never joins, and
 *    its join expires (§6.2.2 step 4);
 *  - [Mode.COPY_JOIN] — every join request is copied into every other namespace the relay knows: the copies open nowhere
 *    (their hint names another generation's `R_join`, and the seal binds the namespace, CS-S3);
 *  - [Mode.FAKE_WELCOME] — the adversary's forged Welcomes ([inject]) are served **before** the honest blobs of the
 *    round: a holder of `JK_g` who is not a committer builds its own group under the channel's id (S0-15);
 *  - [Mode.REPLACE_BOOTSTRAP] — the honest Welcome is held back while the injected substitute is served, and released
 *    when the mode is cleared (PC-17: the joiner refuses the substitute and keeps waiting);
 *  - [Mode.REPLAY_JOIN] — the injected re-wrapped or re-sealed join request is served after the honest one was admitted
 *    (an insider replays a request; the committer must refuse it);
 *  - and, for the receive suites: [Mode.SHUFFLE] (a deterministic scramble of each round's order), [Mode.REPEATS]
 *    (each blob served once per relay of [relayCount]: the copies die at the tombstone, [repeatsRefused] counts them),
 *    [Mode.COPY_NAMESPACE] (every post also stored into every other namespace the relay knows: the seal binds the
 *    namespace, and another channel's keys do not match its hint, §6.3.4 layer 3), [resurrect] (blobs stored again, the
 *    F7 resurrection: the tombstone, or MLS, or `ch_seen` must stop them), [hold] (blobs a predicate keeps back while
 *    it holds) and [fetchedCap] (Phase 7's `FETCHED_CAP`: a client at the cap of a namespace is served nothing more of
 *    it until it consumes or defers rows, §19.38).
 *
 * **The hostile modes of §12.1 that slice S5's commit-and-post suites need** (SCN-CM, SCN-CD, SCN-CL; each built by
 * the first test that needs it):
 *  - [Mode.FORK] — the relay serves different same-epoch commits to two subsets: [forkServing] names, per injected
 *    blob, the client subset that receives it (every other listener never sees it: the partition);
 *  - [Mode.WITHHOLD_COMMIT] — [hold]/[holdAt] keep one commit blob from all or a subset, for good or until the test
 *    releases it ([withheld] counts the skips; SCN-CL's "for good" is S7's scenario);
 *  - [Mode.REORDER_ACROSS_EPOCH] — [orderKey] serves an epoch e + 1 blob before epoch e's winner at chosen members
 *    (a stable reorder of the round by the key the test assigns each blob);
 *  - [Mode.RESURRECT_COMMIT] — [resurrect] stores a consumed candidate's bytes again (the engine's layer 2 refuses
 *    the copy, counted `RESURRECTED_COMMIT`);
 *  - [Mode.LATE_COMMIT] — a valid commit for an epoch, stored only after a chosen member settled it ([holdAt] until
 *    the member's settle, then released): the settled members record a fork signal and never move (CO-6, MM-16);
 *  - [Mode.GRIND] — a member that kept an old epoch's state stores a hash-ground self-update for a settled epoch
 *    (built by [org.ghost.messaging.channel.ChannelAdversary], injected here; never moves anyone: CO-6, MM-16/MM-24);
 *  - [Mode.SPAM_UNOPENABLE] — bulk junk a member seals under the current epoch's key id so the recognition matches
 *    but no key opens it (built by the adversary, injected here; consumed and counted `FORGED_SEAL`, and CO-11's
 *    window counts it toward `resync_needed`; the draining-namespace half is MM-37, S6/S7).
 *
 * Every fetched blob is also recorded in `inbox_source` for the client's whole relay set (what the real read lane
 * writes at `InboxStore.list`: a store reaches every relay of its set), so the engine's CO-11 can attribute the blob
 * to operators through `relay_directory`.
 *
 * **Why the receipts are written on the raw rows.** The outcome is what Phase 7 would decide; writing it is the model's
 * whole job (the same two statements `ModelDmRelay.release` writes, in the order the triggers require).
 */
internal class ModelChannelRelay {

    enum class Mode {
        DROP_WELCOME, COPY_JOIN, FAKE_WELCOME, REPLACE_BOOTSTRAP, REPLAY_JOIN, SHUFFLE, REPEATS, COPY_NAMESPACE,
        FORK, WITHHOLD_COMMIT, REORDER_ACROSS_EPOCH, RESURRECT_COMMIT, LATE_COMMIT, GRIND, SPAM_UNOPENABLE,
        // Slice S7 (SCN-CE's EXPIRE_LOG variant, SCN-CL's silent orphan, MM-36/MM-37):
        EXPIRE_LOG, SILENT_ORPHAN,
    }

    var modes: Set<Mode> = emptySet()

    /**
     * Under [Mode.FORK], the subset of client names an injected blob is served to; null serves it to
     * every listener like any other blob. Two injected commits with disjoint subsets are the
     * relay-induced partition of §12.1 (SCN-CG's and SCN-M20's FORK variants are S7's/S10's).
     */
    var forkServing: (Stored) -> Set<String>? = { null }

    /**
     * Under [Mode.REORDER_ACROSS_EPOCH], the serving order of a round: a stable sort by this key
     * (then store order) runs before the tombstone check, so an epoch e + 1 blob keyed ahead of
     * epoch e's winner reaches the chosen members first (the deferral machinery must hold it).
     */
    var orderKey: (Stored) -> Int = { 0 }

    /** Under [Mode.WITHHOLD_COMMIT]/[Mode.LATE_COMMIT], how many serves [hold]/[holdAt] skipped. */
    var withheld = 0
        private set

    /** Under [Mode.REPEATS], how many relays serve each blob (a store reaches every relay of its set). */
    var relayCount: Int = 2

    /** What the relay says a store's outcome was, by client and op purpose (`sent` unless a test says otherwise). */
    var outcomeFor: (ChannelClient, String?) -> String = { _, _ -> "sent" }

    /**
     * A store whose op ends `failed` and that a relay kept all the same (a quorum missed, one replica written): what makes
     * a retry after FAILED a second copy of one op id (§6.3.4 layer 4). False unless a test says otherwise.
     */
    var storedThoughFailed: (ChannelClient, String?) -> Boolean = { _, _ -> false }

    /** Blobs this predicate holds are not served while it holds (a WITHHOLD of the test's choosing). */
    var hold: (Stored) -> Boolean = { false }

    /** The same, from one client only (by its name): a relay that withholds a blob from a subset. */
    var holdAt: (String, Stored) -> Boolean = { _, _ -> false }

    /**
     * [Mode.EXPIRE_LOG] (SCN-CE's variant): the matching blobs are never served and die at the relay
     * at their TTL un-fetched — a member whose missed commit expired on every relay before it listed
     * (CO-11's "missed commits past their TTL").
     */
    var expireLog: (Stored) -> Boolean = { false }

    /** [Mode.SILENT_ORPHAN] (SCN-CL's variant, MM-36): the matching blobs never reach this client at
     *  all — the member missed a rotating commit for good and its old namespace drains and goes quiet. */
    var silentOrphan: (String, Stored) -> Boolean = { _, _ -> false }

    /** How far past the store the relay claims a blob expires (`InboundBlob.relayExpiryHour`): its TTL, honestly. */
    var expiryFor: (Stored) -> Long = { it.storedAt + it.ttl }

    /**
     * Phase 7's `FETCHED_CAP` at each client (§19.38), or null for none: a blob of a namespace is fetched only while the
     * client holds fewer due fetched rows of it than the cap — `InboxStore.fetchedLoad`'s count (a deferred row, or one
     * the poison guard backed off, does not count) — and is otherwise left at the relay for a later round, unserved.
     */
    var fetchedCap: Int? = null

    /**
     * Called after [client] was served every blob its listening namespaces hold: one round served
     * everything the relay has, which is a completed listing pass over every relay of the set
     * (CO-4 (ii)'s signal in this world; the world records it in the client's [WorldInbox]).
     */
    var onListed: (ChannelClient, List<NamespaceId>) -> Unit = { _, _ -> }

    class Stored(
        val namespace: ByteArray,
        val hash: ByteArray,
        val ciphertext: ByteArray,
        val storedAt: Long,
        val ttl: Long,
        /** The client that stored it, or `adversary` for an injected blob. */
        val from: String,
        /** The op's purpose at its author (`post`, `commit`, `welcome`, `join`, `request`), or the injection's label. */
        val purpose: String?,
        val injected: Boolean = false,
    ) {
        override fun toString(): String = "Stored($purpose from $from)"
    }

    val stored = ArrayList<Stored>()
    private val collected = HashSet<String>()
    private val served = HashSet<String>()
    private var sequence = 1L
    private var shuffle = 0

    var repeatsOffered = 0
        private set
    var repeatsRefused = 0
        private set
    var copies = 0
        private set
    var dropped = 0
        private set

    /** The relay's whole state, for a world restored from a snapshot (the crash enumeration). */
    fun copy(): ModelChannelRelay {
        val out = ModelChannelRelay()
        out.modes = modes
        out.relayCount = relayCount
        out.outcomeFor = outcomeFor
        out.storedThoughFailed = storedThoughFailed
        out.hold = hold
        out.holdAt = holdAt
        out.expiryFor = expiryFor
        out.forkServing = forkServing
        out.orderKey = orderKey
        out.fetchedCap = fetchedCap
        out.onListed = onListed
        out.expireLog = expireLog
        out.silentOrphan = silentOrphan
        out.stored += stored
        out.collected += collected
        out.served += served
        out.sequence = sequence
        out.withheld = withheld
        return out
    }

    /** An adversary's blob, stored now in [namespace] and served like any other (or first, under FAKE_WELCOME). */
    fun inject(namespace: ByteArray, ciphertext: ByteArray, now: Long, label: String, ttl: Long = 7 * DmWorld.DAY) {
        stored += Stored(namespace, sha256(ciphertext), ciphertext, now, ttl, ADVERSARY, label, injected = true)
    }

    /**
     * The F7 resurrection (§6.3.4): every stored blob [which] selects is stored again now, the same bytes in the same
     * namespace, and offered again to every listener — a client that still holds its `(namespace, hash)` tombstone refuses
     * it at the insert (layer 1); one whose tombstone is gone hands it to the engine. Returns how many were resurrected.
     */
    fun resurrect(now: Long, which: (Stored) -> Boolean): Int {
        val again = stored.filter(which).map {
            Stored(it.namespace, it.hash, it.ciphertext, now, it.ttl, it.from, it.purpose, it.injected)
        }
        for (blob in again) served.removeAll { key -> key.startsWith(hex(blob.namespace) + hex(blob.hash) + "@") }
        stored += again
        return again.size
    }

    /** One round: every client's pending stores reach the relay, then every stored blob reaches every listener. */
    fun pump(clients: List<ChannelClient>, now: Long): Int {
        for (c in clients) collect(c, now)
        if (Mode.EXPIRE_LOG in modes) {
            // The held blobs die at the relay at their TTL, un-fetched: a missed commit past its TTL
            // is exactly "no blob ever arrives".
            stored.removeAll { expireLog(it) && now >= it.storedAt + it.ttl }
        }
        var moved = 0
        for (c in clients) moved += serve(c, now)
        return moved
    }

    /** The ops the clients still have pending (with their ciphertext): what a round would collect. */
    fun pendingOps(clients: List<ChannelClient>): Int =
        clients.sumOf { c -> c.count("outbox_op", "outcome = 'pending' AND ciphertext IS NOT NULL").toInt() }

    // ------------------------------------------------------------------------------------------- store side

    private fun collect(client: ChannelClient, now: Long) {
        val rows = ArrayList<Array<Any?>>()
        client.sql.query(
            "SELECT o.operation_id, o.namespace_id, o.ciphertext, o.ttl_seconds, c.purpose FROM outbox_op o " +
                "LEFT JOIN ch_outbound_op c ON c.operation_id = o.operation_id " +
                "WHERE o.outcome = 'pending' AND o.ciphertext IS NOT NULL ORDER BY o.rowid",
        ) { rows += arrayOf(it.blob(0), it.blob(1), it.blob(2), it.long(3), if (it.isNull(4)) null else it.string(4)) }
        for (row in rows) {
            val operation = row[0] as ByteArray
            val namespace = row[1] as ByteArray
            val ciphertext = row[2] as ByteArray
            val ttl = row[3] as Long
            val purpose = row[4] as String?
            val key = hex(operation) + "@" + client.name
            if (!collected.add(key)) continue
            val outcome = outcomeFor(client, purpose)
            if (outcome != "failed" || storedThoughFailed(client, purpose)) {
                if (Mode.DROP_WELCOME in modes && purpose == "welcome") {
                    dropped++
                } else {
                    stored += Stored(namespace, sha256(ciphertext), ciphertext, now, ttl, client.name, purpose)
                    if (Mode.COPY_JOIN in modes && purpose == "join") copyJoin(namespace, ciphertext, now, ttl, client.name)
                    if (Mode.COPY_NAMESPACE in modes && purpose == "post") copyInto(namespace, ciphertext, now, ttl, client.name, "post-copy")
                }
            }
            release(client, operation, outcome, now)
        }
    }

    /** COPY_JOIN: the request into every other namespace the relay knows (the seal binds the namespace, CS-S3). */
    private fun copyJoin(namespace: ByteArray, ciphertext: ByteArray, now: Long, ttl: Long, from: String) =
        copyInto(namespace, ciphertext, now, ttl, from, "join-copy")

    /** The blob into every other namespace the relay knows, labelled [label]. */
    private fun copyInto(namespace: ByteArray, ciphertext: ByteArray, now: Long, ttl: Long, from: String, label: String) {
        val others = stored.map { hex(it.namespace) }.toSet() - hex(namespace)
        for (other in others) {
            stored += Stored(unhex(other), sha256(ciphertext), ciphertext, now, ttl, from, label)
            copies++
        }
    }

    /** What the Phase 7 outbox writes at a decided op: the deliveries settle with a copy hour, then the op's outcome. */
    private fun release(client: ChannelClient, operation: ByteArray, outcome: String, now: Long) {
        val hour = now - Math.floorMod(now, 3_600L)
        client.sql.exec(
            "UPDATE outbox_delivery SET state = ?, inflight = 0, copy_hour = ? " +
                "WHERE operation_id = ? AND state IN ('pending', 'wait_capability')",
            listOf(if (outcome == "failed") "failed" else "verified", hour, operation),
        )
        client.sql.exec(
            "UPDATE outbox_op SET outcome = ?, ciphertext = NULL WHERE operation_id = ? AND outcome = 'pending'",
            listOf(outcome, operation),
        )
    }

    // -------------------------------------------------------------------------------------------- read side

    private fun serve(client: ChannelClient, now: Long): Int {
        val listening = HashSet<String>()
        val namespaces = ArrayList<NamespaceId>()
        client.sql.query("SELECT namespace_id FROM sync_namespace WHERE listening = 1 AND consumer = 'channel'") {
            val raw = it.blob(0)
            listening += hex(raw)
            namespaces += NamespaceId(raw)
        }
        if (listening.isEmpty()) return 0
        var candidates = stored.filter { hex(it.namespace) in listening && it.from != client.name && now < it.storedAt + it.ttl }
        // FAKE_WELCOME: the adversary's blobs first; otherwise in the order they were stored.
        candidates = if (Mode.FAKE_WELCOME in modes) candidates.sortedBy { !it.injected } else candidates
        if (Mode.REORDER_ACROSS_EPOCH in modes) {
            // A stable key sort: the same set reaches every client, in the test's order (§12.1).
            candidates = candidates.sortedBy(orderKey)
        }
        if (Mode.SHUFFLE in modes) {
            // Each blob's key is drawn once, then sorted: a selector that drew a new key at every comparison broke the
            // comparator's contract, and TimSort refused a round of 150 blobs (the review of S4).
            val keyed = candidates.map { it to hex(sha256(it.hash + (shuffle++).toByte())) }
            candidates = keyed.sortedBy { it.second }.map { it.first }
        }
        var moved = 0
        for (blob in candidates) {
            if (hold(blob) || holdAt(client.name, blob)) {
                withheld++
                continue
            }
            if (Mode.EXPIRE_LOG in modes && expireLog(blob)) {
                withheld++
                continue
            }
            if (Mode.SILENT_ORPHAN in modes && silentOrphan(client.name, blob)) {
                continue
            }
            if (Mode.FORK in modes) {
                // A null subset serves the blob to every listener (the honest traffic); a named
                // subset is the fork: only it ever sees the blob.
                val subset = forkServing(blob)
                if (subset != null && client.name !in subset) continue
            }
            if (Mode.REPLACE_BOOTSTRAP in modes && !blob.injected && blob.purpose == "welcome") continue
            val key = hex(blob.namespace) + hex(blob.hash) + "@" + client.name
            if (key !in served && atCap(client, blob.namespace, now)) continue
            val fresh = served.add(key)
            if (!fresh && Mode.REPEATS !in modes) continue
            if (insert(client, blob, now)) moved++
            if (Mode.REPEATS in modes) {
                repeat(relayCount - 1) {
                    repeatsOffered++
                    if (insert(client, blob, now)) moved++ else repeatsRefused++
                }
            }
        }
        onListed(client, namespaces)
        return moved
    }

    /**
     * Whether [client] holds [fetchedCap] due fetched rows of [namespace]: `InboxStore.fetchedLoad`'s count — a row
     * offered fewer than `BACKOFF_OFFERS` (3) times whose re-offer time is not ahead (a deferral clamps at 7 days).
     */
    private fun atCap(client: ChannelClient, namespace: ByteArray, now: Long): Boolean {
        val cap = fetchedCap ?: return false
        var load = 0L
        client.sql.query(
            "SELECT count(*) FROM inbox_blob WHERE namespace_id = ? AND state = 'fetched' AND offers < 3 " +
                "AND (offer_after_minute <= ? OR offer_after_minute > ? + 604800)",
            listOf(namespace, now, now),
        ) { load = it.long(0) }
        return load >= cap
    }

    /**
     * The two-step arrival the Phase 7 schema makes a fetch (`listed`, then `fetched` with the ciphertext and the relay
     * expiry), unless the client already holds the row: the inbox tombstone (§6.3.4 layer 1). False when refused.
     * Also records `inbox_source` rows for every relay of the client's set (what `InboxStore.list` writes: a store
     * reaches every relay of its set), so the engine can attribute the blob to operators (`relay_directory`).
     */
    private fun insert(client: ChannelClient, blob: Stored, now: Long): Boolean {
        var exists = false
        client.sql.query("SELECT 1 FROM inbox_blob WHERE namespace_id = ? AND blob_hash = ?", listOf(blob.namespace, blob.hash)) {
            exists = true
        }
        if (exists) return false
        val retainUntilDay = DmWorld.ceil7(Math.floorDiv(now, DmWorld.DAY) + 24)
        client.sql.exec(
            "INSERT INTO inbox_blob(namespace_id, blob_hash, state, ciphertext, fetch_seq, fetch_attempts, next_fetch_minute, " +
                "offers, offer_after_minute, retain_until_day) VALUES (?, ?, 'listed', NULL, NULL, 0, 0, 0, 0, ?)",
            listOf(blob.namespace, blob.hash, retainUntilDay),
        )
        client.sql.exec(
            "UPDATE inbox_blob SET state = 'fetched', ciphertext = ?, fetch_seq = ?, relay_expiry_hour = ? " +
                "WHERE namespace_id = ? AND blob_hash = ?",
            listOf(blob.ciphertext, sequence++, DmWorld.ceilHour(expiryFor(blob)), blob.namespace, blob.hash),
        )
        for (slot in client.slots) {
            client.sql.exec(
                "INSERT OR IGNORE INTO inbox_source(namespace_id, blob_hash, relay_id, state) VALUES (?, ?, ?, 'candidate')",
                listOf(blob.namespace, blob.hash, slot.relay.value),
            )
        }
        return true
    }

    companion object {
        const val ADVERSARY: String = "adversary"

        fun sha256(bytes: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(bytes)

        fun hex(bytes: ByteArray): String = bytes.joinToString("") { "%02x".format(it) }

        fun unhex(text: String): ByteArray = ByteArray(text.length / 2) { i -> text.substring(2 * i, 2 * i + 2).toInt(16).toByte() }
    }
}
