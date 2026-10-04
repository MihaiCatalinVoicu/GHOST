package org.ghost.messaging.channel

import org.ghost.messaging.DmWorld
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
 *    F7 resurrection: the tombstone, or MLS, or `ch_seen` must stop them) and [hold] (blobs a predicate keeps back while
 *    it holds).
 *
 * **Why the receipts are written on the raw rows.** The outcome is what Phase 7 would decide; writing it is the model's
 * whole job (the same two statements `ModelDmRelay.release` writes, in the order the triggers require).
 */
internal class ModelChannelRelay {

    enum class Mode { DROP_WELCOME, COPY_JOIN, FAKE_WELCOME, REPLACE_BOOTSTRAP, REPLAY_JOIN, SHUFFLE, REPEATS, COPY_NAMESPACE }

    var modes: Set<Mode> = emptySet()

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

    /** How far past the store the relay claims a blob expires (`InboundBlob.relayExpiryHour`): its TTL, honestly. */
    var expiryFor: (Stored) -> Long = { it.storedAt + it.ttl }

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
        out.stored += stored
        out.collected += collected
        out.served += served
        out.sequence = sequence
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
        client.sql.query("SELECT namespace_id FROM sync_namespace WHERE listening = 1 AND consumer = 'channel'") {
            listening += hex(it.blob(0))
        }
        if (listening.isEmpty()) return 0
        var candidates = stored.filter { hex(it.namespace) in listening && it.from != client.name && now < it.storedAt + it.ttl }
        // FAKE_WELCOME: the adversary's blobs first; otherwise in the order they were stored.
        candidates = if (Mode.FAKE_WELCOME in modes) candidates.sortedBy { !it.injected } else candidates
        if (Mode.SHUFFLE in modes) candidates = candidates.sortedBy { hex(sha256(it.hash + (shuffle++).toByte())) }
        var moved = 0
        for (blob in candidates) {
            if (hold(blob) || holdAt(client.name, blob)) continue
            if (Mode.REPLACE_BOOTSTRAP in modes && !blob.injected && blob.purpose == "welcome") continue
            val key = hex(blob.namespace) + hex(blob.hash) + "@" + client.name
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
        return moved
    }

    /**
     * The two-step arrival the Phase 7 schema makes a fetch (`listed`, then `fetched` with the ciphertext and the relay
     * expiry), unless the client already holds the row: the inbox tombstone (§6.3.4 layer 1). False when refused.
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
        return true
    }

    companion object {
        const val ADVERSARY: String = "adversary"

        fun sha256(bytes: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(bytes)

        fun hex(bytes: ByteArray): String = bytes.joinToString("") { "%02x".format(it) }

        fun unhex(text: String): ByteArray = ByteArray(text.length / 2) { i -> text.substring(2 * i, 2 * i + 2).toInt(16).toByte() }
    }
}
