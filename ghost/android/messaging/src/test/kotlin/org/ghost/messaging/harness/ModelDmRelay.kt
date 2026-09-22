package org.ghost.messaging.harness

import org.ghost.messaging.DmWorld
import java.security.MessageDigest

/**
 * The model relay set of a crash world: it takes stores off each node's outbox, keeps them for
 * their TTL, serves them to whichever node listens on the namespace, and tells the sender what
 * happened (Phase 9 design §15.1 "`ModelRelay` extensions", §15.3's three relay events).
 *
 * **What this stands in for, and what it does not.** The transport between `:messaging` and a
 * relay is the Phase 7 sync engine — lanes, leases, quorum, breakers, cursors — and it is proved
 * exhaustively by `sync-exit-gate`. Re-driving it here would re-prove Phase 7 and would put every
 * DM crash class behind two engines at once. So this relay *is* the transport: it reads the ops
 * `:messaging` enqueued through `Outbox.enqueue`, and it writes back the delivery rows and outcome
 * the sync engine would have written. Everything between those two seams is Phase 7's and is
 * declared as such in §22.15. Everything inside them — SEND, RECV, BUNDLE, HELD, OUTCOME, SWEEP,
 * the ratchet, the seal — is the real thing, which is what the DM crash enumeration is about.
 *
 * **Why the receipts are written on the raw connection.** The event counter is what a crash class
 * is named by, and a class has to mean something about `:messaging`. Writing the Phase 7 rows
 * through the armed executor would put Phase 7's statements into `:messaging`'s event stream and
 * make "crash at k" mean "crash inside the sync engine" for a third of all k. The relay's own three
 * phases are the crash points that stand for that window, which is exactly what §15.3 asks for.
 */
internal class ModelDmRelay(private val bus: DmEventBus) {

    /** The hostile modes of §15.1 this slice implements. */
    enum class Mode {
        /** Serves blobs of a namespace in a scrambled order (SCN-B, RO2). */
        SHUFFLE,

        /** Serves each blob twice in the same round (RP1: the tombstone refuses the second). */
        REPEATS,

        /** Keeps a blob back for one round (RO7, SCN-E). */
        WITHHOLD,

        /** Flips a byte of the served ciphertext (RP9: it must not open, and must not answer). */
        TRUNCATE,

        /**
         * Stores the blob and tells the sender it failed: RP6's "re-encryption after a wrongly
         * reported FAILED".
         *
         * It is the only way to reach D3 from the outside. Every other duplicate the sender can
         * produce carries identical bytes and dies at D1's tombstone; a user retry after a FAILED
         * re-encrypts, so the bytes differ, the hash differs, and the only thing left that says
         * "this is the same message" is the `dm_seen` tag over its `message_id`.
         */
        LIE_FAILED,
    }

    var modes: Set<Mode> = emptySet()

    /** What the relay says a store's outcome was. `sent` unless a mode or a test says otherwise. */
    var outcomeFor: (String) -> String = { "sent" }

    /**
     * How far past the store the relay claims the blob expires (`InboundBlob.relayExpiryHour`, the
     * **E** of §10.3). 30 days is the honest store-and-forward horizon.
     */
    var expirySeconds: Long = 30 * DmWorld.DAY

    private class Stored(
        val namespace: ByteArray,
        val hash: ByteArray,
        val ciphertext: ByteArray,
        val storedAt: Long,
        val ttl: Long,
        val from: String,
    )

    private val stored = ArrayList<Stored>()

    /** `(operation hex, node)` pairs already taken off an outbox, so a round is idempotent. */
    private val collected = HashSet<String>()

    /** `(namespace hex + hash hex, node)` pairs already served, so a round does not repeat. */
    private val served = HashSet<String>()

    /** Blobs [Mode.WITHHOLD] has already kept back once. */
    private val withheld = HashSet<String>()

    private var sequence = 1L
    private var shuffleCounter = 0

    /**
     * One round: every node's pending stores reach the relay, then every stored blob reaches every
     * node that listens on its namespace. Returns how many blobs were delivered.
     */
    fun pump(nodes: List<DmNode>): Int {
        for (node in nodes) collect(node)
        var moved = 0
        for (node in nodes) moved += serve(node)
        return moved
    }

    // ------------------------------------------------------------------ store side

    private fun collect(node: DmNode) {
        val rows = ArrayList<Array<Any>>()
        node.raw.query(
            "SELECT o.operation_id, o.namespace_id, o.ciphertext, o.ttl_seconds " +
                "FROM outbox_op o JOIN sync_namespace n ON n.namespace_id = o.namespace_id " +
                "WHERE o.outcome = 'pending' AND o.ciphertext IS NOT NULL ORDER BY o.rowid",
        ) { rows += arrayOf(it.blob(0), it.blob(1), it.blob(2), it.long(3)) }
        for (row in rows) {
            val operation = row[0] as ByteArray
            val namespace = row[1] as ByteArray
            val ciphertext = row[2] as ByteArray
            val ttl = row[3] as Long
            val key = operation.hex() + "@" + node.name
            if (!collected.add(key)) continue
            bus.event(DmEventKind.RELAY_BEFORE_SEND, node.name, "store ${operation.hex().take(8)}")
            val outcome = if (Mode.LIE_FAILED in modes) "failed" else outcomeFor(operation.hex())
            // LIE_FAILED stores it anyway: that is the whole of the lie.
            if (outcome != "failed" || Mode.LIE_FAILED in modes) {
                stored += Stored(
                    namespace, sha256(ciphertext), ciphertext, node.clock.now, ttl, node.name,
                )
            }
            val applied = bus.event(DmEventKind.RELAY_AFTER_APPLY, node.name, "stored")
            if (applied === DmFault.TimeoutAfterApply) {
                // The relay has it; the sender does not know. Its op stays `pending`, the next
                // round re-stores identical bytes, and the recipient must dedup at D1 or D3 —
                // which is the window §7.6 exists for. Re-storing is what a Phase 7 retry does, so
                // the collection key is dropped rather than kept.
                collected.remove(key)
                continue
            }
            release(node, operation, outcome)
            bus.event(DmEventKind.RELAY_AFTER_RESPONSE, node.name, "released $outcome")
        }
    }

    /**
     * What the Phase 7 outbox engine writes when an operation is decided (the recipe `DmOutcomeTest`
     * pinned in S7): the deliveries settle first with a `copy_hour`, then the op takes its outcome
     * and its ciphertext is wiped. `outbox_op_payload` refuses the wipe while any delivery is still
     * in flight, and `OutboxStore.enqueue` refuses identical bytes into a namespace until the wipe
     * — so the order is not cosmetic and a resend of §7.5 depends on it.
     */
    private fun release(node: DmNode, operation: ByteArray, outcome: String) {
        val hour = node.clock.now.let { it - Math.floorMod(it, 3600L) }
        node.raw.exec(
            "UPDATE outbox_delivery SET state = ?, inflight = 0, copy_hour = ? " +
                "WHERE operation_id = ? AND state IN ('pending', 'wait_capability')",
            listOf(if (outcome == "failed") "failed" else "verified", hour, operation),
        )
        node.raw.exec(
            "UPDATE outbox_op SET outcome = ?, ciphertext = NULL " +
                "WHERE operation_id = ? AND outcome = 'pending'",
            listOf(outcome, operation),
        )
    }

    // ------------------------------------------------------------------ read side

    private fun serve(node: DmNode): Int {
        val listening = HashSet<String>()
        node.raw.query("SELECT hex(namespace_id) FROM sync_namespace WHERE listening = 1") {
            listening += it.string(0).lowercase()
        }
        if (listening.isEmpty()) return 0
        var candidates = stored.filter { it.namespace.hex() in listening && it.from != node.name }
        if (Mode.SHUFFLE in modes) {
            // A deterministic scramble: a world that fails must fail again on the same seed.
            candidates = candidates.sortedBy { sha256(it.hash + (shuffleCounter++).toByte()).hex() }
        }
        var moved = 0
        for (blob in candidates) {
            if (blob.storedAt + blob.ttl <= node.clock.now) continue
            val key = blob.namespace.hex() + blob.hash.hex() + "@" + node.name
            // WITHHOLD keeps each blob back for **one** round and then serves it, and it is
            // checked before the served set on purpose: a withheld blob that had already been
            // marked served would never be served at all, which is a lost message rather than a
            // late one — and the property RO7 is about ("loss 0 with peek ordering and the gap
            // hold") is about late ones.
            if (Mode.WITHHOLD in modes && withheld.add(key)) continue
            val fresh = served.add(key)
            if (!fresh && Mode.REPEATS !in modes) continue
            val bytes = if (Mode.TRUNCATE in modes) flip(blob.ciphertext) else blob.ciphertext
            if (insert(node, blob.namespace, bytes)) moved += 1
            if (Mode.REPEATS in modes && insert(node, blob.namespace, bytes)) moved += 1
        }
        return moved
    }

    /**
     * The two-step arrival the Phase 7 schema makes a fetch: `listed` first (`inbox_blob_insert`),
     * then `fetched` with the ciphertext and the relay expiry (`inbox_blob_state` and the two v4
     * triggers of §13.6 step 2). Writing the end state directly would model a path the real engine
     * cannot reach. Returns false when the namespace already holds this hash — a tombstone, which
     * is D1 doing its job.
     */
    private fun insert(node: DmNode, namespace: ByteArray, ciphertext: ByteArray): Boolean {
        val hash = sha256(ciphertext)
        var exists = false
        node.raw.query(
            "SELECT 1 FROM inbox_blob WHERE namespace_id = ? AND blob_hash = ?",
            listOf(namespace, hash),
        ) { exists = true }
        if (exists) return false
        var known = false
        node.raw.query(
            "SELECT 1 FROM sync_namespace WHERE namespace_id = ?",
            listOf(namespace),
        ) { known = true }
        if (!known) return false
        val now = node.clock.now
        val retainUntilDay = DmWorld.ceil7(Math.floorDiv(now, DmWorld.DAY) + 24)
        node.raw.exec(
            "INSERT INTO inbox_blob(namespace_id, blob_hash, state, ciphertext, fetch_seq, " +
                "fetch_attempts, next_fetch_minute, offers, offer_after_minute, retain_until_day) " +
                "VALUES (?, ?, 'listed', NULL, NULL, 0, 0, 0, 0, ?)",
            listOf(namespace, hash, retainUntilDay),
        )
        node.raw.exec(
            "UPDATE inbox_blob SET state = 'fetched', ciphertext = ?, fetch_seq = ?, " +
                "relay_expiry_hour = ? WHERE namespace_id = ? AND blob_hash = ?",
            listOf(ciphertext, sequence++, DmWorld.ceilHour(now + expirySeconds), namespace, hash),
        )
        return true
    }

    /** How many blobs the relay is holding. */
    val blobCount: Int get() = stored.size

    private fun flip(bytes: ByteArray): ByteArray =
        bytes.copyOf().also { it[it.size / 2] = (it[it.size / 2].toInt() xor 0x5a).toByte() }

    private companion object {
        fun sha256(bytes: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(bytes)
    }
}
