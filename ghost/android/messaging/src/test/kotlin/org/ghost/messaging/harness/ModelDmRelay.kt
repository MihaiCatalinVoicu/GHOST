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

        /** Re-serves a blob the recipient already consumed and forgot (RP2). */
        RESURRECT,

        /** Presents a blob of one namespace under another the recipient owns (RP3, B1). */
        COPY_NAMESPACE,

        /** Flips a byte of the served ciphertext (RP9: it must not open, and must not answer). */
        TRUNCATE,

        /** Does not release the sender's outcome for one round (§21.8 the INDETERMINATE window). */
        DELAY_RELEASE,

        /** Reports every store of one chosen sender as failed (SCN-G's "every relay refusing"). */
        REFUSE_ONE_SENDER,

        /** Never serves a `prekeys` namespace's newest blob (SCN-C, PM-31's JD7 variant). */
        WITHHOLD_NEWEST_BUNDLE,
    }

    var modes: Set<Mode> = emptySet()

    /** With [Mode.REFUSE_ONE_SENDER], the node whose stores fail. */
    var refusedSender: String? = null

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

    /** Ops whose outcome the relay is holding back ([Mode.DELAY_RELEASE]). */
    private val held = HashSet<String>()

    private var sequence = 1L
    private var shuffleCounter = 0

    /** Every store the relay accepted, for the report and for JD-style assertions. */
    val storeLog = ArrayList<String>()

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
            val outcome = if (Mode.REFUSE_ONE_SENDER in modes && refusedSender == node.name) {
                "failed"
            } else {
                outcomeFor(operation.hex())
            }
            if (outcome != "failed") {
                stored += Stored(
                    namespace, sha256(ciphertext), ciphertext, node.clock.now, ttl, node.name,
                )
                storeLog += "${node.name} ${namespace.hex()} ${ciphertext.size} $ttl"
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
            if (Mode.DELAY_RELEASE in modes && held.add(key)) continue
            release(node, operation, outcome)
            bus.event(DmEventKind.RELAY_AFTER_RESPONSE, node.name, "released $outcome")
        }
        if (Mode.DELAY_RELEASE in modes) {
            // Everything held in an earlier round is released now, one round late.
            val due = held.filter { it.endsWith("@${node.name}") }
            for (key in due) {
                held.remove(key)
                release(node, hexToBytes(key.substringBefore('@')), outcomeFor(key.substringBefore('@')))
            }
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
            val fresh = served.add(key)
            if (!fresh && Mode.RESURRECT !in modes && Mode.REPEATS !in modes) continue
            if (Mode.WITHHOLD in modes && blob === candidates.lastOrNull()) continue
            val bytes = if (Mode.TRUNCATE in modes) flip(blob.ciphertext) else blob.ciphertext
            val namespace = if (Mode.COPY_NAMESPACE in modes) {
                listening.firstOrNull { it != blob.namespace.hex() }?.let { hexToBytes(it) }
                    ?: blob.namespace
            } else {
                blob.namespace
            }
            if (insert(node, namespace, bytes)) moved += 1
            if (Mode.REPEATS in modes && insert(node, namespace, bytes)) moved += 1
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

    /** Forgets that [node] ever consumed these blobs: the RESURRECT of §15.1 after a tombstone GC. */
    fun forgetTombstones(node: DmNode) {
        served.removeAll { it.endsWith("@${node.name}") }
    }

    /** How many blobs the relay is holding. */
    val blobCount: Int get() = stored.size

    private fun flip(bytes: ByteArray): ByteArray =
        bytes.copyOf().also { it[it.size / 2] = (it[it.size / 2].toInt() xor 0x5a).toByte() }

    private companion object {
        fun sha256(bytes: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(bytes)

        fun hexToBytes(hex: String): ByteArray =
            ByteArray(hex.length / 2) { hex.substring(it * 2, it * 2 + 2).toInt(16).toByte() }
    }
}
