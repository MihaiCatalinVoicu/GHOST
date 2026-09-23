package org.ghost.messaging.dmworld

import org.ghost.messaging.DmDevice
import org.ghost.messaging.DmWorld
import java.security.MessageDigest

/** The operations a relay sees in a DM privacy world (§1.1's effective view, per relay). */
internal enum class ViewOp { STORE, LIST, GET, REGISTER }

/**
 * One event of the effective relay view (Phase 9 design §1.1: "op; namespace; blob hash; size
 * bucket; the TTL as stored; exact arrival time; the credential presented …; the onion circuit …;
 * stored bytes; `keys.redb` records").
 *
 * [client] and [cause] are **ground truth**, not relay-visible: the joins that need them (JD6's
 * store → action mapping, S-DM3's scoring) read them, and every relay-side attacker ignores them.
 */
internal class ViewEvent(
    val op: ViewOp,
    val relaySlot: Int,
    val client: Int,
    /** The relay-visible circuit: one per (client, namespace, relay session), §4.3's isolation. */
    val circuit: String,
    val namespace: ByteArray,
    val second: Long,
    /** STORE: the stored blob; GET: the blob served. */
    val bytes: ByteArray? = null,
    val blobHash: ByteArray? = null,
    val ttlSeconds: Long? = null,
    /** The credential presented (a write capability or a bearer credential v3), if any. */
    val credential: ByteArray? = null,
    /** REGISTER only: the `keys.redb` record. */
    val period: Long? = null,
    val keyKind: String? = null,
    val verifier: ByteArray? = null,
    /** STORE only, ground truth: what the sender's own tables say caused the op. */
    val cause: StoreCause? = null,
    /** STORE only, ground truth: the sender's op deadline (§10.1 R-T4), in epoch seconds. */
    val deadlineSecond: Long? = null,
    /**
     * LIST/GET only, **diagnostic**: the reader's contact row for a namespace it does not own, for a
     * failing JD7's message. No check decides anything on it — the reader's own state is what a
     * mutant would change (JD7 decides on [PrivacyWorld.establishments]).
     */
    val readerState: String? = null,
)

/**
 * Ground truth of one store: the sender's `dm_outbound_op` and `dm_outbound_item` rows, which name
 * the message an op carries. Which timer that message **should** have is not read from the sender
 * (JD5 derives it from the users' timer changes, [PrivacyWorld.timerChanges]).
 */
internal class StoreCause(
    val operationId: ByteArray,
    /** `item` or `bundle`, or null when the op has no `dm_outbound_op` row at all. */
    val purpose: String?,
    /** The message the item carries (`dm_outbound_item.message_ref`), if any. */
    val messageRef: ByteArray?,
    /** `reconnect`, `revocation`, `reset` for a control item. */
    val control: String?,
)

/**
 * The model relay set of a privacy world: four ES slots over two operators, the same table every
 * client holds, and the **effective view** of §1.1 recorded as it happens.
 *
 * **What it stands in for.** Like `ModelDmRelay` of S10, it is the Phase 7 transport: it reads the
 * ops `:messaging` enqueued, stores each at the relays of its `outbox_delivery` rows, and writes back
 * the delivery rows and outcome the sync engine would have written. The reads are the Phase 7 read
 * lane's: every listening namespace is listed at every relay of its `namespace_relay` set, and a hash
 * the device does not know yet is fetched from the first relay that lists it. Pending key
 * registrations are executed as the `:sync` work lane would, once their period is the current or
 * the next week (the core world's "redeem fairy" of §15.1 variant (a): the owner always holds a
 * capability in time).
 *
 * **What it does not model, declared in §22.16:** the credential-selection and capability layers of
 * the redeem lane (no token is ever redeemed, so JD3's redemption half and JD8 have no events),
 * send delays (every world here is STANDARD), circuits' open and close minutes, relay refusals and
 * every hostile mode but one: **WITHHOLD_ALL_BUNDLES** ([withholdBundles]) exists since the S11b
 * slice for the JD7 variant that bounds the attempts (§21.7 point 6, PM-31; §22.21).
 */
internal class ViewRelay(private val now: () -> Long) {

    val events = ArrayList<ViewEvent>()

    private class Stored(
        val hash: ByteArray,
        val bytes: ByteArray,
        val storedAt: Long,
        val ttl: Long,
        val from: Int,
    )

    /** `(slot, namespace hex)` → blobs, in store order. */
    private val stored = HashMap<Pair<Int, String>, MutableList<Stored>>()

    /**
     * `(client, namespace hex + stored hash hex)` → the hash of the bytes served to that client for
     * it (a twin's [serveTransform] may change them). Never a stand-in for the reader's own rows:
     * [serve] asks the reader whether it still holds a row for that hash.
     */
    private val served = HashMap<Pair<Int, String>, ByteArray>()

    /** A relay session counter per client: circuits are per session and namespace. */
    private val session = HashMap<Int, Int>()

    /**
     * Hook for the twin worlds of NI-DM1: what a relay serves one reader instead of a stored blob
     * (a flipped byte, a probe). Null leaves the blob as stored.
     */
    var serveTransform: ((reader: Int, from: Int, storedAt: Long, blob: ByteArray) -> ByteArray?)? = null

    /** Hook for the twin worlds: false keeps a stored blob from one reader (a relay withholding it). */
    var serveFilter: ((reader: Int, from: Int) -> Boolean)? = null

    /**
     * Hostile mode **WITHHOLD_ALL_BUNDLES** (§15.1's list, §21.7 point 6): every relay answers a
     * list of a card's bundle namespace by anyone but its owner as if it held nothing, so no
     * establishment ever gets a candidate and every one runs its three attempt windows out. The
     * lists themselves are recorded — they are what the JD7 variant bounds — and the lists that
     * hid at least one live bundle are counted in [bundleListsWithheld], so a variant world that
     * withheld nothing says so.
     */
    var withholdBundles: Boolean = false

    /** Lists (one per relay) under [withholdBundles] that answered empty over at least one live bundle. */
    var bundleListsWithheld: Int = 0
        private set

    /** Ops that carried no credential at a relay: Phase 7 would have left them `wait_capability`. */
    var storesWithoutCredential: Int = 0
        private set

    fun beginSession(client: Int) {
        session.merge(client, 1, Int::plus)
    }

    private fun circuit(client: Int, namespace: ByteArray): String =
        "c$client/${hex(namespace).take(12)}/s${session[client] ?: 0}"

    // ------------------------------------------------------------------ stores

    /** Takes every pending op off [device]'s outbox and stores it at the relays of its deliveries. */
    fun collect(client: Int, device: DmDevice): Int {
        val slotOf = slotMap(device)
        val ops = ArrayList<Array<Any?>>()
        device.sql.query(
            "SELECT operation_id, namespace_id, ciphertext, ttl_seconds, deadline_hour FROM outbox_op " +
                "WHERE outcome = 'pending' AND ciphertext IS NOT NULL ORDER BY rowid",
        ) { r ->
            ops += arrayOf(r.blob(0), r.blob(1), r.blob(2), r.long(3), if (r.isNull(4)) null else r.long(4))
        }
        var n = 0
        for (row in ops) {
            val operation = row[0] as ByteArray
            val namespace = row[1] as ByteArray
            val blob = row[2] as ByteArray
            val ttl = row[3] as Long
            val deadline = row[4] as Long?
            val hash = sha256(blob)
            val cause = causeOf(device, operation)
            val relays = ArrayList<Long>()
            device.sql.query(
                "SELECT relay_id FROM outbox_delivery WHERE operation_id = ? ORDER BY relay_id",
                listOf(operation),
            ) { relays += it.long(0) }
            for (relay in relays) {
                val slot = slotOf[relay] ?: error("relay $relay is not an ES slot of the world")
                val credential = capability(device, relay, namespace, "write")
                if (credential == null) storesWithoutCredential++
                events += ViewEvent(
                    op = ViewOp.STORE,
                    relaySlot = slot,
                    client = client,
                    circuit = circuit(client, namespace),
                    namespace = namespace,
                    second = now(),
                    bytes = blob,
                    blobHash = hash,
                    ttlSeconds = ttl,
                    credential = credential,
                    cause = cause,
                    deadlineSecond = deadline,
                )
                stored.getOrPut(slot to hex(namespace)) { ArrayList() } +=
                    Stored(hash, blob, now(), ttl, client)
            }
            release(device, operation)
            n++
        }
        return n
    }

    private fun causeOf(device: DmDevice, operation: ByteArray): StoreCause {
        var purpose: String? = null
        var item: ByteArray? = null
        device.sql.query(
            "SELECT purpose, item_id FROM dm_outbound_op WHERE operation_id = ?",
            listOf(operation),
        ) { r ->
            purpose = r.string(0)
            item = if (r.isNull(1)) null else r.blob(1)
        }
        var messageRef: ByteArray? = null
        var control: String? = null
        item?.let { id ->
            device.sql.query(
                "SELECT message_ref, control FROM dm_outbound_item WHERE item_id = ?",
                listOf(id),
            ) { r ->
                messageRef = if (r.isNull(0)) null else r.blob(0)
                control = if (r.isNull(1)) null else r.string(1)
            }
        }
        return StoreCause(operation, purpose, messageRef, control)
    }

    /** The Phase 7 outbox engine's release, the recipe `DmOutcomeTest` pinned in S7. */
    private fun release(device: DmDevice, operation: ByteArray) {
        val hour = now().let { it - Math.floorMod(it, 3600L) }
        device.sql.exec(
            "UPDATE outbox_delivery SET state = 'verified', inflight = 0, copy_hour = ? " +
                "WHERE operation_id = ? AND state IN ('pending', 'wait_capability')",
            listOf(hour, operation),
        )
        device.sql.exec(
            "UPDATE outbox_op SET outcome = 'sent', ciphertext = NULL " +
                "WHERE operation_id = ? AND outcome = 'pending'",
            listOf(operation),
        )
    }

    // ------------------------------------------------------------------ reads

    /**
     * The read lane: every listening namespace is listed at every relay of its set, and every hash
     * the reader does not know is fetched once. Returns how many blobs were delivered.
     */
    fun serve(client: Int, device: DmDevice, ownNamespaces: Set<String>, contactBundles: Map<String, ByteArray>): Int {
        val slotOf = slotMap(device)
        val listening = ArrayList<ByteArray>()
        device.sql.query("SELECT namespace_id FROM sync_namespace WHERE listening = 1 ORDER BY namespace_id") {
            listening += it.blob(0)
        }
        var moved = 0
        for (namespace in listening) {
            val nsHex = hex(namespace)
            val readerState = if (nsHex in ownNamespaces) null else contactRow(device, contactBundles[nsHex])
            val withheld = withholdBundles && nsHex !in ownNamespaces && nsHex in contactBundles
            val relays = ArrayList<Long>()
            device.sql.query(
                "SELECT relay_id FROM namespace_relay WHERE namespace_id = ? ORDER BY relay_id",
                listOf(namespace),
            ) { relays += it.long(0) }
            val handledThisRound = HashSet<String>()
            for (relay in relays) {
                val slot = slotOf[relay] ?: continue
                val credential = capability(device, relay, namespace, "read")
                    ?: capability(device, relay, namespace, "write")
                events += ViewEvent(
                    op = ViewOp.LIST,
                    relaySlot = slot,
                    client = client,
                    circuit = circuit(client, namespace),
                    namespace = namespace,
                    second = now(),
                    credential = credential,
                    readerState = readerState,
                )
                if (withheld) {
                    if (stored[slot to nsHex].orEmpty().any { it.storedAt + it.ttl > now() }) bundleListsWithheld++
                    continue
                }
                for (blob in stored[slot to nsHex].orEmpty()) {
                    if (blob.from == client) continue
                    if (serveFilter?.invoke(client, blob.from) == false) continue
                    if (blob.storedAt + blob.ttl <= now()) continue
                    val key = nsHex + hex(blob.hash)
                    if (!handledThisRound.add(key)) continue
                    // The read lane fetches a hash the reader holds no row for, and the reader's
                    // rows are the only memory it has: what the relay once served this reader is
                    // served again when the reader holds no row for it any more. A card's bundle
                    // namespace is where that happens by design — `Inbox.forgetConsumed` (§21.7
                    // point 2) deletes the reader's tombstones so a reset, a key change or a
                    // re-added contact can fetch the same live bundle again (found by NI-DM2's
                    // reset twin, §22.21) — and anywhere else it would be a lost tombstone, which
                    // shows as a second GET of the same hash instead of being hidden by the model.
                    // The hash looked up is the one of the bytes actually served (a twin's
                    // [serveTransform] may have changed them).
                    val before = served[client to key]
                    if (before != null && known(device, namespace, before)) continue
                    val bytes = serveTransform?.invoke(client, blob.from, blob.storedAt, blob.bytes) ?: blob.bytes
                    served[client to key] = sha256(bytes)
                    if (!insert(device, namespace, bytes)) continue
                    events += ViewEvent(
                        op = ViewOp.GET,
                        relaySlot = slot,
                        client = client,
                        circuit = circuit(client, namespace),
                        namespace = namespace,
                        second = now(),
                        bytes = blob.bytes,
                        blobHash = blob.hash,
                        credential = credential,
                        readerState = readerState,
                    )
                    moved++
                }
            }
        }
        return moved
    }

    /** Whether the reader holds any inbox row (a fetched blob or a tombstone) for [hash]. */
    private fun known(device: DmDevice, namespace: ByteArray, hash: ByteArray): Boolean {
        var exists = false
        device.sql.query(
            "SELECT 1 FROM inbox_blob WHERE namespace_id = ? AND blob_hash = ?",
            listOf(namespace, hash),
        ) { exists = true }
        return exists
    }

    /** The reader's contact row for the owner of [identityPk], for a failing JD7's message only. */
    private fun contactRow(device: DmDevice, identityPk: ByteArray?): String {
        identityPk ?: return "no card's bundle namespace"
        var state = "no contact"
        device.sql.query(
            "SELECT establishment, trust_state, fetch_attempts FROM dm_contact WHERE identity_pk = ?",
            listOf(identityPk),
        ) { state = "${it.string(0)}/${it.string(1)}/${it.long(2)}" }
        return state
    }

    /**
     * Puts a blob into a reader's inbox directly, as a relay serving a probe or a replay would
     * (NI-DM1). The blob is not stored at any relay and no GET is recorded: the twins compare the
     * **reader's** view, and a relay-injected blob is the relay's own doing.
     */
    fun inject(device: DmDevice, namespace: ByteArray, blob: ByteArray): Boolean = insert(device, namespace, blob)

    private fun insert(device: DmDevice, namespace: ByteArray, ciphertext: ByteArray): Boolean {
        val hash = sha256(ciphertext)
        var exists = false
        device.sql.query(
            "SELECT 1 FROM inbox_blob WHERE namespace_id = ? AND blob_hash = ?",
            listOf(namespace, hash),
        ) { exists = true }
        if (exists) return false
        val t = now()
        val retainUntilDay = DmWorld.ceil7(Math.floorDiv(t, DmWorld.DAY) + 24)
        device.sql.exec(
            "INSERT INTO inbox_blob(namespace_id, blob_hash, state, ciphertext, fetch_seq, " +
                "fetch_attempts, next_fetch_minute, offers, offer_after_minute, retain_until_day) " +
                "VALUES (?, ?, 'listed', NULL, NULL, 0, 0, 0, 0, ?)",
            listOf(namespace, hash, retainUntilDay),
        )
        device.sql.exec(
            "UPDATE inbox_blob SET state = 'fetched', ciphertext = ?, fetch_seq = ?, " +
                "relay_expiry_hour = ? WHERE namespace_id = ? AND blob_hash = ?",
            listOf(ciphertext, sequence++, DmWorld.ceilHour(t + 30 * DmWorld.DAY), namespace, hash),
        )
        return true
    }

    private var sequence = 1L

    // ------------------------------------------------------------ registrations

    /**
     * The `:sync` work lane's registration step (§4.8): a pending row whose period is this week or
     * the next is registered — one `keys.redb` record and one capture event — and marked `done`.
     */
    fun register(client: Int, device: DmDevice): Int {
        val slotOf = slotMap(device)
        val week = Math.floorDiv(now() - DmWorld.WEEK_ORIGIN, DmWorld.WEEK)
        val rows = ArrayList<Array<Any>>()
        device.sql.query(
            "SELECT relay_id, namespace_id, period_id, kind, verifier FROM relay_key_registration " +
                "WHERE state = 'pending' ORDER BY relay_id, namespace_id, period_id, kind",
        ) { r -> rows += arrayOf(r.long(0), r.blob(1), r.long(2), r.string(3), r.blob(4)) }
        var n = 0
        for (row in rows) {
            val relay = row[0] as Long
            val namespace = row[1] as ByteArray
            val period = row[2] as Long
            if (period != week && period != week + 1) continue
            val slot = slotOf[relay] ?: continue
            events += ViewEvent(
                op = ViewOp.REGISTER,
                relaySlot = slot,
                client = client,
                circuit = circuit(client, namespace),
                namespace = namespace,
                second = now(),
                period = period,
                keyKind = row[3] as String,
                verifier = row[4] as ByteArray,
            )
            val validUntil = DmWorld.WEEK_ORIGIN + (period + 2) * DmWorld.WEEK + 3_600
            device.sql.exec(
                "UPDATE relay_key_registration SET state = 'done', inflight = 0, lease_hour = NULL, " +
                    "valid_until_hour = ? WHERE relay_id = ? AND namespace_id = ? AND period_id = ? AND kind = ?",
                listOf(validUntil, relay, namespace, period, row[3]),
            )
            n++
        }
        return n
    }

    // ------------------------------------------------------------------ helpers

    private fun capability(device: DmDevice, relay: Long, namespace: ByteArray, kind: String): ByteArray? {
        var token: ByteArray? = null
        device.sql.query(
            "SELECT token FROM relay_capability WHERE relay_id = ? AND namespace_id = ? AND kind = ? " +
                "AND state = 'usable'",
            listOf(relay, namespace, kind),
        ) { token = it.blob(0) }
        return token
    }

    private val slotMaps = HashMap<DmDevice, Map<Long, Int>>()

    private fun slotMap(device: DmDevice): Map<Long, Int> =
        slotMaps.getOrPut(device) { device.slots.associate { it.relay.value to it.slot } }

    /** Every blob a relay holds, for the seizure world's archive (§15.6 T34: "every archived blob"). */
    fun archive(): List<Triple<ByteArray, ByteArray, Long>> =
        stored.entries.flatMap { (key, blobs) ->
            blobs.map { Triple(unhex(key.second), it.bytes, it.storedAt) }
        }.distinctBy { hex(sha256(it.second)) }

    companion object {
        fun sha256(bytes: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(bytes)

        fun hex(bytes: ByteArray): String = bytes.joinToString("") { "%02x".format(it) }

        fun unhex(text: String): ByteArray = ByteArray(text.length / 2) {
            text.substring(2 * it, 2 * it + 2).toInt(16).toByte()
        }
    }
}
