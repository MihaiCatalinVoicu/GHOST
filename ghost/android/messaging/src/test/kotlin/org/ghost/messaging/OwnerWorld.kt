package org.ghost.messaging

import org.ghost.crypto.bridge.DmCards
import org.ghost.crypto.bridge.DmRevocations
import org.ghost.crypto.bridge.DmSessions
import org.ghost.messaging.api.MediaPort
import org.ghost.messaging.api.MessageId
import org.ghost.messaging.api.NotificationPort
import org.ghost.messaging.engine.ContactMaterial
import org.ghost.messaging.engine.ContactSteps
import org.ghost.messaging.engine.DisplayStep
import org.ghost.messaging.engine.DmCounters
import org.ghost.messaging.engine.DmSyncPorts
import org.ghost.messaging.engine.EstablishmentSteps
import org.ghost.messaging.engine.ExpirySchedule
import org.ghost.messaging.engine.HeldReplay
import org.ghost.messaging.engine.KeyDecision
import org.ghost.messaging.engine.MediaOrphanSteps
import org.ghost.messaging.engine.MessagingEngine
import org.ghost.messaging.engine.OwnerSteps
import org.ghost.messaging.engine.PairKeySteps
import org.ghost.messaging.engine.ReceiveStep
import org.ghost.messaging.engine.RecognitionKeys
import org.ghost.messaging.engine.RelaySetResolver
import org.ghost.messaging.engine.ScheduledSteps
import org.ghost.messaging.engine.SelfContexts
import org.ghost.messaging.engine.SendStep
import org.ghost.messaging.engine.SessionSlots
import org.ghost.messaging.engine.Sweeper
import org.ghost.messaging.engine.UnreadNotices
import org.ghost.messaging.port.DmCheckpoint
import org.ghost.messaging.port.DmClock
import org.ghost.messaging.port.DmCrypto
import org.ghost.messaging.port.DmRandom
import org.ghost.messaging.port.EsSlot
import org.ghost.messaging.port.EsSlots
import org.ghost.messaging.port.ExpiryWake
import org.ghost.messaging.port.KeyWrapper
import org.ghost.network.OnionAddress
import org.ghost.storage.JdbcSqlExecutor
import org.ghost.storage.MigrationRunner
import org.ghost.storage.SqlExecutor
import org.ghost.sync.api.PrivacyMode
import org.ghost.sync.api.RelayEntry
import org.ghost.sync.api.RelayId
import org.ghost.sync.api.SyncDatabase
import org.ghost.sync.api.SyncTransaction
import org.ghost.sync.port.PairKey
import org.ghost.sync.port.RandomSources
import org.ghost.sync.port.SchedulePurpose
import org.ghost.sync.port.SyncClock
import org.ghost.sync.store.SyncStores
import java.security.MessageDigest

/**
 * A world for the owner-side steps of Phase 9 design §7.2, over a **real migrated v5 database**.
 *
 * The database is the real one on purpose: every guard the steps rely on is in the schema — the
 * `dm_self_monotonic` trigger behind OWNER-WEEK's week guard, the partial unique index that keeps
 * one current generation, `olm_prekey_gen_fixed`'s write-once `superseded_day`, the REPLACE guards
 * and the `typeof` CHECKs — and a mock would agree with a step that violated all of them.
 *
 * The **cryptography** is faked ([FakeDmCrypto]): the steps of this slice are about transactions,
 * guards and idempotence, and the seal, the card and the bundle are already proved byte for byte
 * by `ghost-client-dm`'s own vectors. [NativeOwnerStepsTest] runs the same steps against the real
 * surface wherever `ghost-dm-host` is on the classpath.
 */
class OwnerWorld(
    /** How many ES slots the week's table holds, and how their operators repeat. */
    slotCount: Int = 4,
    operators: Int = 2,
) : AutoCloseable {

    val sql: JdbcSqlExecutor = JdbcSqlExecutor().also { MigrationRunner(it).migrate() }
    val database: SyncDatabase = SyncDatabase(sql)
    val clock = MovableClock()
    val stores: SyncStores = SyncStores(database, clock, FixedRandomSources()) { PrivacyMode.STANDARD }
    val crypto = FakeDmCrypto()
    val random = SequentialRandom()
    val wrapper = FakeKeyWrapper()

    /** The ES slot table of every week, unless [slotsByWeek] overrides one. */
    var slots: List<EsSlot>

    /** Per-week overrides, for a slot-table change (§5.2). */
    val slotsByWeek: MutableMap<Long, List<EsSlot>> = LinkedHashMap()

    val esSlots = EsSlots { week -> slotsByWeek[week] ?: slots }

    val steps: OwnerSteps

    /**
     * The envelope layer, as far as an **owner-side** world needs one: none at all.
     *
     * S6's steps are about transactions, guards and idempotence, and none of them seals, opens or
     * ratchets; the context handed here is closed, so every call answers the `CRYPTO_UNAVAILABLE`
     * path of §2.7. A world that exercises sending and receiving wires the real one against
     * `ghost-dm-host` (§15.1), which is what `DmWorld` does.
     */
    val envelopes: org.ghost.messaging.port.DmEnvelopes =
        org.ghost.messaging.port.NativeDmEnvelopes(
            object : org.ghost.messaging.port.DmContext {
                override fun handleOrNull(): Long? = null

                override fun stateKeyWrapped(): ByteArray? = null

                override fun channelScheduleKey(): ByteArray? = null
            },
        )

    internal val contexts: SelfContexts by lazy { SelfContexts(database, crypto, wrapper) }

    internal val material: ContactMaterial by lazy { ContactMaterial(crypto, contexts) }

    internal val counters: DmCounters by lazy { DmCounters() }

    private val relayResolver: RelaySetResolver by lazy { RelaySetResolver(esSlots) }

    private val dmSync: DmSyncPorts by lazy {
        DmSyncPorts(
            stores.namespaces,
            stores.capabilities,
            stores.registrations,
            stores.outbox,
            stores.inbox,
        )
    }

    internal val contactSteps: ContactSteps by lazy {
        ContactSteps(database, crypto, random, contexts, establishment)
    }

    internal val sendStep: SendStep by lazy {
        SendStep(
            database, dmSync, envelopes, material, relayResolver, clock, random, contexts,
            counters = counters,
        )
    }

    internal val establishment: EstablishmentSteps by lazy {
        EstablishmentSteps(database, dmSync, envelopes, material, relayResolver, clock, contexts)
    }

    internal val keyDecision: KeyDecision by lazy { KeyDecision(database, crypto, contexts) }

    /**
     * The receive step exists here only so the facade can be built: an owner-side world receives
     * nothing, and the envelope layer above answers `CRYPTO_UNAVAILABLE` to every call it would
     * make. `DmWorld` is where `RECV` and `HELD` are exercised against the real library (§15.1).
     */
    internal val recognition: RecognitionKeys by lazy { RecognitionKeys(envelopes) }

    internal val receiveStep: ReceiveStep by lazy {
        ReceiveStep(
            database, dmSync, envelopes, crypto, material, recognition,
            SessionSlots(), clock, random, contexts, counters,
        )
    }

    internal val heldReplay: HeldReplay by lazy {
        HeldReplay(database, envelopes, receiveStep, clock, contexts, counters)
    }

    internal val scheduledSteps: ScheduledSteps by lazy {
        ScheduledSteps(database, crypto, sendStep, establishment, clock, random, contexts)
    }

    internal val displayStep: DisplayStep by lazy { DisplayStep(database, clock) }

    /** The real checkpoint over this world's executor, with its calls counted (ME-10, ME-11). */
    val checkpoints = RecordingCheckpoint { org.ghost.storage.Checkpoint.truncate(sql) }

    /** The ids SWEEP handed the media port inside its own transaction (§10.6). */
    val media = RecordingMedia()

    /** Every wake the schedule asked for (§10.7 triggers 1 and 5); null is a cancel. */
    val wakes = RecordingWake()

    /** Every unread count the notification port was given (§10.6, §10.7 Q19). */
    val notifications = RecordingNotifications()

    /**
     * SWEEP over this world's tables. The envelope layer here is always closed, so the skipped-key
     * prune of §7.7 point 4 is skipped and everything else runs — which is what a table-by-table
     * test of the cascade wants, and what `DmWorld` complements with the real library.
     */
    internal val sweeper: Sweeper by lazy {
        Sweeper(
            database = database,
            namespaces = stores.namespaces,
            envelopes = envelopes,
            pairKeys = PairKeySteps(envelopes),
            checkpoint = checkpoints,
            clock = clock,
            contexts = contexts,
            media = media,
            mediaOrphans = MediaOrphanSteps(crypto, clock),
        )
    }

    internal val schedule: ExpirySchedule by lazy {
        ExpirySchedule(sweeper, wakes, UnreadNotices { sweeper.unreadCount() })
    }

    /** The facade, wired to this world's steps. No actor: the world is single-threaded already. */
    internal val engine: MessagingEngine by lazy {
        MessagingEngine(
            database, steps, contactSteps, sendStep, establishment, keyDecision, heldReplay,
            scheduledSteps, displayStep, schedule, counters, clock, contexts, recognition,
        )
    }

    init {
        val relayIds = database.transaction { tx ->
            stores.relayDirectory.upsert(
                tx,
                (0 until slotCount).map { i ->
                    RelayEntry(onion(i), operatorId(i % operators), RelayEntry.Source.CONFIG)
                },
            )
        }
        val ordered = (0 until slotCount).map { i -> relayIds.getValue(onion(i)) }
        slots = (0 until slotCount).map { i -> EsSlot(i, ordered[i], operatorId(i % operators)) }
        steps = OwnerSteps(
            database = database,
            sync = OwnerSteps.SyncPorts(stores.namespaces, stores.capabilities, stores.registrations, stores.outbox),
            crypto = crypto,
            clock = clock,
            random = random,
            keyWrapper = wrapper,
            esSlots = esSlots,
        )
    }

    override fun close() {
        sql.close()
    }

    // ---- rows SWEEP deletes, written straight in (`SweepTest`) ----
    //
    // A live conversation cannot reach most of them inside a test: a generation two months past
    // its retention with a hold still naming it, a `prov_env` past its erase minute, a request
    // past its day. Writing the row is exact and the schema still judges it — every CHECK, every
    // trigger and every REPLACE guard of migration 5 applies to these inserts as much as to the
    // steps'.

    /** ACTIVATE, so `dm_self` exists and the expiry clock has somewhere to live (R-T7). */
    fun activate() {
        check(steps.activate(restored = false) == OwnerSteps.Result.DONE) { "ACTIVATE" }
    }

    /** One contact, with the columns its CHECKs demand for the trust state asked for. */
    fun seedContact(
        contact: Int = 0x21,
        identity: Int = 0x22,
        trust: String = "unverified",
        requestUntilDay: Long? = null,
    ) {
        sql.exec(
            "INSERT INTO dm_contact(contact_id, identity_pk, card_env, card_index, trust_state, " +
                "source, establishment, request_until_day) VALUES (?, ?, ?, 0, ?, 'link', 'card_only', ?)",
            listOf(
                ByteArray(16) { contact.toByte() },
                ByteArray(32) { identity.toByte() },
                ByteArray(159) { contact.toByte() },
                trust,
                requestUntilDay,
            ),
        )
    }

    /** [seedContact] plus the conversation every message row needs. */
    fun seedConversation(contact: Int = 0x21) {
        seedContact(contact = contact)
        sql.exec(
            "INSERT INTO dm_conversation(conversation_id, contact_id) VALUES (?, ?)",
            listOf(ByteArray(16) { contact.toByte() }, ByteArray(16) { contact.toByte() }),
        )
    }

    /**
     * One message with a reaction, and optionally the outbound item, op (with a retained blob) and
     * pending send that must cascade with it (§10.6).
     */
    fun seedMessage(
        id: Int,
        deleteAt: Long,
        incoming: Boolean = false,
        withItem: Boolean = false,
        contact: Int = 0x21,
    ) {
        val messageId = messageId(id)
        val conversation = ByteArray(16) { contact.toByte() }
        val author = deleteAt - 86_400
        sql.exec(
            "INSERT INTO dm_message(message_id, conversation_id, direction, kind, author_minute, " +
                "sort_minute, minute_index, timer_code, body_env, state, expire_at_minute, " +
                "unread_deadline_minute, delete_at_minute) VALUES (?, ?, ?, 1, ?, ?, 0, 4, ?, ?, ?, ?, ?)",
            listOf(
                messageId,
                conversation,
                if (incoming) "in" else "out",
                author,
                author,
                ByteArray(100) { id.toByte() },
                if (incoming) "unread" else "sent",
                if (incoming) null else deleteAt,
                if (incoming) deleteAt else null,
                deleteAt,
            ),
        )
        sql.exec(
            "INSERT INTO dm_reaction(target_id, from_self, grapheme_env) VALUES (?, 1, ?)",
            listOf(messageId, ByteArray(40) { id.toByte() }),
        )
        if (!withItem) return
        sql.exec(
            "INSERT INTO dm_outbound_item(item_id, contact_id, message_ref, kind, control, l0_env, " +
                "deadline_hour, state, ttl_seconds) VALUES (?, ?, ?, 1, NULL, ?, ?, 'enqueued', 604800)",
            listOf(
                messageId,
                ByteArray(16) { contact.toByte() },
                messageId,
                ByteArray(60) { id.toByte() },
                ceilHour(deleteAt),
            ),
        )
        sql.exec(
            "INSERT INTO dm_outbound_op(operation_id, purpose, item_id, bundle_week, blob, " +
                "resend_count, deadline_hour) VALUES (?, 'item', ?, NULL, ?, 0, ?)",
            listOf(messageId, messageId, ByteArray(4096) { id.toByte() }, ceilHour(deleteAt)),
        )
        sql.exec(
            "INSERT INTO dm_pending_send(item_id, contact_id, fail_after_hour) VALUES (?, ?, ?)",
            listOf(messageId, ByteArray(16) { contact.toByte() }, ceilHour(deleteAt) + 86_400),
        )
    }

    /**
     * A 16-byte id from a small integer.
     *
     * A byte repeated sixteen times for `id ≤ 0xFF`, which is what the assertions of `SweepTest`
     * spell out (`X'e1e1…'`), and the integer big-endian in the first four bytes above that — a
     * test that seeds more than a batch of rows needs 500 **distinct** primary keys, and the
     * repeated low byte would have given it 256.
     */
    fun messageId(id: Int): ByteArray {
        val out = ByteArray(16) { id.toByte() }
        if (id <= 0xFF) return out
        for (i in 0 until 4) out[i] = (id ushr (8 * (3 - i))).toByte()
        return out
    }

    /** One `olm_prekey_gen` row, superseded and past (or not past) its retention (§5.4). */
    fun seedGeneration(genId: Long, deleteAfterDay: Long) {
        sql.exec(
            "INSERT INTO olm_prekey_gen(gen_id, bundle_week, fallback_pub, secrets_env, " +
                "superseded_day, delete_after_day) VALUES (?, 1, ?, ?, ?, ?)",
            listOf(
                genId,
                ByteArray(32) { genId.toByte() },
                ByteArray(92) { genId.toByte() },
                deleteAfterDay - 91,
                deleteAfterDay,
            ),
        )
    }

    /** One held row naming [genId] (§8.3). */
    fun seedHeld(heldId: Int, genId: Long, holdUntil: Long, contact: Int = 0x21) {
        sql.exec(
            "INSERT INTO dm_held(held_id, contact_id, identity, l1_env, gen_id, prov_env, " +
                "hold_until_minute, relay_expiry_hour, consume_minute) VALUES (?, ?, ?, ?, ?, NULL, ?, ?, ?)",
            listOf(
                ByteArray(16) { heldId.toByte() },
                ByteArray(16) { contact.toByte() },
                ByteArray(32) { heldId.toByte() },
                ByteArray(60) { heldId.toByte() },
                genId,
                holdUntil,
                ceilHour(holdUntil),
                holdUntil - 3_600,
            ),
        )
    }

    /** One D3 tag with its `ceil7` day (§7.6, §21.10 point 3). */
    fun seedSeen(tag: Int, untilDay: Long) {
        sql.exec(
            "INSERT INTO dm_seen(tag, until_day) VALUES (?, ?)",
            listOf(ByteArray(16) { tag.toByte() }, untilDay),
        )
    }

    /** One session in [slot], with the columns that slot's CHECKs demand (§13.6 step 5). */
    fun seedSession(
        slot: String,
        contact: Int = 0x21,
        retireDay: Long? = null,
        provEraseMinute: Long? = null,
    ) {
        sql.exec(
            "INSERT INTO olm_session(contact_id, slot, session_id, role, acknowledged, state_env, " +
                "prov_env, prov_erase_minute, peer_gen_id, unack_since_day, retire_day, " +
                "peer_bind_minute, prov_anchor_minute, pair_sent) " +
                "VALUES (?, ?, ?, 'responder', 1, ?, ?, ?, NULL, NULL, ?, ?, NULL, 0)",
            listOf(
                ByteArray(16) { contact.toByte() },
                slot,
                ByteArray(32) { (contact + slot.length).toByte() },
                ByteArray(60) { contact.toByte() },
                if (provEraseMinute == null) null else ByteArray(60) { 0x5a },
                provEraseMinute,
                retireDay,
                floorMinute(clock.now) - 600,
            ),
        )
    }

    /** One peer X-Wing key of a bundle week (§22.8.6 rule 2). */
    fun seedPeerPq(genId: Long, bundleWeek: Long, contact: Int = 0x21) {
        sql.exec(
            "INSERT INTO dm_peer_pq(contact_id, gen_id, bundle_week, source, xwing_pk) " +
                "VALUES (?, ?, ?, 'bundle', ?)",
            listOf(ByteArray(16) { contact.toByte() }, genId, bundleWeek, ByteArray(1216) { genId.toByte() }),
        )
    }

    /** `dm_self.expiry_clock_minute` (R-T7). */
    fun expiryClock(): Long {
        var out: Long? = null
        sql.query("SELECT expiry_clock_minute FROM dm_self") { out = it.long(0) }
        return checkNotNull(out) { "no dm_self row" }
    }

    fun count(query: String, args: List<Any?> = emptyList()): Int {
        var out = 0
        sql.query(query, args) { out = it.long(0).toInt() }
        return out
    }

    fun longs(query: String): List<Long> {
        val out = ArrayList<Long>()
        sql.query(query) { out += it.long(0) }
        return out
    }

    private fun ceilHour(seconds: Long): Long = -Math.floorDiv(-seconds, 3_600L) * 3_600L

    private fun floorMinute(seconds: Long): Long = Math.floorDiv(seconds, 60L) * 60L

    // ---- queries the assertions use, written out rather than hidden behind the DAOs ----

    fun selfRow(): Map<String, Any?>? = singleRow(
        "SELECT card_index, bundle_week, bundle_published_week, expiry_clock_minute, accept_after_minute FROM dm_self",
        listOf("card_index", "bundle_week", "bundle_published_week", "expiry_clock_minute", "accept_after_minute"),
    )

    fun generations(): List<Map<String, Any?>> = rows(
        "SELECT gen_id, bundle_week, superseded_day, delete_after_day FROM olm_prekey_gen ORDER BY bundle_week, gen_id",
        listOf("gen_id", "bundle_week", "superseded_day", "delete_after_day"),
    )

    fun ownNamespaces(): Map<String, ByteArray> {
        val out = LinkedHashMap<String, ByteArray>()
        sql.query("SELECT role, namespace_id FROM dm_own_namespace") { out[it.string(0)] = it.blob(1) }
        return out
    }

    fun bundleOps(): List<Map<String, Any?>> = rows(
        "SELECT hex(operation_id) AS op, bundle_week, length(blob) AS len, deadline_hour FROM dm_outbound_op WHERE purpose = 'bundle' ORDER BY bundle_week",
        listOf("op!", "bundle_week", "len", "deadline_hour"),
    )

    fun outboxOps(): List<Map<String, Any?>> = rows(
        "SELECT hex(namespace_id) AS ns, ttl_seconds, deadline_hour, not_before_minute FROM outbox_op ORDER BY rowid",
        listOf("ns!", "ttl_seconds", "deadline_hour", "not_before_minute"),
    )

    fun registrations(): List<Map<String, Any?>> = rows(
        "SELECT relay_id, hex(namespace_id) AS ns, period_id, kind, state, hex(verifier) AS verifier " +
            "FROM relay_key_registration ORDER BY period_id, relay_id, kind",
        listOf("relay_id", "ns!", "period_id", "kind!", "state!", "verifier!"),
    )

    fun capabilities(): List<Map<String, Any?>> = rows(
        "SELECT relay_id, hex(namespace_id) AS ns, kind, state, expires_hour, generation, length(token) AS len " +
            "FROM relay_capability ORDER BY relay_id, kind",
        listOf("relay_id", "ns!", "kind!", "state!", "expires_hour", "generation", "len"),
    )

    fun namespaceRelays(namespace: ByteArray): Set<Long> {
        val out = HashSet<Long>()
        sql.query("SELECT relay_id FROM namespace_relay WHERE namespace_id = ?", listOf(namespace)) { out += it.long(0) }
        return out
    }

    fun markRegistrationsDone(validUntilHour: Long) {
        sql.exec(
            "UPDATE relay_key_registration SET state = 'done', valid_until_hour = ? WHERE state = 'pending'",
            listOf(validUntilHour),
        )
    }

    fun markCapabilityRejected(relay: RelayId) {
        sql.exec("UPDATE relay_capability SET state = 'rejected' WHERE relay_id = ?", listOf(relay.value))
    }

    /**
     * Reads rows as maps. Each column is named `name` for an INTEGER and `name!` for a TEXT: JDBC
     * happily reads `"6538E1…"` with `getLong` and returns `6538`, so the type has to be declared
     * rather than guessed — the first version of this helper guessed, and every hex comparison in
     * the assertions silently compared prefixes.
     */
    private fun rows(query: String, columns: List<String>): List<Map<String, Any?>> {
        val out = ArrayList<Map<String, Any?>>()
        sql.query(query) { row ->
            val map = LinkedHashMap<String, Any?>()
            columns.forEachIndexed { i, spec ->
                val text = spec.endsWith("!")
                val name = if (text) spec.dropLast(1) else spec
                map[name] = when {
                    row.isNull(i) -> null
                    text -> row.string(i)
                    else -> row.long(i)
                }
            }
            out += map
        }
        return out
    }

    private fun singleRow(query: String, columns: List<String>): Map<String, Any?>? =
        rows(query, columns).firstOrNull()

    companion object {
        fun onion(seed: Int, port: Int = 443): OnionAddress {
            val publicKey = ByteArray(32) { (seed * 13 + it * 5 + 1).toByte() }
            val md = MessageDigest.getInstance("SHA3-256")
            md.update(".onion checksum".toByteArray(Charsets.US_ASCII))
            md.update(publicKey)
            md.update(3.toByte())
            val checksum = md.digest()
            val raw = publicKey + byteArrayOf(checksum[0], checksum[1], 3)
            return OnionAddress.parse(base32(raw) + ".onion:" + port)
        }

        fun operatorId(i: Int): ByteArray = ByteArray(16) { (0x40 + i).toByte() }

        private fun base32(bytes: ByteArray): String {
            val alphabet = "abcdefghijklmnopqrstuvwxyz234567"
            val out = StringBuilder()
            var buffer = 0
            var bits = 0
            for (b in bytes) {
                buffer = (buffer shl 8) or (b.toInt() and 0xff)
                bits += 8
                while (bits >= 5) {
                    bits -= 5
                    out.append(alphabet[(buffer shr bits) and 31])
                }
            }
            if (bits > 0) out.append(alphabet[(buffer shl (5 - bits)) and 31])
            return out.toString()
        }
    }
}

/** A clock the test moves by hand; also the `:sync` clock, so both see one time. */
class MovableClock(var now: Long = 1_800_000_000L) : DmClock, SyncClock {
    var monotonic: Long = 0

    override fun nowEpochSeconds(): Long = now

    override fun epochSeconds(): Long = now

    override fun monotonicMillis(): Long = monotonic
}

/**
 * Deterministic, distinct bytes per call: a repeat would hide an id collision the steps must
 * avoid.
 *
 * **[stream] separates two devices' draws, and it is not cosmetic.** Every draw is a prefix of
 * `SHA-256("<stream>:<n>:<block>")`, so without a per-device stream a 16-byte draw and a 32-byte
 * draw with the same counter **share their first 16 bytes** — and two devices whose counters
 * happened to line up produced a `message_id` on one that was the prefix of a `seen_key` on the
 * other. The T25 physical scan of `EphemeralTest` found exactly that and reported a message id
 * "surviving the sweep" inside `dm_self`. A real CSPRNG makes the collision negligible; this one
 * has to be told.
 */
class SequentialRandom(private var counter: Int = 0, private val stream: String = "") : DmRandom {
    override fun bytes(count: Int): ByteArray {
        val out = ByteArray(count)
        var pos = 0
        var block = 0
        val seed = counter++
        while (pos < count) {
            val digest = MessageDigest.getInstance("SHA-256")
                .digest("$stream:$seed:$block".toByteArray(Charsets.US_ASCII))
            val n = minOf(digest.size, count - pos)
            System.arraycopy(digest, 0, out, pos, n)
            pos += n
            block++
        }
        return out
    }
}

/**
 * The wakes the actor asked for (§10.7 triggers 1 and 5): every **delay** it was given, in order,
 * with null for a cancel.
 *
 * It records rather than schedules, because what the EP suite checks is the **contract** — one
 * wake per pass, the delay to the next due minute, a cancel when nothing is pending — and the
 * platform half is `ExpiryAlarm`'s, whose arithmetic `ExpiryAlarmSpecTest` checks on its own.
 *
 * It records a **delay** since the S9 review: while the port carried an absolute minute, a
 * recorder like this one could not see the defect the review found, because the conversion that
 * was wrong — subtracting the wall clock instead of `now_e` (R-T7) — happened on the other side of
 * it, in code no world ever instantiated.
 */
class RecordingWake : ExpiryWake {
    val requested = ArrayList<Long?>()

    override fun wakeIn(delaySeconds: Long?) {
        requested += delaySeconds
    }

    /** The last wake asked for, or null when the last thing asked for was a cancel. */
    val last: Long? get() = requested.lastOrNull()
}

/** Every unread count the notification port was given (§10.6, §10.7 Q19). */
class RecordingNotifications : NotificationPort {
    val counts = ArrayList<Int>()

    override fun onUnreadChanged(count: Int) {
        counts += count
    }

    val last: Int? get() = counts.lastOrNull()
}

/**
 * The media port of §10.6, which SWEEP calls **inside** its own transaction. The world records the
 * ids so a test can assert that they are exactly the messages that then disappeared.
 */
class RecordingMedia : MediaPort {
    val deleted = ArrayList<List<String>>()

    /**
     * When set, the port raises `SQLITE_FULL` from inside SWEEP's transaction — the fault
     * injection of §21.12 point 1 and SCN-J, at the one seam a Phase 11 media store would really
     * write through. A full disk must not take the rest of the actor pass down with it.
     */
    var failStorageFull: Boolean = false

    override fun onMessagesDeleted(tx: SyncTransaction, ids: List<MessageId>) {
        if (failStorageFull) {
            throw org.ghost.storage.StorageFullException(
                IllegalStateException("[SQLITE_FULL] injected"),
            )
        }
        deleted += ids.map { id -> id.toByteArray().joinToString("") { "%02x".format(it) } }
    }

    val allIds: List<String> get() = deleted.flatten()
}

/**
 * The checkpoint port, wired to the real `Checkpoint.truncate` and counting the calls.
 *
 * [busy] models the §10.7 case the design names — a reader holds the log through all three retries
 * — so a test can check that the need is **kept** and retried at the next sweep rather than lost
 * (mutant ME-10, "checkpoint result ignored").
 */
class RecordingCheckpoint(private val real: () -> Boolean) : DmCheckpoint {
    var calls: Int = 0
        private set

    /** While true, every call answers false, as a busy reader would. */
    var busy: Boolean = false

    /**
     * While true, every call raises `SQLITE_FULL`, as the pragma on a full disk would.
     *
     * The pragma is a **write**, so it is exactly what fails on the device that most needs the
     * pages back. The S9 review found that this failure used to discard the counts of a
     * transaction that had already committed *and* the `checkpoint_due` flag with them, so the
     * next sweep saw nothing owed and the freed plaintext stayed in the `-wal` for the life of
     * the process.
     */
    var failStorageFull: Boolean = false

    override fun truncate(): Boolean {
        calls += 1
        if (failStorageFull) {
            throw org.ghost.storage.StorageFullException(
                IllegalStateException("[SQLITE_FULL] injected at the checkpoint"),
            )
        }
        if (busy) return false
        return real()
    }
}

/** The in-memory wrapper port §13.8 names for JVM tests: a marker prefix, so a wrap is visible. */
class FakeKeyWrapper : KeyWrapper {
    override fun wrap(key: ByteArray): ByteArray = PREFIX + key

    override fun unwrap(wrapped: ByteArray): ByteArray {
        require(wrapped.size > PREFIX.size && wrapped.copyOf(PREFIX.size).contentEquals(PREFIX)) {
            "not a wrapped key"
        }
        return wrapped.copyOfRange(PREFIX.size, wrapped.size)
    }

    companion object {
        /** 8 bytes, so a wrapped 32-byte key is 40: the schema's lower bound for the column. */
        val PREFIX: ByteArray = "GHOSTWRP".toByteArray(Charsets.US_ASCII)
    }
}

/**
 * A [DmCrypto] whose outputs are deterministic functions of their inputs, with the **shapes** the
 * schema and the sync API demand: a 131-byte card, 32-byte namespaces, a 4096-byte bundle blob, a
 * 92-byte `secrets_env`. A length that drifted would fail a CHECK here exactly as on device.
 */
class FakeDmCrypto : DmCrypto {

    /** Set false to model a locked or wiped context (§2.5). */
    var available: Boolean = true

    /** Counts calls, so a test can show that a guard stopped a step before any native work. */
    var bundleCreateCalls: Int = 0
        private set

    /** The (week, rank, genId) each `bundleCreate` was asked for, so the rank rule is assertable. */
    val requestedRanks: MutableList<Triple<Long, Int, Int>> = ArrayList()

    /** The publication offset the fake card reports; a whole minute, inside one week (§5.4). */
    var publicationOffsetSeconds: Long = 3 * 86_400L + 1_200L

    override fun isAvailable(): Boolean = available

    override fun ownCard(cardIndex: Int): DmSessions.OwnCard? {
        if (!available) return null
        return DmSessions.OwnCard(
            card = derive("card", cardIndex, 0, 131),
            inboxNamespace = derive("inbox-ns", cardIndex, 0, 32),
            bundleNamespace = derive("bundle-ns", cardIndex, 0, 32),
            mediaNamespace = derive("media-ns", cardIndex, 0, 32),
            recognitionIntro = derive("rec-intro", cardIndex, 0, 32),
            recognitionBundle = derive("rec-bundle", cardIndex, 0, 32),
            olmIdentity = derive("olm", cardIndex, 0, 32),
            publicationOffsetSeconds = publicationOffsetSeconds,
        )
    }

    override fun ownSecrets(cardIndex: Int, slot: Int): DmSessions.OwnSecrets? {
        if (!available) return null
        return DmSessions.OwnSecrets(
            read = derive("rx", cardIndex, slot, 32),
            deposit = derive("d", cardIndex, slot, 32),
            fetch = derive("rp", cardIndex, slot, 32),
            mediaRead = derive("rm", cardIndex, slot, 32),
        )
    }

    override fun bundleCreate(
        cardIndex: Int,
        bundleWeek: Long,
        bundleRank: Int,
        genId: Int,
    ): DmSessions.BundleGeneration? {
        if (!available) return null
        bundleCreateCalls++
        requestedRanks += Triple(bundleWeek, bundleRank, genId)
        val tag = "$bundleWeek:$bundleRank:$genId"
        return DmSessions.BundleGeneration(
            blob = derive("blob-$tag", cardIndex, 0, 4096),
            fallbackPublic = derive("fallback-$tag", cardIndex, 0, 32),
            xwingPublic = derive("xwing-$tag", cardIndex, 0, 1216),
            secretsEnv = derive("secrets-$tag", cardIndex, 0, 92),
        )
    }

    override fun stateKeyWrapped(): ByteArray? =
        if (available) FakeKeyWrapper.PREFIX + derive("state-key", 0, 0, 32) else null

    /**
     * §2.6 function 3, faked: a card is 131 bytes whose bytes 1..3 are the index and 3..35 the
     * identity key, exactly as §3.3 lays one out, so a caller that reads those offsets reads the
     * same fields a real card carries. The signature is not checked here — a fake that verified
     * one would be verifying its own arithmetic — so a world that needs the real parse uses the
     * native crypto (§15.1).
     */
    override fun parseCard(card: ByteArray): DmCards.ParseResult {
        if (!available) return DmCards.ParseResult.Unavailable
        if (card.size != CARD_BYTES) return DmCards.ParseResult.InvalidCard
        val index = ((card[1].toInt() and 0xff) shl 8) or (card[2].toInt() and 0xff)
        return DmCards.ParseResult.Ok(DmCards.Parsed(index, card.copyOfRange(3, 35)))
    }

    /**
     * §2.6 function 3, faked: deterministic values of the card and the slot, with the shapes the
     * schema and the credential layout demand — 32-byte namespaces and secrets, 60-byte wrapped
     * opening keys — so a length that drifted fails a CHECK here exactly as on device.
     */
    override fun deriveCard(card: ByteArray, slot: Int): DmCards.DeriveResult {
        if (!available) return DmCards.DeriveResult.Unavailable
        if (card.size != CARD_BYTES) return DmCards.DeriveResult.InvalidCard
        val tag = card.take(8).joinToString("") { "%02x".format(it) }
        return DmCards.DeriveResult.Ok(
            DmCards.Derived(
                inboxNamespace = derive("inbox-ns-$tag", 0, 0, 32),
                bundleNamespace = derive("bundle-ns-$tag", 0, 0, 32),
                mediaNamespace = derive("media-ns-$tag", 0, 0, 32),
                deposit = derive("d-$tag", 0, slot, 32),
                fetch = derive("rp-$tag", 0, slot, 32),
                mediaDeposit = derive("md-$tag", 0, slot, 32),
                recognitionIntro = derive("rec-intro-$tag", 0, 0, 32),
                recognitionBundle = derive("rec-bundle-$tag", 0, 0, 32),
                introKeyEnv = derive("kio-$tag", 0, 0, 60),
                bundleKeyEnv = derive("kb-$tag", 0, 0, 60),
            ),
        )
    }

    /**
     * §2.6 function 17, faked: a deterministic 60 digits and 65 scannable bytes of the four keys,
     * in the **shape** §8.4 fixes — a version byte and two 32-byte halves, the own one first — so
     * a caller that compares two halves the wrong way round is caught here as it would be on
     * device. The digits themselves are `dm_safety_number.txt`'s, replayed by the crate.
     */
    override fun safetyNumber(
        ownIdentityPk: ByteArray,
        ownOlm: ByteArray,
        peerIdentityPk: ByteArray,
        peerOlm: ByteArray,
    ): DmSessions.SafetyNumber? {
        if (!available) return null
        val own = derive("sn-${hex(ownIdentityPk)}-${hex(ownOlm)}", 0, 0, 32)
        val peer = derive("sn-${hex(peerIdentityPk)}-${hex(peerOlm)}", 0, 0, 32)
        val digits = (own + peer).take(30).joinToString("") { ((it.toInt() and 0x0f)).toString() }
        return DmSessions.SafetyNumber(digits, byteArrayOf(1) + own + peer)
    }

    /**
     * §8.5, faked: a 102-byte certificate whose identity half is derived from the reason, so a
     * caller that hands the wrong bytes to [verifyRevocation] is caught. A real signature is the
     * crate's, and `DmWorld` is where one is made.
     */
    override fun issueRevocation(
        issuedMinute: Long,
        reason: DmRevocations.Reason,
    ): DmRevocations.Issued {
        if (!available) return DmRevocations.Issued.Unavailable
        return DmRevocations.Issued.Ok(derive("revocation-${reason.code}", 0, 0, 102))
    }

    override fun verifyRevocation(
        certificate: ByteArray,
        expectedIdentityPk: ByteArray,
    ): DmRevocations.Verified {
        if (!available) return DmRevocations.Verified.Unavailable
        if (certificate.size != 102) return DmRevocations.Verified.NonCanonical
        return DmRevocations.Verified.Ok(expectedIdentityPk, 0, DmRevocations.Reason.DEVICE_LOST)
    }

    private fun hex(bytes: ByteArray): String = bytes.joinToString("") { "%02x".format(it) }

    private fun derive(label: String, cardIndex: Int, slot: Int, size: Int): ByteArray {
        val out = ByteArray(size)
        var pos = 0
        var block = 0
        while (pos < size) {
            val digest = MessageDigest.getInstance("SHA-256")
                .digest("$label|$cardIndex|$slot|$block".toByteArray(Charsets.US_ASCII))
            val n = minOf(digest.size, size - pos)
            System.arraycopy(digest, 0, out, pos, n)
            pos += n
            block++
        }
        return out
    }

    private companion object {
        /** A contact card v2 (§3.3). */
        const val CARD_BYTES = 131
    }
}

/** `:sync`'s random port; fixed values, because no assertion here depends on a schedule draw. */
class FixedRandomSources : RandomSources {
    override fun schedule(pair: PairKey, purpose: SchedulePurpose, index: Long): Double = 0.5

    override fun readBreaker(relay: RelayId, index: Long): Double = 0.5

    override fun sendDelay(): Double = 0.5

    override fun selection(): Double = 0.5

    override fun quietRun(index: Long): Double = 0.5

    override fun paymentHold(index: Long): Double = 0.5

    override fun requestId(): ByteArray = ByteArray(16) { 0x11 }
}

/** Reads a single value out of the world's database, for assertions the DAOs do not expose. */
fun SqlExecutor.scalar(query: String, args: List<Any?> = emptyList()): Long? {
    var out: Long? = null
    query(query, args) { if (!it.isNull(0)) out = it.long(0) }
    return out
}
