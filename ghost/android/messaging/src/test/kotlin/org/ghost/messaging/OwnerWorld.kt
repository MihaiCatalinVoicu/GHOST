package org.ghost.messaging

import org.ghost.crypto.bridge.DmSessions
import org.ghost.messaging.engine.OwnerSteps
import org.ghost.messaging.port.DmClock
import org.ghost.messaging.port.DmCrypto
import org.ghost.messaging.port.DmRandom
import org.ghost.messaging.port.EsSlot
import org.ghost.messaging.port.EsSlots
import org.ghost.messaging.port.KeyWrapper
import org.ghost.network.OnionAddress
import org.ghost.storage.JdbcSqlExecutor
import org.ghost.storage.MigrationRunner
import org.ghost.storage.SqlExecutor
import org.ghost.sync.api.PrivacyMode
import org.ghost.sync.api.RelayEntry
import org.ghost.sync.api.RelayId
import org.ghost.sync.api.SyncDatabase
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

/** Deterministic, distinct bytes per call: a repeat would hide an id collision the steps must avoid. */
class SequentialRandom(private var counter: Int = 0) : DmRandom {
    override fun bytes(count: Int): ByteArray {
        val out = ByteArray(count)
        var pos = 0
        var block = 0
        val seed = counter++
        while (pos < count) {
            val digest = MessageDigest.getInstance("SHA-256").digest("$seed:$block".toByteArray(Charsets.US_ASCII))
            val n = minOf(digest.size, count - pos)
            System.arraycopy(digest, 0, out, pos, n)
            pos += n
            block++
        }
        return out
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
}

/** `:sync`'s random port; fixed values, because no assertion here depends on a schedule draw. */
class FixedRandomSources : RandomSources {
    override fun schedule(pair: PairKey, purpose: SchedulePurpose, index: Long): Double = 0.5

    override fun readBreaker(relay: RelayId, index: Long): Double = 0.5

    override fun sendDelay(): Double = 0.0

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
